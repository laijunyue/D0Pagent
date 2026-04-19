from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import re

from .pentest_helpers import (
    build_target_profile,
    dedupe_preserve_order,
    extract_secrets_and_flags,
    flatten_text_inputs,
    is_ip_address,
)


EVIDENCE_CATEGORIES: tuple[str, ...] = (
    "hosts",
    "services",
    "urls",
    "creds",
    "vulns",
    "flags",
    "pivots",
    "loot",
    "notes",
)
UNIX_PATH_PATTERN = re.compile(r"(?:/[A-Za-z0-9._-]+){2,}")
WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+")
SERVICE_PATTERN = re.compile(r"\b(?P<port>\d{1,5})/(?:tcp|udp)\s+(?:open|filtered|closed)?\s*(?P<service>[A-Za-z0-9_.-]{2,40})?")
HOST_PORT_PATTERN = re.compile(
    r"\b(?P<host>(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,24}|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.local)"
    r"(?::(?P<port>\d{1,5}))\b",
    re.IGNORECASE,
)
PIVOT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("proxy", re.compile(r"(?i)\bsocks5?://[^\s\"'<>]+")),
    ("proxy", re.compile(r"(?i)\bproxychains(?:4)?\b[^\r\n]*")),
    ("tunnel", re.compile(r"(?i)\bssh\s+-D\s+\S+[^\r\n]*")),
    ("tunnel", re.compile(r"(?i)\b(?:chisel|frp|ligolo|sshuttle)\b[^\r\n]*")),
    ("session", re.compile(r"(?i)\bmeterpreter\b[^\r\n]*")),
)
DATABASE_PATTERN = re.compile(r"(?i)\b(?:database|db_name|schema)\b\s*[:=]\s*([A-Za-z0-9_.-]{3,64})")
DOMAIN_INFO_PATTERN = re.compile(r"(?i)\b(?:domain|realm|forest)\b\s*[:=]\s*([A-Za-z0-9_.-]{3,128})")


class EvidenceStore:
    """Persistent challenge-level evidence memory for multi-attempt hackathon runs."""

    def __init__(
        self,
        *,
        path: Path,
        challenge_code: str = "",
        event_logger: Callable[[str, Any], None] | None = None,
    ) -> None:
        self.path = path.expanduser().resolve()
        self.challenge_code = str(challenge_code).strip()
        self.event_logger = event_logger
        self.data = self._load()

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable copy of the current evidence store."""

        return json.loads(json.dumps(self.data, ensure_ascii=False, default=str))

    def merge_mapping(self, mapping: dict[str, Any]) -> dict[str, int]:
        """Merge evidence lists into the store and return per-category insert counts."""

        counts = {category: 0 for category in EVIDENCE_CATEGORIES}
        changed = False
        for category in EVIDENCE_CATEGORIES:
            for item in self._iter_category_items(mapping.get(category)):
                if self._merge_item(category, item):
                    counts[category] += 1
                    changed = True

        if changed:
            self.data["updated_at"] = self._timestamp()
            self._save()
            self._log("evidence_store_updated", {"path": str(self.path), "counts": counts})
        return counts

    def seed_entrypoints(self, entrypoints: Sequence[str]) -> dict[str, int]:
        """Seed obvious hosts and URLs from official challenge entrypoints."""

        urls: list[dict[str, Any]] = []
        hosts: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        for entrypoint in flatten_text_inputs(entrypoints):
            if entrypoint.startswith("http://") or entrypoint.startswith("https://"):
                urls.append({"url": entrypoint})
                parsed = self._safe_urlparse(entrypoint)
                if parsed is None:
                    self._log(
                        "evidence_seed_warning",
                        {
                            "challenge_code": self.challenge_code,
                            "entrypoint": entrypoint,
                            "warning": "skipped invalid URL while seeding entrypoints",
                        },
                    )
                    continue
                host = parsed.hostname
                if host:
                    hosts.append({"value": host, "kind": self._guess_host_kind(host)})
                port = parsed.port
                if host and port is not None:
                    services.append({"host": host, "port": port, "service": parsed.scheme, "protocol": "tcp"})
            else:
                hosts.append({"value": entrypoint, "kind": self._guess_host_kind(entrypoint)})
        return self.merge_mapping({"hosts": hosts, "urls": urls, "services": services})

    def aggregate_attempt_workspace(self, workspace: Path) -> dict[str, Any]:
        """Extract lightweight structured evidence from one attempt workspace."""

        texts = self._collect_workspace_texts(workspace)
        aggregated: dict[str, list[Any]] = {category: [] for category in EVIDENCE_CATEGORIES}
        skipped_invalid_urls_count = 0
        parse_errors_count = 0
        extracted_flags_count = 0
        for text in texts:
            try:
                extracted = extract_secrets_and_flags(text)
            except Exception as exc:
                parse_errors_count += 1
                self._log(
                    "evidence_absorb_warning",
                    {
                        "challenge_code": self.challenge_code,
                        "warning": "failed to parse one workspace text blob",
                        "error": str(exc),
                    },
                )
                continue
            aggregated["urls"].extend({"url": url} for url in extracted["urls"])
            aggregated["hosts"].extend({"value": ip, "kind": "ip"} for ip in extracted["ips"])
            aggregated["hosts"].extend({"value": domain, "kind": "domain"} for domain in extracted["domains"])
            aggregated["creds"].extend(extracted["credentials"])
            aggregated["flags"].extend({"value": flag, "status": "candidate"} for flag in extracted["flags"])
            extracted_flags_count += len(extracted["flags"])
            skipped_invalid_urls_count += int(extracted.get("skipped_invalid_urls_count", 0) or 0)
            aggregated["vulns"].extend(
                {"name": cve, "target": "", "confidence": "high"} for cve in extracted["cves"]
            )
            aggregated["loot"].extend({"kind": "version", "value": version} for version in extracted["versions"])
            aggregated["services"].extend(self._extract_services(text))
            aggregated["pivots"].extend(self._extract_pivots(text))
            aggregated["loot"].extend(self._extract_loot(text))

        try:
            profile = build_target_profile(texts)
        except Exception as exc:
            parse_errors_count += 1
            profile = {}
            self._log(
                "evidence_absorb_warning",
                {
                    "challenge_code": self.challenge_code,
                    "warning": "failed to build target profile from absorbed evidence",
                    "error": str(exc),
                },
            )
        aggregated["notes"].extend(self._profile_notes(profile))
        artifact_count = sum(len(values) for values in aggregated.values())
        return {
            "aggregated": aggregated,
            "artifact_count": artifact_count,
            "sources_scanned": len(texts),
            "absorbed_files_count": len(texts),
            "extracted_flags_count": extracted_flags_count,
            "skipped_invalid_urls_count": skipped_invalid_urls_count,
            "parse_errors_count": parse_errors_count,
        }

    def absorb_attempt_workspace(self, workspace: Path) -> dict[str, Any]:
        """Aggregate and persist evidence from one attempt workspace."""

        payload = self.aggregate_attempt_workspace(workspace)
        counts = self.merge_mapping(payload["aggregated"])
        summary = self.build_prompt_context()
        return {
            "path": str(self.path),
            "artifact_count": int(payload["artifact_count"]),
            "sources_scanned": int(payload["sources_scanned"]),
            "absorbed_files_count": int(payload.get("absorbed_files_count", payload["sources_scanned"])),
            "extracted_flags_count": int(payload.get("extracted_flags_count", 0)),
            "skipped_invalid_urls_count": int(payload.get("skipped_invalid_urls_count", 0)),
            "parse_errors_count": int(payload.get("parse_errors_count", 0)),
            "merge_counts": counts,
            "summary": summary,
        }

    def build_prompt_context(self, *, submitted_flags: Sequence[str] | None = None) -> dict[str, Any]:
        """Render a compact prompt-oriented summary from the evidence store."""

        hosts = self._format_host_list()
        services = self._format_service_list()
        known_hosts_services = dedupe_preserve_order(hosts + services)
        known_credentials = self._format_credential_list()
        known_pivots = self._format_pivot_list()
        known_flags = dedupe_preserve_order(
            [str(flag).strip() for flag in (submitted_flags or []) if str(flag).strip()]
            + [item.get("value", "") for item in self.data["flags"] if item.get("status") == "submitted"]
        )

        counts = {category: len(self.data.get(category, [])) for category in EVIDENCE_CATEGORIES}
        summary_parts: list[str] = []
        if counts["hosts"]:
            summary_parts.append(f"{counts['hosts']} host(s)")
        if counts["services"]:
            summary_parts.append(f"{counts['services']} service(s)")
        if counts["urls"]:
            summary_parts.append(f"{counts['urls']} URL(s)")
        if counts["creds"]:
            summary_parts.append(f"{counts['creds']} credential artifact(s)")
        if counts["pivots"]:
            summary_parts.append(f"{counts['pivots']} pivot/tunnel artifact(s)")
        if counts["flags"]:
            summary_parts.append(f"{counts['flags']} flag artifact(s)")
        if counts["loot"]:
            summary_parts.append(f"{counts['loot']} loot item(s)")
        if counts["vulns"]:
            summary_parts.append(f"{counts['vulns']} vuln hint(s)")

        return {
            "summary": ", ".join(summary_parts) if summary_parts else "No preserved evidence yet.",
            "counts": counts,
            "known_hosts": hosts[:12],
            "known_services": services[:12],
            "known_hosts_services": known_hosts_services[:16],
            "known_urls": self._format_url_list()[:16],
            "known_credentials": known_credentials[:12],
            "known_pivots": known_pivots[:12],
            "notable_notes": self._format_note_list()[:12],
            "known_submitted_flags": known_flags[:12],
        }

    def mark_flags_submitted(self, flags: Sequence[str]) -> dict[str, int]:
        """Upgrade flag artifacts to submitted status when the platform accepts them."""

        items = [{"value": str(flag).strip(), "status": "submitted"} for flag in flags if str(flag).strip()]
        return self.merge_mapping({"flags": items})

    def _load(self) -> dict[str, Any]:
        empty = self._empty_payload()
        if not self.path.exists():
            return empty
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log("evidence_store_load_error", {"path": str(self.path), "error": str(exc)})
            return empty
        if not isinstance(payload, dict):
            return empty
        for category in EVIDENCE_CATEGORIES:
            payload.setdefault(category, [])
            if not isinstance(payload[category], list):
                payload[category] = []
        payload.setdefault("version", 1)
        payload.setdefault("challenge_code", self.challenge_code)
        payload.setdefault("created_at", self._timestamp())
        payload.setdefault("updated_at", self._timestamp())
        return payload

    def _empty_payload(self) -> dict[str, Any]:
        payload = {
            "version": 1,
            "challenge_code": self.challenge_code,
            "created_at": self._timestamp(),
            "updated_at": self._timestamp(),
        }
        for category in EVIDENCE_CATEGORIES:
            payload[category] = []
        return payload

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    def _merge_item(self, category: str, raw_item: Any) -> bool:
        item = self._coerce_item(category, raw_item)
        if item is None:
            return False

        existing_items = self.data[category]
        fingerprint = self._fingerprint(category, item)
        for index, existing in enumerate(existing_items):
            if self._fingerprint(category, existing) != fingerprint:
                continue
            merged = self._merge_existing(category, existing, item)
            if merged != existing:
                existing_items[index] = merged
                return True
            return False

        existing_items.append(item)
        return True

    def _coerce_item(self, category: str, raw_item: Any) -> dict[str, Any] | None:
        if raw_item is None:
            return None
        if isinstance(raw_item, str):
            text = raw_item.strip()
            if not text:
                return None
            if category == "hosts":
                return {"value": text, "kind": self._guess_host_kind(text)}
            if category == "urls":
                return {"url": text}
            if category == "notes":
                return {"fact": text}
            if category == "flags":
                return {"value": text, "status": "candidate"}
            if category == "creds":
                return {"kind": "fact", "value": text}
            if category == "pivots":
                return {"type": "artifact", "value": text}
            if category == "loot":
                return {"kind": "artifact", "value": text}
            if category == "vulns":
                return {"name": text}
            if category == "services":
                return self._service_from_string(text)
            return None

        if not isinstance(raw_item, dict):
            return None

        if category == "hosts":
            value = self._first_text(raw_item.get("value"), raw_item.get("host"), raw_item.get("ip"), raw_item.get("domain"))
            if not value or not self._looks_like_real_host(value):
                return None
            return {"value": value, "kind": self._first_text(raw_item.get("kind"), self._guess_host_kind(value))}

        if category == "services":
            host = self._first_text(raw_item.get("host"), raw_item.get("ip"), raw_item.get("hostname"))
            port = self._safe_int(raw_item.get("port"))
            service = self._first_text(raw_item.get("service"), raw_item.get("scheme"), raw_item.get("name"))
            protocol = self._first_text(raw_item.get("protocol"), raw_item.get("transport"))
            title = self._first_text(raw_item.get("title"), raw_item.get("product"), raw_item.get("webserver"))
            if host and not self._looks_like_real_host(host):
                return None
            if not host and port is None and not service and not title:
                return None
            item: dict[str, Any] = {}
            if host:
                item["host"] = host
            if port is not None:
                item["port"] = port
            if service:
                item["service"] = service
            if protocol:
                item["protocol"] = protocol
            if title:
                item["title"] = title
            return item

        if category == "urls":
            url = self._first_text(raw_item.get("url"), raw_item.get("value"))
            normalized_url = self._normalize_observed_url(url)
            return {"url": normalized_url} if normalized_url else None

        if category == "creds":
            item = {
                "kind": self._first_text(raw_item.get("kind"), "fact"),
                "username": self._first_text(raw_item.get("username")),
                "password": self._first_text(raw_item.get("password")),
                "value": self._first_text(raw_item.get("value")),
                "label": self._first_text(raw_item.get("label")),
            }
            item = {key: value for key, value in item.items() if value}
            if not item:
                return None
            value = self._first_text(item.get("value"), item.get("password"))
            if value and self._looks_like_code_blob(value):
                return None
            return item

        if category == "vulns":
            item = {
                "name": self._first_text(raw_item.get("name"), raw_item.get("cve")),
                "target": self._first_text(raw_item.get("target"), raw_item.get("url"), raw_item.get("host")),
                "confidence": self._first_text(raw_item.get("confidence")),
                "detail": self._first_text(raw_item.get("detail")),
            }
            item = {key: value for key, value in item.items() if value}
            return item if item else None

        if category == "flags":
            value = self._first_text(raw_item.get("value"), raw_item.get("flag"))
            if not value:
                return None
            return {"value": value, "status": self._first_text(raw_item.get("status"), "candidate")}

        if category == "pivots":
            item = {
                "type": self._first_text(raw_item.get("type"), "artifact"),
                "value": self._first_text(raw_item.get("value"), raw_item.get("detail")),
                "detail": self._first_text(raw_item.get("detail"), raw_item.get("network")),
            }
            item = {key: value for key, value in item.items() if value}
            return item if item else None

        if category == "loot":
            item = {
                "kind": self._first_text(raw_item.get("kind"), "artifact"),
                "value": self._first_text(raw_item.get("value"), raw_item.get("path"), raw_item.get("name")),
                "detail": self._first_text(raw_item.get("detail")),
            }
            item = {key: value for key, value in item.items() if value}
            return item if item else None

        if category == "notes":
            fact = self._first_text(raw_item.get("fact"), raw_item.get("value"), raw_item.get("note"))
            return {"fact": fact} if fact else None
        return None

    def _merge_existing(self, category: str, existing: dict[str, Any], new_item: dict[str, Any]) -> dict[str, Any]:
        if category == "flags":
            status = "submitted" if "submitted" in {existing.get("status"), new_item.get("status")} else "candidate"
            return {"value": new_item.get("value", existing.get("value")), "status": status}

        merged = dict(existing)
        for key, value in new_item.items():
            if value in (None, "", []):
                continue
            if key not in merged or merged.get(key) in (None, "", []):
                merged[key] = value
                continue
            if key == "detail" and str(value) not in str(merged.get(key)):
                merged[key] = f"{merged[key]}; {value}"
        return merged

    def _fingerprint(self, category: str, item: dict[str, Any]) -> str:
        if category == "flags":
            return str(item.get("value", "")).strip().lower()
        if category == "urls":
            return str(item.get("url", "")).strip().lower()
        if category == "hosts":
            return str(item.get("value", "")).strip().lower()
        if category == "services":
            return "|".join(
                str(item.get(key, "")).strip().lower()
                for key in ("host", "port", "service", "protocol", "title")
            )
        if category == "creds":
            return "|".join(
                str(item.get(key, "")).strip().lower()
                for key in ("kind", "username", "password", "value", "label")
            )
        if category == "pivots":
            return "|".join(str(item.get(key, "")).strip().lower() for key in ("type", "value"))
        if category == "loot":
            return "|".join(str(item.get(key, "")).strip().lower() for key in ("kind", "value"))
        if category == "notes":
            return str(item.get("fact", "")).strip().lower()
        if category == "vulns":
            return "|".join(str(item.get(key, "")).strip().lower() for key in ("name", "target"))
        return json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)

    def _collect_workspace_texts(self, workspace: Path) -> list[str]:
        texts: list[str] = []
        candidates = [
            workspace / "final_answer.txt",
            workspace / "todo.md",
        ]
        for path in candidates:
            if path.exists() and path.is_file():
                text = self._read_text(path)
                if text:
                    texts.append(text)

        for note_path in sorted((workspace / "notes").glob("*")):
            if not note_path.is_file():
                continue
            text = self._read_text(note_path)
            if text:
                texts.append(text)

        texts.extend(self._collect_execution_summaries(workspace))
        texts.extend(self._collect_agent_log_summaries(workspace))
        return [text for text in texts if text]

    def _collect_execution_summaries(self, workspace: Path) -> list[str]:
        summaries: list[str] = []
        execution_paths = sorted((workspace / "executions").glob("*.json"))[-20:]
        for execution_path in execution_paths:
            try:
                payload = json.loads(execution_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue

            summary_parts: list[str] = []
            tool_name = self._first_text(payload.get("tool"))
            if tool_name:
                summary_parts.append(f"tool={tool_name}")

            helper_payload = payload.get("helper_payload")
            if isinstance(helper_payload, dict):
                helper_text = self._compact_observed_blob(helper_payload.get("output"))
                if helper_text:
                    summary_parts.append(helper_text)

            wrapped_payload = payload.get("payload")
            if isinstance(wrapped_payload, dict):
                for key in ("result", "message", "error"):
                    compact = self._compact_observed_blob(wrapped_payload.get(key))
                    if compact:
                        summary_parts.append(compact)

            outputs = payload.get("outputs")
            flattened = self._flatten_outputs(outputs)
            compact_outputs = self._compact_observed_blob(flattened)
            if compact_outputs:
                summary_parts.append(compact_outputs)

            if summary_parts:
                summaries.append("\n".join(summary_parts)[:20_000])
        return summaries

    def _collect_agent_log_summaries(self, workspace: Path) -> list[str]:
        log_path = workspace / "logs" / "agent.jsonl"
        if not log_path.exists():
            return []

        summaries: list[str] = []
        try:
            lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return summaries

        for raw_line in lines[-160:]:
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue

            event = str(record.get("event", "")).strip()
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue

            if event == "assistant":
                text = self._compact_observed_blob(payload.get("text"))
                if text:
                    summaries.append(text)
                continue

            if event == "tool_call":
                compact = self._compact_observed_blob(payload.get("result_preview"))
                if compact:
                    summaries.append(compact)
                continue

        return summaries[-40:]

    def _read_text(self, path: Path, *, max_chars: int = 40_000) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
        return text[:max_chars]

    def _flatten_outputs(self, outputs: Any) -> str:
        if not isinstance(outputs, list):
            return ""
        parts: list[str] = []
        for output in outputs:
            if not isinstance(output, dict):
                continue
            output_type = str(output.get("type", "")).strip().lower()
            if output_type == "stream":
                text = self._first_text(output.get("text"))
                if text:
                    parts.append(text)
                continue
            if output_type == "display_data":
                data = output.get("data")
                if isinstance(data, dict):
                    text = self._first_text(data.get("text/plain"))
                    if text:
                        parts.append(text)
                continue
            if output_type == "error":
                traceback_lines = output.get("traceback")
                if isinstance(traceback_lines, list):
                    parts.append("\n".join(str(item) for item in traceback_lines))
                else:
                    text = self._first_text(output.get("evalue"))
                    if text:
                        parts.append(text)
        return "\n".join(part for part in parts if part)

    def _compact_observed_blob(self, value: Any, *, limit: int = 6_000) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False, default=str)
        else:
            text = str(value)

        cleaned_lines: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if self._looks_like_code_blob(line):
                continue
            cleaned_lines.append(line)

        cleaned = "\n".join(cleaned_lines)
        return cleaned[:limit]


    def _extract_services(self, text: str) -> list[dict[str, Any]]:
        services: list[dict[str, Any]] = []
        for match in SERVICE_PATTERN.finditer(text):
            port = self._safe_int(match.group("port"))
            service = self._first_text(match.group("service"))
            if port is None:
                continue
            services.append({"port": port, "service": service, "protocol": "tcp"})

        for match in HOST_PORT_PATTERN.finditer(text):
            host = match.group("host")
            port = self._safe_int(match.group("port"))
            if not host or port is None or not self._looks_like_real_host(host):
                continue
            services.append({"host": host, "port": port, "protocol": "tcp"})
        return dedupe_preserve_order(services, key=lambda item: json.dumps(item, sort_keys=True, default=str))

    def _extract_pivots(self, text: str) -> list[dict[str, Any]]:
        pivots: list[dict[str, Any]] = []
        for pivot_type, pattern in PIVOT_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0).strip()
                if value:
                    pivots.append({"type": pivot_type, "value": value})
        return dedupe_preserve_order(pivots, key=lambda item: json.dumps(item, sort_keys=True, default=str))

    def _extract_loot(self, text: str) -> list[dict[str, Any]]:
        loot: list[dict[str, Any]] = []
        for match in UNIX_PATH_PATTERN.finditer(text):
            loot.append({"kind": "file", "value": match.group(0)})
        for match in WINDOWS_PATH_PATTERN.finditer(text):
            loot.append({"kind": "file", "value": match.group(0)})
        for match in DATABASE_PATTERN.finditer(text):
            loot.append({"kind": "database", "value": match.group(1)})
        for match in DOMAIN_INFO_PATTERN.finditer(text):
            loot.append({"kind": "domain", "value": match.group(1)})
        return dedupe_preserve_order(loot, key=lambda item: json.dumps(item, sort_keys=True, default=str))

    def _profile_notes(self, profile: dict[str, Any]) -> list[dict[str, str]]:
        notes: list[dict[str, str]] = []
        for stack in profile.get("suspected_stack", [])[:4]:
            notes.append({"fact": f"Detected stack marker: {stack}"})
        for framework in profile.get("suspected_frameworks", [])[:4]:
            notes.append({"fact": f"Detected framework marker: {framework}"})
        for path in profile.get("important_paths", [])[:4]:
            notes.append({"fact": f"Important path observed: {path}"})
        for parameter in profile.get("suspicious_parameters", [])[:4]:
            notes.append({"fact": f"Suspicious parameter observed: {parameter}"})
        return dedupe_preserve_order(notes, key=lambda item: item.get("fact", "").lower())

    def _format_host_list(self) -> list[str]:
        values = []
        for item in self.data["hosts"]:
            value = self._first_text(item.get("value"))
            kind = self._first_text(item.get("kind"))
            if not value:
                continue
            values.append(f"{value} ({kind})" if kind else value)
        return dedupe_preserve_order(values)

    def _format_service_list(self) -> list[str]:
        values = []
        for item in self.data["services"]:
            host = self._first_text(item.get("host"))
            port = item.get("port")
            service = self._first_text(item.get("service"))
            protocol = self._first_text(item.get("protocol"))
            title = self._first_text(item.get("title"))
            parts = []
            if host:
                parts.append(host)
            if port not in (None, ""):
                parts.append(f":{port}")
            suffix = " ".join(part for part in (service, protocol, title) if part)
            text = "".join(parts).strip() or suffix
            if suffix and text != suffix:
                text = f"{text} [{suffix}]"
            if text:
                values.append(text)
        return dedupe_preserve_order(values)

    def _format_credential_list(self) -> list[str]:
        values = []
        for item in self.data["creds"]:
            kind = self._first_text(item.get("kind"))
            username = self._first_text(item.get("username"))
            password = self._first_text(item.get("password"))
            value = self._first_text(item.get("value"))
            label = self._first_text(item.get("label"))
            if username and password:
                values.append(f"{username} / {password}")
            elif value:
                prefix = f"{kind}: " if kind else ""
                suffix = f" ({label})" if label else ""
                values.append(f"{prefix}{value}{suffix}")
        return dedupe_preserve_order(values)

    def _format_pivot_list(self) -> list[str]:
        values = []
        for item in self.data["pivots"]:
            pivot_type = self._first_text(item.get("type"))
            value = self._first_text(item.get("value"))
            detail = self._first_text(item.get("detail"))
            text = value or detail
            if not text:
                continue
            if pivot_type and not text.startswith(f"{pivot_type}:"):
                text = f"{pivot_type}: {text}"
            if detail and detail != value:
                text = f"{text} ({detail})"
            values.append(text)
        return dedupe_preserve_order(values)

    def _format_url_list(self) -> list[str]:
        values = []
        for item in self.data["urls"]:
            url = self._first_text(item.get("url"))
            if url:
                values.append(url)
        return dedupe_preserve_order(values)

    def _format_note_list(self) -> list[str]:
        values = []
        for item in self.data["notes"]:
            note = self._first_text(item.get("fact"))
            if note:
                values.append(note)
        return dedupe_preserve_order(values)

    def _service_from_string(self, text: str) -> dict[str, Any] | None:
        parsed = self._safe_urlparse(text) if text.startswith("http://") or text.startswith("https://") else None
        if parsed is not None and parsed.hostname and self._looks_like_real_host(parsed.hostname):
            item: dict[str, Any] = {"host": parsed.hostname, "service": parsed.scheme, "protocol": "tcp"}
            if parsed.port is not None:
                item["port"] = parsed.port
            return item
        match = HOST_PORT_PATTERN.search(text)
        if match is None:
            return None
        host = match.group("host")
        port = self._safe_int(match.group("port"))
        if not host or not self._looks_like_real_host(host):
            return None
        item = {"host": host}
        if port is not None:
            item["port"] = port
        return item

    @staticmethod
    def _looks_like_code_blob(text: str) -> bool:
        lowered = str(text).lower()
        code_markers = (
            "import ",
            "def ",
            "class ",
            "print(",
            "requests.",
            "json.dumps",
            "traceback",
            "session_name",
            "tool_call",
            "execution_record",
            "response:",
            "status:",
            "cookie_payloads",
            "for ",
            "while ",
            "if ",
            "try:",
            "except",
            "payload =",
            "python ",
            "bash -lc ",
        )
        if any(marker in lowered for marker in code_markers):
            return True
        if "\\n" in text and ("{" in text or "[" in text):
            return True
        if len(text) > 400:
            return True
        return False

    def _looks_like_real_host(self, value: str) -> bool:
        candidate = str(value).strip().strip("\\")
        if not candidate:
            return False
        if candidate.startswith(("http://", "https://")):
            parsed = self._safe_urlparse(candidate)
            return bool(parsed and parsed.hostname and self._looks_like_real_host(parsed.hostname))
        if "/" in candidate or "\\" in candidate or " " in candidate:
            return False
        if candidate.endswith((".py", ".json", ".md", ".js", ".css", ".html", ".txt")):
            return False
        if candidate.count(".") == 1 and candidate.split(".")[-1] in {
            "get", "post", "put", "delete", "dumps", "loads", "text", "content", "headers", "py"
        }:
            return False
        if ":" in candidate:
            host_part, _, port_part = candidate.rpartition(":")
            if host_part and port_part.isdigit():
                candidate = host_part
        if is_ip_address(candidate):
            return True
        if "." not in candidate:
            return False
        labels = candidate.split(".")
        if any(not label or len(label) > 63 for label in labels):
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
        return all(set(label) <= allowed for label in labels)

    def _normalize_observed_url(self, value: str | None) -> str | None:
        text = self._first_text(value)
        if not text:
            return None
        cleaned = text.strip().rstrip("\\")
        cleaned = cleaned.replace("\\n", "").replace("\\r", "")
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            return None
        parsed = self._safe_urlparse(cleaned)
        if parsed is None or not parsed.scheme or not parsed.netloc:
            return None
        if not parsed.hostname or not self._looks_like_real_host(parsed.hostname):
            return None
        return cleaned

    @staticmethod
    def _iter_category_items(value: Any) -> Iterable[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _first_text(*values: Any) -> str | None:
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return None

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _guess_host_kind(value: str) -> str:
        if is_ip_address(value):
            return "ip"
        if value.startswith("http://") or value.startswith("https://"):
            return "url"
        return "domain" if "." in value else "host"

    @staticmethod
    def _safe_urlparse(value: str):
        try:
            from urllib.parse import urlparse

            return urlparse(value)
        except ValueError:
            return None

    def _log(self, event: str, payload: dict[str, Any]) -> None:
        if self.event_logger is None:
            return
        try:
            self.event_logger(event, payload)
        except Exception:
            pass

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()
