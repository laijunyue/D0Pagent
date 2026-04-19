from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable
import json
import re


SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}
SEARCH_TOKEN_RE = re.compile(r"[a-z0-9_.:/-]+|[\u4e00-\u9fff]+", re.IGNORECASE)
MAX_SUMMARY_ITEMS = 6
MAX_REQUESTS_IN_DETAIL = 3
MAX_SHELL_OPTIONS_IN_DETAIL = 3
MAX_STRING_PREVIEW = 240


@dataclass(slots=True, frozen=True)
class CVEKnowledgeSummary:
    """Compact search summary returned to the tool layer."""

    id: str
    family: str
    product: str
    cve: str
    severity: str
    tags: list[str]
    versions: list[str]
    fingerprints: list[str]
    signals: list[str]
    verification_summary: list[str]
    exploitation_summary: list[str]
    aliases: list[str]
    path: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the summary to a JSON-friendly dictionary."""

        payload = asdict(self)
        return payload


@dataclass(slots=True, frozen=True)
class CVEKnowledgeRecord:
    """Normalized full CVE / POC knowledge entry."""

    id: str
    family: str
    product: str
    cve: str
    aliases: list[str]
    severity: str
    tags: list[str]
    applicability: dict[str, Any]
    preconditions: list[str]
    verification: dict[str, Any]
    exploitation: dict[str, Any]
    post_exploitation: dict[str, Any]
    stability: dict[str, Any]
    detection_notes: list[str]
    references: list[str]
    path: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the normalized record to a JSON-friendly dictionary."""

        return asdict(self)


def normalize_cve_entry(
    raw: dict[str, Any] | None,
    *,
    source_path: str = "",
    family_hint: str = "",
) -> CVEKnowledgeRecord:
    """Normalize one CVE knowledge entry with safe defaults."""

    raw = raw if isinstance(raw, dict) else {}
    family = _normalize_slug(raw.get("family")) or _normalize_slug(family_hint) or _family_from_path(source_path)
    applicability_raw = raw.get("applicability") if isinstance(raw.get("applicability"), dict) else {}
    verification_raw = raw.get("verification") if isinstance(raw.get("verification"), dict) else {}
    exploitation_raw = raw.get("exploitation") if isinstance(raw.get("exploitation"), dict) else {}
    post_raw = raw.get("post_exploitation") if isinstance(raw.get("post_exploitation"), dict) else {}
    stability_raw = raw.get("stability") if isinstance(raw.get("stability"), dict) else {}

    entry_id = _clean_text(raw.get("id")) or _derive_id_from_path(source_path) or "unknown-cve-entry"
    product = _clean_text(raw.get("product")) or _title_from_family(family) or "Unknown Product"
    severity = _normalize_severity(raw.get("severity"))
    applicability = {
        "versions": _string_list(applicability_raw.get("versions")),
        "fingerprints": _string_list(applicability_raw.get("fingerprints")),
        "signals": _string_list(applicability_raw.get("signals")),
    }
    verification = {
        "method": _clean_text(verification_raw.get("method")) or "manual",
        "requests": _normalize_requests(verification_raw.get("requests"), include_os_hint=False),
    }
    exploitation = {
        "mode": _clean_text(exploitation_raw.get("mode")) or "manual",
        "requests": _normalize_requests(exploitation_raw.get("requests"), include_os_hint=True),
    }
    post_exploitation = {
        "stabilization": _string_list(post_raw.get("stabilization")),
        "shell_options": _normalize_shell_options(post_raw.get("shell_options")),
    }
    stability = {
        "preferred_order": _string_list(stability_raw.get("preferred_order")),
        "safe_commands": _string_list(stability_raw.get("safe_commands")),
        "shell_prerequisites": _string_list(stability_raw.get("shell_prerequisites")),
        "fallbacks": _string_list(stability_raw.get("fallbacks")),
    }

    return CVEKnowledgeRecord(
        id=entry_id,
        family=family or "generic",
        product=product,
        cve=_clean_text(raw.get("cve")) or "N/A",
        aliases=_string_list(raw.get("aliases")),
        severity=severity,
        tags=_string_list(raw.get("tags")),
        applicability=applicability,
        preconditions=_string_list(raw.get("preconditions")),
        verification=verification,
        exploitation=exploitation,
        post_exploitation=post_exploitation,
        stability=stability,
        detection_notes=_string_list(raw.get("detection_notes")),
        references=_string_list(raw.get("references")),
        path=source_path,
    )


def summarize_cve_entry(entry: CVEKnowledgeRecord) -> CVEKnowledgeSummary:
    """Build a compact search summary from a normalized full entry."""

    return CVEKnowledgeSummary(
        id=entry.id,
        family=entry.family,
        product=entry.product,
        cve=entry.cve,
        severity=entry.severity,
        tags=entry.tags[:MAX_SUMMARY_ITEMS],
        versions=_string_list(entry.applicability.get("versions"))[:MAX_SUMMARY_ITEMS],
        fingerprints=_string_list(entry.applicability.get("fingerprints"))[:MAX_SUMMARY_ITEMS],
        signals=_string_list(entry.applicability.get("signals"))[:MAX_SUMMARY_ITEMS],
        verification_summary=_request_summaries(entry.verification)[:MAX_SUMMARY_ITEMS],
        exploitation_summary=_request_summaries(entry.exploitation)[:MAX_SUMMARY_ITEMS],
        aliases=entry.aliases[:MAX_SUMMARY_ITEMS],
        path=entry.path,
    )


def normalize_cve_summary(
    raw: dict[str, Any] | None,
    *,
    family_hint: str = "",
    source_path: str = "",
) -> CVEKnowledgeSummary | None:
    """Normalize one index summary entry with safe defaults."""

    raw = raw if isinstance(raw, dict) else {}
    entry_id = _clean_text(raw.get("id")) or _derive_id_from_path(source_path)
    if not entry_id:
        return None

    family = _normalize_slug(raw.get("family")) or _normalize_slug(family_hint) or _family_from_path(source_path) or "generic"
    product = _clean_text(raw.get("product")) or _title_from_family(family) or "Unknown Product"
    verification_summary = _string_list(raw.get("verification_summary"))
    exploitation_summary = _string_list(raw.get("exploitation_summary"))

    if not verification_summary and isinstance(raw.get("verification"), dict):
        verification_summary = _request_summaries(raw["verification"])
    if not exploitation_summary and isinstance(raw.get("exploitation"), dict):
        exploitation_summary = _request_summaries(raw["exploitation"])

    applicability = raw.get("applicability") if isinstance(raw.get("applicability"), dict) else {}
    return CVEKnowledgeSummary(
        id=entry_id,
        family=family,
        product=product,
        cve=_clean_text(raw.get("cve")) or "N/A",
        severity=_normalize_severity(raw.get("severity")),
        tags=_string_list(raw.get("tags")),
        versions=_string_list(raw.get("versions") or applicability.get("versions")),
        fingerprints=_string_list(raw.get("fingerprints") or applicability.get("fingerprints")),
        signals=_string_list(raw.get("signals") or applicability.get("signals")),
        verification_summary=verification_summary[:MAX_SUMMARY_ITEMS],
        exploitation_summary=exploitation_summary[:MAX_SUMMARY_ITEMS],
        aliases=_string_list(raw.get("aliases")),
        path=source_path,
    )


class CVEKnowledgeBase:
    """Load, search, and summarize the local JSON CVE knowledge base."""

    def __init__(
        self,
        *,
        root: str | Path,
        event_logger: Callable[[str, Any], None] | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.event_logger = event_logger
        self._summaries: dict[str, CVEKnowledgeSummary] = {}
        self._paths: dict[str, Path] = {}
        self._errors: list[dict[str, str]] = []

    def refresh(self) -> None:
        """Refresh summaries from global index, family indexes, and fallback file scans."""

        self._summaries = {}
        self._paths = {}
        self._errors = []

        if not self.root.exists():
            return

        discovered_families = self._discover_family_dirs()
        for family, family_dir in discovered_families:
            self._load_family_index(family, family_dir)
            indexed_paths = {path.resolve() for path in self._paths.values() if path.parent == family_dir}
            for entry_path in sorted(family_dir.glob("*.json")):
                if entry_path.name == "index.json":
                    continue
                if entry_path.resolve() in indexed_paths:
                    continue
                raw = self._load_json(entry_path)
                if raw is None:
                    continue
                record = normalize_cve_entry(raw, source_path=self._relative_path(entry_path), family_hint=family)
                self._register_record(record, entry_path)

    def has_entries(self) -> bool:
        """Return whether the local knowledge base currently has any entries."""

        self.refresh()
        return bool(self._summaries)

    def search(
        self,
        *,
        query: str = "",
        family: str = "",
        product: str = "",
        version: str = "",
        tags: list[str] | None = None,
        severity: str = "",
        limit: int = 5,
    ) -> dict[str, Any]:
        """Search the local knowledge base and return compact structured summaries."""

        self.refresh()

        query_text = _clean_text(query) or ""
        family_filter = _normalize_slug(family)
        product_filter = (_clean_text(product) or "").lower()
        version_filter = (_clean_text(version) or "").lower()
        tags_filter = [item.lower() for item in _string_list(tags)]
        severity_filter = _normalize_severity(severity) if _clean_text(severity) else ""
        try:
            effective_limit = max(min(int(limit or 5), 20), 1)
        except (TypeError, ValueError):
            effective_limit = 5

        ranked: list[tuple[tuple[int, int, int, int, int, str], CVEKnowledgeSummary]] = []
        for summary in self._summaries.values():
            if family_filter and summary.family != family_filter:
                continue
            if product_filter and product_filter not in summary.product.lower():
                continue
            if version_filter and not any(version_filter in item.lower() for item in summary.versions):
                continue
            if severity_filter and summary.severity != severity_filter:
                continue
            if tags_filter and not all(tag in [item.lower() for item in summary.tags] for tag in tags_filter):
                continue

            query_hits, field_hits = self._query_match_score(summary, query_text)
            if query_text and query_hits == 0:
                continue

            family_exact = 1 if family_filter and summary.family == family_filter else 0
            product_exact = 1 if product_filter and summary.product.lower() == product_filter else 0
            severity_score = SEVERITY_ORDER.get(summary.severity, 0)
            ranked.append(
                (
                    (
                        family_exact,
                        product_exact,
                        field_hits,
                        query_hits,
                        severity_score,
                        summary.id,
                    ),
                    summary,
                )
            )

        ranked.sort(key=lambda item: item[0], reverse=True)
        results = [summary.to_dict() for _, summary in ranked[:effective_limit]]
        return {
            "success": True,
            "root": str(self.root),
            "query": query_text,
            "filters": {
                "family": family_filter,
                "product": product_filter,
                "version": version_filter,
                "tags": tags_filter,
                "severity": severity_filter,
            },
            "count": len(results),
            "total": len(ranked),
            "results": results,
            "errors": self._errors[:20],
        }

    def load_by_id(self, entry_id: str) -> dict[str, Any]:
        """Load one CVE entry by id and return an agent-friendly detail summary."""

        self.refresh()
        normalized_id = _clean_text(entry_id) or ""
        if not normalized_id:
            return {
                "success": False,
                "error": "id is required",
                "root": str(self.root),
            }

        path = self._paths.get(normalized_id)
        if path is None:
            return {
                "success": False,
                "error": f"CVE knowledge entry '{normalized_id}' not found",
                "root": str(self.root),
                "available_ids": sorted(self._summaries)[:50],
            }

        raw = self._load_json(path)
        if raw is None:
            return {
                "success": False,
                "error": f"Failed to read CVE knowledge entry '{normalized_id}'",
                "root": str(self.root),
                "path": self._relative_path(path),
            }

        record = normalize_cve_entry(
            raw,
            source_path=self._relative_path(path),
            family_hint=self._summaries.get(normalized_id).family if normalized_id in self._summaries else "",
        )
        return {
            "success": True,
            "root": str(self.root),
            "path": record.path,
            "knowledge": self._build_detail_payload(record),
            "raw_entry_excerpt": self._truncate_record(record),
            "errors": self._errors[:20],
        }

    def _discover_family_dirs(self) -> list[tuple[str, Path]]:
        families: dict[str, Path] = {}
        global_index = self._load_json(self.root / "index.json")
        if isinstance(global_index, dict):
            for item in global_index.get("families", []):
                if not isinstance(item, dict):
                    continue
                family = _normalize_slug(item.get("family") or item.get("slug") or item.get("name"))
                if not family:
                    continue
                families[family] = (self.root / family).resolve()

        for family_dir in sorted(path for path in self.root.iterdir() if path.is_dir()):
            families.setdefault(family_dir.name.lower(), family_dir.resolve())

        return [(family, directory) for family, directory in sorted(families.items()) if directory.exists()]

    def _load_family_index(self, family: str, family_dir: Path) -> None:
        index_path = family_dir / "index.json"
        raw = self._load_json(index_path)
        if not isinstance(raw, dict):
            return

        for item in raw.get("entries", []):
            if not isinstance(item, dict):
                continue
            entry_path = self._resolve_entry_path(family_dir, item.get("path"))
            source_path = self._relative_path(entry_path) if entry_path is not None else ""
            summary = normalize_cve_summary(item, family_hint=family, source_path=source_path)
            if summary is None:
                self._log_error(index_path, "family index entry missing id")
                continue
            self._register_summary(summary, entry_path)

    def _register_record(self, record: CVEKnowledgeRecord, path: Path | None) -> None:
        self._register_summary(summarize_cve_entry(record), path)

    def _register_summary(self, summary: CVEKnowledgeSummary, path: Path | None) -> None:
        if summary.id in self._summaries:
            self._log_error(path, f"duplicate CVE knowledge id '{summary.id}'")
            return
        self._summaries[summary.id] = summary
        if path is not None:
            self._paths[summary.id] = path.resolve()

    def _build_detail_payload(self, record: CVEKnowledgeRecord) -> dict[str, Any]:
        return {
            "basic_info": {
                "id": record.id,
                "family": record.family,
                "product": record.product,
                "cve": record.cve,
                "severity": record.severity,
                "aliases": record.aliases,
                "tags": record.tags,
                "path": record.path,
            },
            "applicability": {
                "versions": _string_list(record.applicability.get("versions")),
                "fingerprints": _string_list(record.applicability.get("fingerprints")),
                "signals": _string_list(record.applicability.get("signals")),
                "preconditions": record.preconditions,
            },
            "verification_steps": self._format_requests(record.verification, include_mode=False),
            "exploitation_steps": self._format_requests(record.exploitation, include_mode=True),
            "post_exploitation": {
                "stabilization": record.post_exploitation.get("stabilization", []),
                "shell_options": record.post_exploitation.get("shell_options", [])[:MAX_SHELL_OPTIONS_IN_DETAIL],
            },
            "stability": {
                "preferred_order": record.stability.get("preferred_order", []),
                "safe_commands": record.stability.get("safe_commands", []),
                "shell_prerequisites": record.stability.get("shell_prerequisites", []),
                "fallbacks": record.stability.get("fallbacks", []),
            },
            "detection_notes": record.detection_notes,
            "references": record.references,
        }

    def _format_requests(self, section: dict[str, Any], *, include_mode: bool) -> dict[str, Any]:
        payload = {
            "method": _clean_text(section.get("method")) or "manual",
            "requests": [],
        }
        if include_mode:
            payload["mode"] = _clean_text(section.get("mode")) or "manual"

        requests = section.get("requests")
        if not isinstance(requests, list):
            return payload

        for request in requests[:MAX_REQUESTS_IN_DETAIL]:
            if not isinstance(request, dict):
                continue
            item = {
                "method": _clean_text(request.get("method")) or "GET",
                "path": _clean_text(request.get("path")) or "/",
                "headers": _string_dict(request.get("headers")),
                "data": _truncate_preview(_clean_text(request.get("data")) or ""),
            }
            if include_mode:
                os_hint = _clean_text(request.get("os_hint"))
                if os_hint:
                    item["os_hint"] = os_hint
            matchers = _string_list(request.get("matchers"))
            if matchers:
                item["matchers"] = matchers
            payload["requests"].append(item)
        return payload

    def _truncate_record(self, record: CVEKnowledgeRecord) -> dict[str, Any]:
        data = record.to_dict()
        verification_requests = data["verification"].get("requests", [])
        exploitation_requests = data["exploitation"].get("requests", [])
        data["verification"]["requests"] = verification_requests[:MAX_REQUESTS_IN_DETAIL]
        data["exploitation"]["requests"] = exploitation_requests[:MAX_REQUESTS_IN_DETAIL]
        data["post_exploitation"]["shell_options"] = data["post_exploitation"].get("shell_options", [])[
            :MAX_SHELL_OPTIONS_IN_DETAIL
        ]
        return data

    def _resolve_entry_path(self, family_dir: Path, raw_path: Any) -> Path | None:
        path_text = _clean_text(raw_path)
        if not path_text:
            return None
        candidate = (family_dir / path_text).resolve()
        if candidate.exists():
            return candidate
        candidate = (self.root / path_text).resolve()
        if candidate.exists():
            return candidate
        return (family_dir / path_text).resolve()

    def _load_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log_error(path, str(exc))
            return None

    def _relative_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root))
        except Exception:
            return str(path)

    def _query_match_score(self, summary: CVEKnowledgeSummary, query: str) -> tuple[int, int]:
        if not query:
            return 0, 0

        query_tokens = _search_tokens(query)
        if not query_tokens:
            return 0, 0

        fields = {
            "id": summary.id.lower(),
            "family": summary.family.lower(),
            "product": summary.product.lower(),
            "cve": summary.cve.lower(),
            "aliases": " ".join(alias.lower() for alias in summary.aliases),
            "tags": " ".join(tag.lower() for tag in summary.tags),
            "versions": " ".join(version.lower() for version in summary.versions),
            "fingerprints": " ".join(item.lower() for item in summary.fingerprints),
            "signals": " ".join(item.lower() for item in summary.signals),
            "verification": " ".join(item.lower() for item in summary.verification_summary),
            "exploitation": " ".join(item.lower() for item in summary.exploitation_summary),
        }

        query_hits = 0
        field_hits = 0
        for field_value in fields.values():
            matched_here = 0
            for token in query_tokens:
                if token in field_value:
                    matched_here += 1
            if matched_here:
                field_hits += 1
                query_hits += matched_here
        return query_hits, field_hits

    def _log_error(self, path: Path | None, message: str) -> None:
        payload = {
            "path": str(path) if path is not None else str(self.root),
            "error": message,
        }
        self._errors.append(payload)
        if self.event_logger is not None:
            self.event_logger("cve_knowledge_error", payload)


def _normalize_requests(raw: Any, *, include_os_hint: bool) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        request: dict[str, Any] = {
            "path": _clean_text(item.get("path")) or "/",
            "method": (_clean_text(item.get("method")) or "GET").upper(),
            "headers": _string_dict(item.get("headers")),
            "data": _clean_text(item.get("data")) or "",
            "matchers": _string_list(item.get("matchers")),
        }
        if include_os_hint:
            request["os_hint"] = _clean_text(item.get("os_hint")) or "unknown"
        normalized.append(request)
    return normalized


def _normalize_shell_options(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []

    options: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        shell_type = _clean_text(item.get("type")) or "generic_shell"
        template = _clean_text(item.get("template")) or ""
        options.append({"type": shell_type, "template": template})
    return options


def _request_summaries(section: dict[str, Any] | None) -> list[str]:
    if not isinstance(section, dict):
        return []

    requests = section.get("requests")
    if not isinstance(requests, list):
        return []

    summaries: list[str] = []
    for item in requests:
        if not isinstance(item, dict):
            continue
        method = (_clean_text(item.get("method")) or "GET").upper()
        path = _clean_text(item.get("path")) or "/"
        matcher_text = ", ".join(_string_list(item.get("matchers"))[:2])
        if matcher_text:
            summaries.append(f"{method} {path} -> match {matcher_text}")
        else:
            summaries.append(f"{method} {path}")
    return summaries


def _string_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        text = raw.strip()
        return [text] if text else []
    if not isinstance(raw, list):
        return []

    values: list[str] = []
    for item in raw:
        text = _clean_text(item)
        if text and text not in values:
            values.append(text)
    return values


def _string_dict(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}

    result: dict[str, str] = {}
    for key, value in raw.items():
        clean_key = _clean_text(key)
        clean_value = _clean_text(value)
        if clean_key and clean_value is not None:
            result[clean_key] = clean_value
    return result


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_slug(value: Any) -> str:
    text = (_clean_text(value) or "").lower()
    return re.sub(r"[^a-z0-9_-]+", "-", text).strip("-")


def _normalize_severity(value: Any) -> str:
    text = (_clean_text(value) or "medium").lower()
    return text if text in SEVERITY_ORDER else "medium"


def _derive_id_from_path(path_text: str) -> str:
    path = Path(path_text)
    stem = path.stem.strip()
    return stem or ""


def _family_from_path(path_text: str) -> str:
    path = Path(path_text)
    if len(path.parts) >= 2:
        return _normalize_slug(path.parts[0])
    return ""


def _title_from_family(family: str) -> str:
    if not family:
        return ""
    return family.replace("-", " ").replace("_", " ").title()


def _search_tokens(text: str) -> list[str]:
    return [token.lower() for token in SEARCH_TOKEN_RE.findall(text or "") if token.strip()]


def _truncate_preview(text: str) -> str:
    if len(text) <= MAX_STRING_PREVIEW:
        return text
    return text[:MAX_STRING_PREVIEW] + "..."
