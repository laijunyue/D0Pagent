from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import json
import os
import re
import threading

import yaml


FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)
SEARCH_TOKEN_RE = re.compile(r"[a-z0-9]+|[\u4e00-\u9fff]+", re.IGNORECASE)
SKILL_FILENAME = "SKILL.md"
DEFAULT_LOAD_CHARS = 12_000
MAX_LOAD_CHARS = 14_000
MAX_SUMMARY_CHARS = 320
ZONE_SKILL_PRIORITIES: dict[int, tuple[str, ...]] = {
    1: ("src-web-recon", "web-vuln-hunting"),
    2: ("cve-cloud-aiinfra", "web-vuln-hunting"),
    3: ("network-oa-pivot", "persistence-maintenance"),
    4: ("ad-internal-ops", "persistence-maintenance"),
}
SKILL_KEYWORD_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("web", "login", "admin", "api", "js", "upload"), ("src-web-recon", "web-vuln-hunting")),
    (
        ("cve", "k8s", "docker", "jupyter", "mlflow", "ray", "cloud", "metadata", "kubernetes", "container"),
        ("cve-cloud-aiinfra", "web-vuln-hunting"),
    ),
    (("oa", "intranet", "pivot", "proxy", "internal", "jump", "tunnel"), ("network-oa-pivot", "persistence-maintenance")),
    (("ad", "domain", "kerberos", "ldap", "dc", "域渗透", "域控", "活动目录"), ("ad-internal-ops", "persistence-maintenance")),
)
DYNAMIC_SKILL_SIGNAL_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        (
            "swagger",
            "swagger ui",
            "redoc",
            "openapi",
            "openapi.json",
            "/docs",
            "/redoc",
            "fastapi",
            "uvicorn",
            "fetch(",
            "/api/",
            "api/",
        ),
        ("src-web-recon", "web-vuln-hunting"),
    ),
    (
        (
            "only admins can see private jobs",
            "admin only",
            "unauthorized",
            "forbidden",
            "not allowed",
            "private jobs",
            "private",
            "admin",
            "login",
            "job",
            "filter",
            "demo",
        ),
        ("web-vuln-hunting", "src-web-recon"),
    ),
)


@dataclass(slots=True, frozen=True)
class SkillRecord:
    name: str
    slug: str
    category: str
    stage: list[str]
    tags: list[str]
    priority: int
    summary: str
    when_to_load: str
    tools: list[str]
    signals: list[str]
    title: str
    path: Path

    def to_index_dict(self, relative_path: str) -> dict[str, Any]:
        return {
            "name": self.name,
            "slug": self.slug,
            "category": self.category,
            "stage": self.stage,
            "tags": self.tags,
            "priority": self.priority,
            "summary": self.summary,
            "when_to_load": self.when_to_load,
            "tools": self.tools,
            "signals": self.signals,
            "title": self.title,
            "path": relative_path,
        }


class SkillManager:
    _index_write_lock = threading.Lock()

    def __init__(
        self,
        *,
        skills_root: str | Path,
        workspace: Path,
        event_logger: Callable[[str, Any], None] | None = None,
    ) -> None:
        self.skills_root = Path(skills_root).expanduser().resolve()
        self.project_root = self.skills_root.parent
        self.workspace = workspace
        self.event_logger = event_logger
        self.index_path = self.skills_root / "index.yaml"
        self.workflow_path = self.skills_root / "WORKFLOW.md"
        self.log_path = self.workspace / "logs" / "skills.jsonl"
        self.loaded_log_path = self.workspace / "skills_loaded.jsonl"
        self._records: dict[str, SkillRecord] = {}
        self._index_errors: list[dict[str, str]] = []
        self._generated_at: str | None = None

    def refresh_index(self) -> None:
        records: dict[str, SkillRecord] = {}
        errors: list[dict[str, str]] = []

        if not self.skills_root.exists():
            self._records = {}
            self._index_errors = [{"path": str(self.skills_root), "error": "skills root does not exist"}]
            self._generated_at = self._timestamp()
            self._log(
                "skills_index_built",
                {
                    "skills_root": str(self.skills_root),
                    "skills_count": 0,
                    "errors": self._index_errors,
                },
            )
            return

        for skill_path in sorted(self.skills_root.glob(f"*/{SKILL_FILENAME}")):
            try:
                record = self._parse_skill(skill_path)
            except Exception as exc:
                errors.append({"path": self._relative_path(skill_path), "error": str(exc)})
                continue

            if record.slug in records:
                errors.append(
                    {
                        "path": self._relative_path(skill_path),
                        "error": f"duplicate skill slug: {record.slug}",
                    }
                )
                continue
            records[record.slug] = record

        self._records = dict(sorted(records.items(), key=lambda item: (item[1].priority, item[1].name.lower())))
        self._index_errors = errors
        self._generated_at = self._timestamp()
        self._write_index_file()
        self._log(
            "skills_index_built",
            {
                "skills_root": str(self.skills_root),
                "skills_count": len(self._records),
                "workflow_path": self._relative_path(self.workflow_path) if self.workflow_path.exists() else None,
                "index_path": str(self.index_path),
                "errors": errors,
            },
        )

    def has_skills(self) -> bool:
        self._ensure_index_loaded()
        return bool(self._records)

    def skill_count(self) -> int:
        self._ensure_index_loaded()
        return len(self._records)

    def available_slugs(self) -> list[str]:
        self._ensure_index_loaded()
        return list(self._records)

    def list_skills(
        self,
        *,
        category: str | None = None,
        stage: str | Iterable[str] | None = None,
        tags: str | Iterable[str] | None = None,
        limit: int | None = None,
        step: int | None = None,
    ) -> dict[str, Any]:
        self._ensure_index_loaded()
        filtered = self._filter_records(category=category, stage=stage, tags=tags)
        limited = self._apply_limit(filtered, limit)
        payload = {
            "success": True,
            "skills_root": str(self.skills_root),
            "workflow_file": self._relative_path(self.workflow_path) if self.workflow_path.exists() else None,
            "generated_at": self._generated_at,
            "count": len(limited),
            "total": len(filtered),
            "skills": [self._public_record(record) for record in limited],
            "index_errors": self._index_errors,
            "recommended_start": "core-methodology" if "core-methodology" in self._records else None,
            "load_strategy": "Use LoadSkill only for the few skills that match the current target and stage.",
        }
        self._log(
            "skills_listed",
            {
                "step": step,
                "count": len(limited),
                "total": len(filtered),
                "category": category,
                "stage": self._normalize_list(stage),
                "tags": self._normalize_list(tags),
            },
        )
        return payload

    def search_skills(
        self,
        *,
        query: str | None = None,
        category: str | None = None,
        stage: str | Iterable[str] | None = None,
        tags: str | Iterable[str] | None = None,
        limit: int | None = None,
        step: int | None = None,
    ) -> dict[str, Any]:
        self._ensure_index_loaded()
        filtered = self._filter_records(category=category, stage=stage, tags=tags)
        query_text = (query or "").strip().lower()
        if query_text:
            filtered = self._rank_search_records(filtered, query_text)
        limited = self._apply_limit(filtered, limit)
        payload = {
            "success": True,
            "query": query or "",
            "count": len(limited),
            "total": len(filtered),
            "skills": [self._public_record(record) for record in limited],
            "index_errors": self._index_errors,
        }
        self._log(
            "skills_searched",
            {
                "step": step,
                "query": query or "",
                "count": len(limited),
                "total": len(filtered),
                "category": category,
                "stage": self._normalize_list(stage),
                "tags": self._normalize_list(tags),
            },
        )
        return payload

    def load_skill(self, slug: str, *, max_chars: int | None = None, step: int | None = None) -> dict[str, Any]:
        self._ensure_index_loaded()
        normalized_slug = str(slug or "").strip()
        record = self._records.get(normalized_slug)
        if record is None:
            payload = {
                "success": False,
                "error": f"skill '{normalized_slug}' not found",
                "available_slugs": self.available_slugs(),
            }
            self._log("skill_load_failed", {"step": step, "slug": normalized_slug, "error": payload["error"]})
            return payload

        resolved_path = record.path.resolve()
        try:
            resolved_path.relative_to(self.skills_root)
        except ValueError:
            payload = {
                "success": False,
                "error": f"skill path escapes skills root: {resolved_path}",
                "slug": normalized_slug,
            }
            self._log("skill_load_failed", {"step": step, "slug": normalized_slug, "error": payload["error"]})
            return payload

        try:
            raw_text = resolved_path.read_text(encoding="utf-8")
        except Exception as exc:
            payload = {
                "success": False,
                "error": f"failed to read skill '{normalized_slug}': {exc}",
                "slug": normalized_slug,
            }
            self._log("skill_load_failed", {"step": step, "slug": normalized_slug, "error": payload["error"]})
            return payload

        effective_limit = self._coerce_load_limit(max_chars)
        content, truncated = self._truncate(raw_text, effective_limit)
        payload = {
            "success": True,
            "skill": self._public_record(record),
            "document": content,
            "document_chars": len(raw_text),
            "returned_chars": len(content),
            "truncated": truncated,
            "max_chars": effective_limit,
        }
        log_payload = {
            "step": step,
            "slug": normalized_slug,
            "path": self._relative_path(resolved_path),
            "document_chars": len(raw_text),
            "returned_chars": len(content),
            "truncated": truncated,
            "max_chars": effective_limit,
        }
        self._append_jsonl(self.loaded_log_path, {"timestamp": self._timestamp(), **log_payload})
        self._log("skill_loaded", log_payload)
        return payload

    def recommend_skills_for_challenge(self, challenge: dict[str, Any]) -> list[str]:
        """Recommend a small set of candidate skills for main-battleground challenges."""

        self._ensure_index_loaded()
        recommendations = recommend_skills_for_challenge(challenge, available_slugs=self._records.keys())
        self._log(
            "skills_recommended",
            {
                "challenge_code": challenge.get("code") if isinstance(challenge, dict) else None,
                "challenge_title": challenge.get("title") if isinstance(challenge, dict) else None,
                "recommendations": recommendations,
            },
        )
        return recommendations

    def _ensure_index_loaded(self) -> None:
        if self._generated_at is None:
            self.refresh_index()

    def _filter_records(
        self,
        *,
        category: str | None = None,
        stage: str | Iterable[str] | None = None,
        tags: str | Iterable[str] | None = None,
    ) -> list[SkillRecord]:
        category_filter = (category or "").strip().lower()
        stage_filters = {item.lower() for item in self._normalize_list(stage)}
        tag_filters = {item.lower() for item in self._normalize_list(tags)}

        filtered: list[SkillRecord] = []
        for record in self._records.values():
            if category_filter and record.category.lower() != category_filter:
                continue
            if stage_filters and not stage_filters.intersection({item.lower() for item in record.stage}):
                continue
            if tag_filters and not tag_filters.issubset({item.lower() for item in record.tags}):
                continue
            filtered.append(record)
        return filtered

    def _parse_skill(self, skill_path: Path) -> SkillRecord:
        text = skill_path.read_text(encoding="utf-8")
        metadata, body = self._split_frontmatter(text)
        title = self._extract_title(body, fallback=skill_path.parent.name.replace("-", " ").title())

        slug = self._safe_slug(str(metadata.get("slug") or skill_path.parent.name))
        if not slug:
            raise ValueError("skill slug is empty")

        name = str(metadata.get("name") or title).strip() or title
        category = str(metadata.get("category") or "general").strip() or "general"
        stage = self._normalize_list(metadata.get("stage"))
        tags = self._normalize_list(metadata.get("tags"))
        tools = self._normalize_list(metadata.get("tools"))
        signals = self._normalize_list(metadata.get("signals"))
        when_to_load = str(metadata.get("when_to_load") or "").strip()
        summary = str(metadata.get("summary") or "").strip() or self._derive_summary(body)
        priority = self._coerce_priority(metadata.get("priority"))

        return SkillRecord(
            name=name,
            slug=slug,
            category=category,
            stage=stage,
            tags=tags,
            priority=priority,
            summary=summary,
            when_to_load=when_to_load,
            tools=tools,
            signals=signals,
            title=title,
            path=skill_path,
        )

    def _write_index_file(self) -> None:
        payload = {
            "version": 1,
            "generated_at": self._generated_at,
            "workflow_file": self._relative_path(self.workflow_path) if self.workflow_path.exists() else None,
            "skills": [
                record.to_index_dict(relative_path=self._relative_path(record.path))
                for record in self._records.values()
            ],
            "errors": self._index_errors,
        }
        try:
            serialized_payload = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
            self.skills_root.mkdir(parents=True, exist_ok=True)
            temp_path = self.index_path.with_name(
                f"{self.index_path.name}.tmp.{os.getpid()}.{threading.get_ident()}"
            )
            with self.__class__._index_write_lock:
                temp_path.write_text(serialized_payload, encoding="utf-8")
                os.replace(temp_path, self.index_path)
        except Exception as exc:
            self._append_jsonl(
                self.log_path,
                {
                    "timestamp": self._timestamp(),
                    "event": "skills_index_write_failed",
                    "payload": {"index_path": str(self.index_path), "error": str(exc)},
                },
            )

    def _public_record(self, record: SkillRecord) -> dict[str, Any]:
        return {
            "name": record.name,
            "slug": record.slug,
            "category": record.category,
            "stage": record.stage,
            "tags": record.tags,
            "priority": record.priority,
            "summary": record.summary,
            "when_to_load": record.when_to_load,
            "signals": record.signals,
            "tools": record.tools,
            "path": self._relative_path(record.path),
        }

    def _search_blob(self, record: SkillRecord) -> str:
        parts = [
            record.name,
            record.slug,
            record.category,
            record.summary,
            record.when_to_load,
            " ".join(record.stage),
            " ".join(record.tags),
            " ".join(record.tools),
            " ".join(record.signals),
        ]
        return " ".join(part for part in parts if part).lower()

    def _rank_search_records(self, records: list[SkillRecord], query_text: str) -> list[SkillRecord]:
        query_tokens = self._search_tokens(query_text)
        scored_records: list[tuple[SkillRecord, int]] = []
        for record in records:
            score = self._score_record_search(record, query_text=query_text, query_tokens=query_tokens)
            if score > 0:
                scored_records.append((record, score))
        scored_records.sort(key=lambda item: (-item[1], item[0].priority, item[0].name.lower()))
        return [record for record, _score in scored_records]

    def _score_record_search(self, record: SkillRecord, *, query_text: str, query_tokens: list[str]) -> int:
        index = self._record_search_index(record)
        score = 0
        matched_tokens = 0

        if query_text in index["tag_values"]:
            score += 320
        if query_text in index["stage_values"]:
            score += 300
        if query_text == record.slug.lower():
            score += 280
        elif query_text in record.slug.lower():
            score += 180
        if query_text in index["name_values"]:
            score += 240
        elif any(query_text in value for value in index["name_values"]):
            score += 150
        if query_text == record.category.lower():
            score += 120

        for token in query_tokens:
            token_score = self._score_query_token(index, token)
            if token_score > 0:
                matched_tokens += 1
                score += token_score

        if query_tokens and matched_tokens == len(query_tokens):
            score += 90
        elif matched_tokens > 1:
            score += matched_tokens * 20

        if self._allow_loose_substring_match(query_text):
            blob = self._search_blob(record)
            if query_text in blob:
                score += 40
            elif any(token in blob for token in query_tokens):
                score += 10

        return score

    def _score_query_token(self, index: dict[str, Any], token: str) -> int:
        if token in index["tag_values"]:
            return 140
        if token in index["stage_values"]:
            return 130
        if token in index["tag_tokens"]:
            return 120
        if token in index["stage_tokens"]:
            return 110
        if token in index["slug_tokens"]:
            return 100
        if token in index["name_tokens"]:
            return 90
        if token in index["category_tokens"]:
            return 70
        if token in index["signal_tokens"]:
            return 60
        if token in index["summary_tokens"]:
            return 45
        return 0

    def _record_search_index(self, record: SkillRecord) -> dict[str, Any]:
        tag_values = {item.lower() for item in record.tags}
        stage_values = {item.lower() for item in record.stage}
        name_values = {record.name.lower(), record.title.lower()}
        return {
            "tag_values": tag_values,
            "stage_values": stage_values,
            "name_values": name_values,
            "tag_tokens": self._token_set(record.tags),
            "stage_tokens": self._token_set(record.stage),
            "slug_tokens": self._token_set([record.slug]),
            "name_tokens": self._token_set([record.name, record.title]),
            "category_tokens": self._token_set([record.category]),
            "signal_tokens": self._token_set(record.signals + record.tools),
            "summary_tokens": self._token_set([record.summary, record.when_to_load]),
        }

    def _token_set(self, values: Iterable[str]) -> set[str]:
        tokens: set[str] = set()
        for value in values:
            tokens.update(self._search_tokens(value))
        return tokens

    @staticmethod
    def _search_tokens(value: str) -> list[str]:
        return [match.group(0).lower() for match in SEARCH_TOKEN_RE.finditer(value.lower())]

    @staticmethod
    def _allow_loose_substring_match(query_text: str) -> bool:
        compact_query = query_text.strip().lower()
        if not compact_query:
            return False
        if re.search(r"[\u4e00-\u9fff]", compact_query):
            return True
        if " " in compact_query or "-" in compact_query or "_" in compact_query:
            return True
        return len(compact_query) >= 3

    @staticmethod
    def _split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
        match = FRONTMATTER_RE.match(text)
        if not match:
            return {}, text.strip()
        raw_frontmatter, body = match.groups()
        metadata = yaml.safe_load(raw_frontmatter) or {}
        if not isinstance(metadata, dict):
            metadata = {}
        return metadata, body.strip()

    @staticmethod
    def _extract_title(body: str, *, fallback: str) -> str:
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                return stripped.lstrip("#").strip() or fallback
        return fallback

    @staticmethod
    def _derive_summary(body: str) -> str:
        cleaned_lines: list[str] = []
        in_code_block = False
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if line.startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block or not line or line.startswith("#"):
                continue
            cleaned_lines.append(line)
            if len(" ".join(cleaned_lines)) >= MAX_SUMMARY_CHARS:
                break
        summary = " ".join(cleaned_lines).strip()
        if len(summary) > MAX_SUMMARY_CHARS:
            summary = summary[:MAX_SUMMARY_CHARS].rstrip() + "..."
        return summary

    @staticmethod
    def _normalize_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = [item.strip() for item in value.split(",")]
            return [item for item in raw_items if item]
        if isinstance(value, Iterable):
            normalized: list[str] = []
            for item in value:
                item_text = str(item).strip()
                if item_text:
                    normalized.append(item_text)
            return normalized
        item_text = str(value).strip()
        return [item_text] if item_text else []

    @staticmethod
    def _safe_slug(value: str) -> str:
        return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")

    @staticmethod
    def _coerce_priority(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 100

    @staticmethod
    def _coerce_load_limit(value: int | None) -> int:
        if value is None:
            return DEFAULT_LOAD_CHARS
        try:
            coerced = int(value)
        except (TypeError, ValueError):
            return DEFAULT_LOAD_CHARS
        if coerced <= 0:
            return DEFAULT_LOAD_CHARS
        return min(coerced, MAX_LOAD_CHARS)

    @staticmethod
    def _truncate(text: str, limit: int) -> tuple[str, bool]:
        if len(text) <= limit:
            return text, False
        omitted = len(text) - limit
        return f"{text[:limit]}\n\n[TRUNCATED {omitted} CHARS]", True

    def _relative_path(self, path: Path) -> str:
        resolved = path.expanduser().resolve()
        try:
            return str(resolved.relative_to(self.project_root))
        except ValueError:
            return str(resolved)

    @staticmethod
    def _apply_limit(records: list[SkillRecord], limit: int | None) -> list[SkillRecord]:
        if limit is None:
            return records
        try:
            effective_limit = max(1, int(limit))
        except (TypeError, ValueError):
            effective_limit = len(records)
        return records[:effective_limit]

    def _log(self, event: str, payload: dict[str, Any]) -> None:
        record = {
            "timestamp": self._timestamp(),
            "event": event,
            "payload": payload,
        }
        self._append_jsonl(self.log_path, record)
        if self.event_logger is not None:
            try:
                self.event_logger(event, payload)
            except Exception:
                pass

    @staticmethod
    def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()


def recommend_skills_for_challenge(
    challenge: dict[str, Any],
    available_slugs: Iterable[str] | None = None,
) -> list[str]:
    """Recommend likely useful skills from zone, metadata, and dynamic signal heuristics."""

    if not isinstance(challenge, dict):
        return []

    available = {slug.strip() for slug in (available_slugs or []) if str(slug).strip()}
    recommendations: list[str] = []
    stage_number = _extract_stage_number(challenge)
    if stage_number in ZONE_SKILL_PRIORITIES:
        recommendations.extend(ZONE_SKILL_PRIORITIES[stage_number])

    haystack = " ".join(_flatten_challenge_strings(challenge)).lower()
    for keywords, skills in SKILL_KEYWORD_RULES:
        if any(keyword in haystack for keyword in keywords):
            recommendations.extend(skills)
    for keywords, skills in DYNAMIC_SKILL_SIGNAL_RULES:
        if any(keyword in haystack for keyword in keywords):
            recommendations.extend(skills)

    deduped: list[str] = []
    for slug in recommendations:
        normalized = str(slug).strip()
        if not normalized or normalized in deduped:
            continue
        if available and normalized not in available:
            continue
        deduped.append(normalized)
    return deduped


def _flatten_challenge_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for nested_value in value.values():
            values.extend(_flatten_challenge_strings(nested_value))
        return values
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for nested_value in value:
            values.extend(_flatten_challenge_strings(nested_value))
        return values
    text = str(value).strip()
    return [text] if text else []


def _extract_stage_number(challenge: dict[str, Any]) -> int | None:
    stage_text = " ".join(
        _flatten_challenge_strings(
            {
                "stage": challenge.get("stage"),
                "zone": challenge.get("zone"),
                "track": challenge.get("track"),
                "level": challenge.get("level"),
                "title": challenge.get("title"),
                "description": challenge.get("description"),
            }
        )
    ).lower()
    if not stage_text:
        return None
    demo_match = re.search(r"\bdemo\s*([1-4])\b|\bdemo([1-4])\b", stage_text)
    if demo_match is not None:
        token = demo_match.group(1) or demo_match.group(2)
        if token is not None:
            return int(token)
    if "第一赛区" in stage_text or "识器·明理" in stage_text or re.search(r"\b(zone|stage|track|level)\s*[-_ ]?1\b", stage_text):
        return 1
    if "第二赛区" in stage_text or "洞见·虚实" in stage_text or re.search(r"\b(zone|stage|track|level)\s*[-_ ]?2\b", stage_text):
        return 2
    if "第三赛区" in stage_text or "执刃·循迹" in stage_text or re.search(r"\b(zone|stage|track|level)\s*[-_ ]?3\b", stage_text):
        return 3
    if "第四赛区" in stage_text or "铸剑·止戈" in stage_text or re.search(r"\b(zone|stage|track|level)\s*[-_ ]?4\b", stage_text):
        return 4
    chinese_match = re.search(r"第\s*([一二三四1234])\s*(?:赛区|阶段|关卡)", stage_text)
    if chinese_match is None:
        return None
    token = chinese_match.group(1)
    if token == "一":
        return 1
    if token == "二":
        return 2
    if token == "三":
        return 3
    if token == "四":
        return 4
    return int(token)
