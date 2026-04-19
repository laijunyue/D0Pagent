from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from typing import Any


class ChallengePlatformClient:
    """Thin MCP client for the official hackathon challenge platform.

    NOTE: The MCP server sometimes returns *successful* tool-call envelopes whose
    textual payload starts with "Error calling tool ..." instead of raising an
    exception. Historically we treated those as normal `raw_text` responses.
    That made callers believe start/stop succeeded and could lead to repeated
    start/stop loops (e.g. stop while the platform is still switching, then
    start again immediately).

    This client now detects those tool-error strings, raises an exception, and
    lets the built-in retry logic handle transient "starting/stopping" windows.
    """

    _throttle_lock = threading.Lock()
    _last_call_started_at = 0.0
    _lifecycle_lock = threading.Lock()

    _TOOL_ERROR_RE = re.compile(r"^Error calling tool ['\"]?(?P<tool>[^'\"]+)['\"]?:\s*(?P<msg>.+)$")

    def __init__(
        self,
        *,
        server_host: str | None = None,
        mcp_url: str | None = None,
        agent_token: str | None = None,
        min_interval: float = 0.4,
        max_retries: int = 3,
        retry_backoff: float = 1.5,
        request_timeout: float | None = None,
        sse_read_timeout: float | None = None,
        tool_timeout: float | None = None,
    ) -> None:
        resolved_server_host = self._clean_text(server_host) or self._clean_text(
            os.getenv("PENTEST_MCP_SERVER_HOST")
        )
        resolved_mcp_url = self._clean_text(mcp_url) or self._clean_text(os.getenv("PENTEST_MCP_URL"))
        resolved_agent_token = self._clean_text(agent_token) or self._clean_text(os.getenv("PENTEST_AGENT_TOKEN"))

        self.server_host = resolved_server_host
        self.mcp_url = self._resolve_mcp_url(resolved_mcp_url, resolved_server_host)
        self.agent_token = resolved_agent_token
        self.min_interval = max(float(min_interval), 0.0)
        self.max_retries = max(int(max_retries), 0)
        self.retry_backoff = max(float(retry_backoff), 1.0)
        self.request_timeout = self._resolve_timeout(
            explicit_value=request_timeout,
            env_name="PENTEST_MCP_REQUEST_TIMEOUT",
            default=15.0,
        )
        self.sse_read_timeout = self._resolve_timeout(
            explicit_value=sse_read_timeout,
            env_name="PENTEST_MCP_SSE_READ_TIMEOUT",
            default=max(self.request_timeout, 30.0),
        )
        self.tool_timeout = self._resolve_timeout(
            explicit_value=tool_timeout,
            env_name="PENTEST_MCP_TOOL_TIMEOUT",
            default=max(self.sse_read_timeout, self.request_timeout, 30.0),
        )

    def ensure_configured(self) -> None:
        """Validate required environment-backed configuration."""

        missing: list[str] = []
        if not self.mcp_url:
            missing.append("PENTEST_MCP_URL or PENTEST_MCP_SERVER_HOST")
        if not self.agent_token:
            missing.append("PENTEST_AGENT_TOKEN")
        if missing:
            raise RuntimeError(
                "Challenge platform configuration is incomplete. Missing: "
                + ", ".join(missing)
                + "."
            )

    def list_challenges(self) -> dict[str, Any]:
        """Fetch the currently visible challenge list."""

        return self._call_tool("list_challenges", {})

    def start_challenge(self, code: str) -> dict[str, Any]:
        """Start a challenge instance and return platform metadata."""

        return self._call_tool("start_challenge", {"code": code})

    def stop_challenge(self, code: str) -> dict[str, Any]:
        """Stop a running challenge instance."""

        return self._call_tool("stop_challenge", {"code": code})

    def submit_flag(self, code: str, flag: str) -> dict[str, Any]:
        """Submit one candidate flag for a challenge."""

        return self._call_tool("submit_flag", {"code": code, "flag": flag})

    def view_hint(self, code: str) -> dict[str, Any]:
        """Fetch hint content for a challenge."""

        return self._call_tool("view_hint", {"code": code})

    def is_challenge_fully_solved(self, challenge_dict: dict[str, Any]) -> bool:
        """Return True when the platform indicates all flags were obtained."""

        if not isinstance(challenge_dict, dict):
            return False

        flag_got_count = self._as_int(challenge_dict.get("flag_got_count"))
        flag_count = self._as_int(challenge_dict.get("flag_count"))
        if flag_got_count is not None and flag_count is not None:
            return flag_count > 0 and flag_got_count >= flag_count

        if challenge_dict.get("solved") is True or challenge_dict.get("completed") is True:
            return True

        status = str(challenge_dict.get("status", "")).strip().lower()
        return status in {"solved", "completed", "finished"}

    def find_challenge(self, challenges_payload: dict[str, Any], code: str) -> dict[str, Any] | None:
        """Find one challenge entry by code from a list_challenges payload."""

        if not code:
            return None

        for challenge in self.extract_challenges(challenges_payload):
            if str(challenge.get("code", "")).strip() == code.strip():
                return challenge
        return None

    @staticmethod
    def extract_challenges(challenges_payload: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Extract the challenge list from a platform response."""

        if isinstance(challenges_payload, dict):
            raw_challenges = challenges_payload.get("challenges")
            if isinstance(raw_challenges, list):
                return [item for item in raw_challenges if isinstance(item, dict)]
        return []

    def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.ensure_configured()

        lifecycle_managed_tools = {"start_challenge", "stop_challenge", "view_hint", "submit_flag"}
        call_lock = self.__class__._lifecycle_lock if tool_name in lifecycle_managed_tools else None
        if call_lock is None:
            return self._call_tool_unlocked(tool_name, arguments)
        with call_lock:
            return self._call_tool_unlocked(tool_name, arguments)

    def _call_tool_unlocked(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        last_message = f"Unknown error calling challenge platform tool '{tool_name}'."
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                payload = asyncio.run(self._call_tool_with_timeout(tool_name, arguments))
                # Some MCP servers return textual "Error calling tool ..." payloads
                # instead of throwing. Treat them as real errors so we can retry.
                self._raise_if_tool_error_payload(tool_name, payload)
                return payload
            except Exception as exc:
                last_message = self._exception_message(exc)
                if not self._should_retry(last_message, attempt):
                    raise RuntimeError(self._format_tool_error(tool_name, last_message)) from exc
                time.sleep(self._retry_delay(attempt))

        raise RuntimeError(self._format_tool_error(tool_name, last_message))

    async def _call_tool_with_timeout(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(
                self._call_tool_async(tool_name, arguments),
                timeout=self.tool_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(f"challenge platform call timed out after {self.tool_timeout:.1f}s") from exc

    async def _call_tool_async(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError as exc:
            raise RuntimeError(
                "The `mcp` package is required for challenge platform integration. "
                "Install dependencies with `pip install -r requirements.txt`."
            ) from exc

        headers = {"Authorization": f"Bearer {self.agent_token}"}
        async with streamablehttp_client(
            self.mcp_url,
            headers=headers,
            timeout=self.request_timeout,
            sse_read_timeout=self.sse_read_timeout,
        ) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=self.request_timeout)
                result = await asyncio.wait_for(
                    session.call_tool(tool_name, arguments=arguments),
                    timeout=self.tool_timeout,
                )
        return self._parse_tool_result(result)

    def _throttle(self) -> None:
        with self.__class__._throttle_lock:
            now = time.monotonic()
            wait_time = self.min_interval - (now - self.__class__._last_call_started_at)
            if wait_time > 0:
                time.sleep(wait_time)
                now = time.monotonic()
            self.__class__._last_call_started_at = now

    def _retry_delay(self, attempt: int) -> float:
        return self.min_interval * (self.retry_backoff**attempt)

    def _should_retry(self, message: str, attempt: int) -> bool:
        if attempt >= self.max_retries:
            return False
        if self._is_business_error(message):
            return False
        return self._is_retryable_error(message)

    @classmethod
    def _raise_if_tool_error_payload(cls, tool_name: str, payload: dict[str, Any]) -> None:
        # Tool-call errors often show up as a plain string in raw_text.
        raw_text = payload.get("raw_text") if isinstance(payload, dict) else None
        if not raw_text or not isinstance(raw_text, str):
            return
        text = raw_text.strip()
        if not text:
            return
        match = cls._TOOL_ERROR_RE.match(text)
        if match:
            # Prefer the embedded message after the tool prefix.
            msg = match.group("msg").strip()
            raise RuntimeError(msg or text)
        # A few MCP servers return traceback-like strings; detect the common prefix.
        if text.lower().startswith("traceback") and "error calling tool" in text.lower():
            raise RuntimeError(text)

        # Some errors are surfaced without the exact prefix, but still contain
        # the key phrase.
        if "error calling tool" in text.lower():
            raise RuntimeError(text)

        # Optional: handle common platform transitional responses that arrive as raw_text.
        # We do *not* raise on arbitrary raw_text; only on the known tool-error envelope.

    @staticmethod
    def _is_retryable_error(message: str) -> bool:
        normalized = message.lower()
        retryable_patterns = (
            # Rate limiting
            "请求频率超出限制",
            "每秒最多调用3次",
            "rate limit",
            "too many requests",
            "http 429",
            " 429",
            # Transient platform switching windows (important for start/stop)
            "已有实例正在启动或停止中",
            "实例正在启动",
            "实例正在停止",
            "答题开关切换中",
            "开关切换中",
            "请稍后重试",
            "请稍后再试",
            "稍后重试",
            "稍后再试",
            "switching",
            # Generic transient outages
            "temporarily unavailable",
            "temporary failure",
            "service unavailable",
            "gateway timeout",
            "bad gateway",
            "http 500",
            "http 502",
            "http 503",
            "http 504",
            " 500",
            " 502",
            " 503",
            " 504",
            "timed out",
            "timeout",
            "connection reset",
            "connection refused",
            "connection aborted",
            "broken pipe",
            "server disconnected",
            "network is unreachable",
            "name or service not known",
            "temporary network",
        )
        return any(pattern in normalized for pattern in retryable_patterns)

    @staticmethod
    def _is_business_error(message: str) -> bool:
        normalized = message.lower()
        business_patterns = (
            "赛题不存在",
            "尚未解锁",
            "无效的token",
            "缺少认证token",
            "队伍已禁用",
            "比赛尚未开始",
            "比赛已暂停",
            "实例未运行",
            "最多同时运行",
            "not unlocked",
            "challenge does not exist",
            "missing token",
            "invalid token",
            "forbidden",
            "unauthorized",
            "permission denied",
        )
        return any(pattern in normalized for pattern in business_patterns)

    def _parse_tool_result(self, result: Any) -> dict[str, Any]:
        text_parts: list[str] = []
        content_items = getattr(result, "content", None) or []
        for content in content_items:
            text_value = getattr(content, "text", None)
            if text_value is None and isinstance(content, dict):
                text_value = content.get("text")
            if text_value is not None:
                text_parts.append(str(text_value))

        if text_parts:
            first_text = text_parts[0].strip()
            if first_text:
                try:
                    parsed = json.loads(first_text)
                except json.JSONDecodeError:
                    return {"raw_text": first_text}
                if isinstance(parsed, dict):
                    return parsed
                return {"data": parsed}

        if isinstance(result, dict):
            return result

        if hasattr(result, "model_dump"):
            dumped = result.model_dump()
            if isinstance(dumped, dict):
                return dumped

        return {"raw_text": str(result)}

    @staticmethod
    def _format_tool_error(tool_name: str, message: str) -> str:
        return f"Challenge platform tool '{tool_name}' failed: {message}"

    @staticmethod
    def _exception_message(exc: Exception) -> str:
        message = str(exc).strip()
        return message or exc.__class__.__name__

    @staticmethod
    def _resolve_timeout(*, explicit_value: float | None, env_name: str, default: float) -> float:
        if explicit_value is not None:
            raw_value = explicit_value
        else:
            raw_value = os.getenv(env_name)
        if raw_value is None or str(raw_value).strip() == "":
            return float(default)
        try:
            resolved = float(str(raw_value).strip())
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid timeout value for {env_name}: {raw_value!r}") from exc
        if resolved <= 0:
            raise RuntimeError(f"Timeout value for {env_name} must be positive, got {resolved}.")
        return resolved

    @staticmethod
    def _resolve_mcp_url(mcp_url: str | None, server_host: str | None) -> str | None:
        if mcp_url:
            normalized = ChallengePlatformClient._ensure_http_scheme(mcp_url.rstrip("/"))
            return normalized

        if not server_host:
            return None

        normalized_host = ChallengePlatformClient._ensure_http_scheme(server_host.strip().rstrip("/"))
        if normalized_host.endswith("/mcp"):
            return normalized_host
        return f"{normalized_host}/mcp"

    @staticmethod
    def _ensure_http_scheme(value: str) -> str:
        normalized = value.strip()
        if normalized.startswith("http://") or normalized.startswith("https://"):
            return normalized
        return f"http://{normalized}"

    @staticmethod
    def _clean_text(value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None
