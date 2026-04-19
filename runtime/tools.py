from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import hashlib
import json
import os
from queue import Empty, Queue
import re
import shlex
import threading
import time
import traceback

from .cve_knowledge import CVEKnowledgeBase
from .challenge_platform import ChallengePlatformClient
from .pentest_helpers import (
    build_target_profile as build_target_profile_from_text,
    extract_secrets_and_flags as extract_artifacts_from_text,
    load_json_lines,
    truncate_lines,
)
from .skills import SkillManager

flag_PATTERN = re.compile(r"flag\{[^}\r\n]+\}", re.IGNORECASE)
MAX_TOOL_RESULT_CHARS = 16_000
MAX_RESULT_PREVIEW_CHARS = 4_000
TERMINAL_HELPER_PREFIX = "__PENTEST_TOOL_RESULT__"
TOOLSET_WRAPPER_PREFIX = "__TOOLSET_WRAPPED_RESULT__"
DEFAULT_FFUF_WORDLIST = "/home/ubuntu/Public/dicc.txt"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FLAG_CONFIDENCE_HIGH = "high"
FLAG_CONFIDENCE_MEDIUM = "medium"
FLAG_CONFIDENCE_LOW = "low"
FLAG_SOURCE_OBSERVED_TARGET_RESPONSE = "observed_target_response"
FLAG_SOURCE_OBSERVED_PLATFORM_RESPONSE = "observed_platform_response"
FLAG_SOURCE_OBSERVED_HINT = "observed_hint"
FLAG_SOURCE_OBSERVED_TOOL_OUTPUT = "observed_tool_output"
FLAG_SOURCE_SELF_GENERATED_PAYLOAD = "self_generated_payload"
FLAG_SOURCE_SELF_GENERATED_CODE_LITERAL = "self_generated_code_literal"
FLAG_SOURCE_PROMPT_LITERAL = "prompt_literal"
FLAG_SOURCE_EXECUTION_RECORD_CODE = "execution_record_code"
FLAG_SOURCE_SUBMITTED_FLAG_ECHO = "submitted_flag_echo"
FLAG_SOURCE_UNKNOWN = "unknown"
SELF_GENERATED_FLAG_CONTEXT_RE = re.compile(
    r"(?i)\b(trying|testing|guess|candidate|potential|maybe|submit|submitting|payload|constructed|generated|example)\b"
)
SELF_GENERATED_FLAG_PREFIX_RE = re.compile(r"(?i)^\s*(?:trying|testing|candidate|potential|submit)\s*[:=-]\s*")
SUBMITTED_FLAG_ECHO_RE = re.compile(r"(?i)\bsubmit(?:ted|ting)?\b.*\bflag\b")
OBSERVED_RESPONSE_HINT_RE = re.compile(
    r"(?i)(http/|response|body|html|json|swagger|openapi|redoc|unauthorized|forbidden|admin only|not allowed)"
)


def extract_flag(text: str) -> str | None:
    match = flag_PATTERN.search(text)
    return match.group(0) if match else None


def truncate_text(text: str, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n\n[TRUNCATED {omitted} CHARS]"


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def python_literal(value: Any) -> str:
    return repr(value)


@dataclass(slots=True)
class ToolInvocationResult:
    name: str
    content: str
    solved: bool = False
    flag: str | None = None
    progress: bool = False
    progress_detail: str | None = None
    candidate_flags: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class CandidateFlagObservation:
    value: str
    source_type: str
    confidence: str
    observed_in_step: int
    evidence_excerpt: str
    auto_submittable: bool


class CompatibleToolRegistry:
    def __init__(
        self,
        executor: Any,
        workspace: Path,
        event_logger: Callable[[str, Any], None],
        msf_client: Any | None = None,
        skill_manager: SkillManager | None = None,
        challenge_client: ChallengePlatformClient | None = None,
    ) -> None:
        self.executor = executor
        self.workspace = workspace
        self.event_logger = event_logger
        self.msf_client = msf_client
        self.skill_manager = skill_manager
        self.challenge_client = challenge_client
        self.allow_challenge_lifecycle_tools = self._resolve_challenge_lifecycle_tool_policy(workspace)
        self.cve_knowledge = CVEKnowledgeBase(
            root=PROJECT_ROOT / "knowledge" / "cves",
            event_logger=self.event_logger,
        )
        self.todo_path = workspace / "todo.md"
        self.state_path = workspace / "agent_state.json"
        self.subtask_path = workspace / "subtasks.jsonl"
        self.execution_dir = workspace / "executions"
        self.execution_dir.mkdir(parents=True, exist_ok=True)
        self.execution_counter = 0
        self.repeated_fingerprints: dict[str, int] = {}


    @staticmethod
    def _resolve_challenge_lifecycle_tool_policy(workspace: Path) -> bool:
        env_value = (os.getenv("CTF_ALLOW_CHALLENGE_LIFECYCLE_TOOLS") or "").strip().lower()
        if env_value in {"1", "true", "yes", "on"}:
            return True
        if env_value in {"0", "false", "no", "off"}:
            return False

        # In orchestrated hackathon runs, lifecycle is owned by the orchestrator.
        # Exposing start/stop/view_hint to the runtime agent causes platform thrashing
        # and visible start/view_hint/stop loops. Outside hackathon workspaces we keep
        # the legacy behavior by default.
        return "hackathon" not in {part.lower() for part in workspace.parts}

    def _challenge_lifecycle_blocked_result(self, tool_name: str) -> ToolInvocationResult:
        content = (
            f"[SYSTEM] Tool '{tool_name}' is disabled inside orchestrated hackathon attempts. "
            "The orchestrator already manages challenge instance lifecycle and hint policy. "
            "Do not start, stop, or reveal hints from inside the runtime agent. "
            "Continue solving the currently assigned challenge and only use mcp__challenge__submit_flag for real high-confidence flags."
        )
        return ToolInvocationResult(name=tool_name, content=content)

    def _resolve_tool_hard_timeout(self, name: str, arguments: dict[str, Any]) -> float:
        env_value = (os.getenv("CTF_TOOL_HARD_TIMEOUT_SECONDS") or "").strip()
        if env_value:
            try:
                resolved = float(env_value)
            except ValueError:
                resolved = 0.0
            if resolved > 0:
                return resolved

        timeout_candidates: list[float] = []
        for key in ("timeout", "timeout_hint"):
            raw_value = arguments.get(key)
            if raw_value is None:
                continue
            try:
                candidate = float(raw_value)
            except (TypeError, ValueError):
                continue
            if candidate > 0:
                timeout_candidates.append(candidate)

        base_timeout = max(timeout_candidates, default=0.0)

        if name == "mcp__sandbox__execute_code":
            return max(base_timeout + 25.0, 45.0)
        if name.startswith("mcp__challenge__"):
            platform_timeout = getattr(self.challenge_client, "tool_timeout", None)
            try:
                platform_timeout_value = float(platform_timeout) if platform_timeout is not None else 0.0
            except (TypeError, ValueError):
                platform_timeout_value = 0.0
            return max(platform_timeout_value + 15.0, base_timeout + 20.0, 45.0)
        if name.startswith("mcp__msf__"):
            return max(base_timeout + 45.0, 180.0)
        if name.startswith("run_") or name.startswith("toolset."):
            return max(base_timeout + 30.0, 90.0)
        return max(base_timeout + 15.0, 30.0)

    @staticmethod
    def _tool_timeout_message(*, tool_name: str, timeout_seconds: float) -> str:
        return (
            f"[SYSTEM] Tool '{tool_name}' exceeded the watchdog timeout of {timeout_seconds:.1f} seconds. "
            "Treat this call as failed, avoid repeating the exact same request immediately, and either break the task "
            "into a smaller step or use a different tool/path."
        )

    def _invoke_with_timeout(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        handler: Callable[[dict[str, Any], int], ToolInvocationResult],
    ) -> ToolInvocationResult:
        timeout_seconds = self._resolve_tool_hard_timeout(tool_name, arguments)
        result_queue: Queue[tuple[str, Any]] = Queue(maxsize=1)

        def worker() -> None:
            try:
                result_queue.put(("ok", handler(arguments, step)))
            except Exception as exc:
                result_queue.put(
                    (
                        "error",
                        {
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                    )
                )

        thread = threading.Thread(
            target=worker,
            name=f"tool-watchdog-{self._safe_name(tool_name)}-{step}",
            daemon=True,
        )
        started_at = time.monotonic()
        thread.start()
        thread.join(timeout_seconds)
        if thread.is_alive():
            message = self._tool_timeout_message(tool_name=tool_name, timeout_seconds=timeout_seconds)
            self.event_logger(
                "tool_error",
                {
                    "tool": tool_name,
                    "arguments": arguments,
                    "message": message,
                    "step": step,
                    "watchdog_timeout_seconds": timeout_seconds,
                    "duration_seconds": round(time.monotonic() - started_at, 3),
                },
            )
            return ToolInvocationResult(name=tool_name, content=message)

        try:
            status, payload = result_queue.get_nowait()
        except Empty as exc:
            raise RuntimeError(f"Tool '{tool_name}' worker finished without returning a result.") from exc

        if status == "error":
            message = str(payload.get("message") or f"tool '{tool_name}' failed")
            worker_traceback = str(payload.get("traceback") or "").strip()
            if worker_traceback:
                raise RuntimeError(f"{message}\n{worker_traceback}")
            raise RuntimeError(message)
        return payload

    @staticmethod
    def _execute_code_wall_timeout(timeout: int) -> float:
        return max(float(timeout) + 10.0, 15.0)

    def _close_executor_session_with_timeout(
        self,
        session_name: str,
        *,
        timeout_seconds: float = 5.0,
    ) -> tuple[bool | None, str | None]:
        close_session = getattr(self.executor, "close_session", None)
        if not callable(close_session):
            return None, "executor does not expose close_session"

        result: dict[str, Any] = {"closed": None, "error": None}

        def worker() -> None:
            try:
                result["closed"] = bool(close_session(session_name))
            except Exception as exc:
                result["error"] = str(exc)

        thread = threading.Thread(
            target=worker,
            name=f"close-session-{session_name}",
            daemon=True,
        )
        thread.start()
        thread.join(timeout_seconds)
        if thread.is_alive():
            return None, (
                f"close_session({session_name!r}) did not finish within {timeout_seconds:.1f} seconds"
            )
        if result["error"]:
            return None, str(result["error"])
        return bool(result["closed"]), None

    def tool_definitions(self) -> list[dict[str, Any]]:
        definitions = [
            {
                "type": "function",
                "function": {
                    "name": "mcp__sandbox__execute_code",
                    "description": (
                        "Execute SMALL, FOCUSED Python code in a stateful Jupyter session. "
                        "Use this as the primary meta-tool and call toolset from inside the code."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_name": {
                                "type": "string",
                                "description": "Stable session name. Reusing the same name preserves imports and variables.",
                            },
                            "code": {
                                "type": "string",
                                "description": "Python code snippet to execute. Keep it under roughly 20-30 lines when possible.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Maximum seconds to wait before interrupting the kernel.",
                                "minimum": 1,
                            },
                        },
                        "required": ["session_name", "code"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__sandbox__list_sessions",
                    "description": "List active PythonExecutor session names.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__sandbox__close_session",
                    "description": "Close a PythonExecutor session and release its kernel.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_name": {
                                "type": "string",
                                "description": "Exact session name to close.",
                            }
                        },
                        "required": ["session_name"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "Task",
                    "description": (
                        "Claude Code compatibility shim. Record a subtask locally so calls to Task do not fail."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "prompt": {"type": "string"},
                            "context": {"type": "string"},
                            "goal": {"type": "string"},
                        },
                        "additionalProperties": True,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "EnterPlanMode",
                    "description": "Claude Code compatibility shim. Mark the local agent state as being in planning mode.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "reason": {"type": "string"},
                        },
                        "additionalProperties": True,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "ExitPlanMode",
                    "description": "Claude Code compatibility shim. Mark the local agent state as no longer being in planning mode.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                        },
                        "additionalProperties": True,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "TodoWrite",
                    "description": "Claude Code compatibility shim. Write or append a todo list in the workspace.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "items": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "content": {"type": "string"},
                                        "status": {"type": "string"},
                                        "note": {"type": "string"},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                            "content": {"type": "string"},
                            "append": {"type": "boolean"},
                        },
                        "additionalProperties": True,
                    },
                },
            },
        ]
        definitions.extend(self._toolset_runtime_tool_definitions())
        definitions.extend(self._pentest_tool_definitions())
        if self.skill_manager is not None:
            definitions.extend(self._skill_tool_definitions())
        if self.has_msf_tools():
            definitions.extend(self._msf_tool_definitions())
        if self.has_challenge_tools():
            definitions.extend(self._challenge_tool_definitions())
        return definitions

    def invoke(self, name: str, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        handlers: dict[str, Callable[[dict[str, Any], int], ToolInvocationResult]] = {
            "mcp__sandbox__execute_code": self._execute_code,
            "mcp__sandbox__list_sessions": self._list_sessions,
            "mcp__sandbox__close_session": self._close_session,
            "Task": self._task,
            "EnterPlanMode": self._enter_plan_mode,
            "ExitPlanMode": self._exit_plan_mode,
            "TodoWrite": self._todo_write,
            "toolset.browser": self._toolset_browser,
            "toolset.browser.get_context": self._toolset_browser_get_context,
            "toolset.terminal.list_sessions": self._toolset_terminal_list_sessions,
            "toolset.terminal.kill_session": self._toolset_terminal_kill_session,
            "toolset.terminal.new_session": self._toolset_terminal_new_session,
            "toolset.terminal.get_output": self._toolset_terminal_get_output,
            "toolset.terminal.send_keys": self._toolset_terminal_send_keys,
            "run_httpx_scan": self._run_httpx_scan,
            "run_katana_crawl": self._run_katana_crawl,
            "run_ffuf_scan": self._run_ffuf_scan,
            "run_nuclei_scan": self._run_nuclei_scan,
            "run_sqlmap_scan": self._run_sqlmap_scan,
            "extract_secrets_and_flags": self._extract_secrets_and_flags_tool,
            "build_target_profile": self._build_target_profile_tool,
            "SearchCVEKnowledge": self._search_cve_knowledge,
            "LoadCVEKnowledge": self._load_cve_knowledge,
            "ListSkills": self._list_skills,
            "SearchSkills": self._search_skills,
            "LoadSkill": self._load_skill,
            "mcp__msf__get_status": self._msf_get_status,
            "mcp__msf__execute_command": self._msf_execute_command,
            "mcp__msf__search_modules": self._msf_search_modules,
            "mcp__msf__workspace": self._msf_workspace,
            "mcp__msf__db_query": self._msf_db_query,
            "mcp__msf__session": self._msf_session,
            "mcp__msf__module": self._msf_module,
            "mcp__challenge__list_challenges": self._challenge_list_challenges,
            "mcp__challenge__start_challenge": self._challenge_start_challenge,
            "mcp__challenge__stop_challenge": self._challenge_stop_challenge,
            "mcp__challenge__submit_flag": self._challenge_submit_flag,
            "mcp__challenge__view_hint": self._challenge_view_hint,
        }
        handler = handlers.get(name)
        if handler is None:
            content = f"Unknown tool '{name}'. Available tools: {', '.join(sorted(handlers))}"
            self.event_logger("tool_error", {"tool": name, "arguments": arguments, "message": content, "step": step})
            return ToolInvocationResult(name=name, content=content)

        try:
            return self._invoke_with_timeout(
                tool_name=name,
                arguments=arguments,
                step=step,
                handler=handler,
            )
        except Exception as exc:
            message = str(exc)
            self.event_logger(
                "tool_error",
                {
                    "tool": name,
                    "arguments": arguments,
                    "message": message,
                    "step": step,
                },
            )
            return ToolInvocationResult(name=name, content=message)

    def _execute_code(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        session_name = str(arguments.get("session_name", "default"))
        code = str(arguments.get("code", ""))
        timeout = int(arguments.get("timeout") or 10)
        if not code.strip():
            content = "execute_code requires a non-empty 'code' string."
            return ToolInvocationResult(name="mcp__sandbox__execute_code", content=content)

        fingerprint = hashlib.sha256(
            json.dumps(
                {"session_name": session_name, "code": code, "timeout": timeout},
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        repeated_count = self.repeated_fingerprints.get(fingerprint, 0) + 1
        self.repeated_fingerprints[fingerprint] = repeated_count

        outputs = self._execute_code_with_guard(session_name=session_name, code=code, timeout=timeout, step=step)
        self.execution_counter += 1
        record = {
            "step": step,
            "tool": "mcp__sandbox__execute_code",
            "session_name": session_name,
            "timeout": timeout,
            "code": code,
            "outputs": outputs,
            "repeated_count": repeated_count,
        }
        execution_path = self.execution_dir / f"{self.execution_counter:04d}_{self._safe_name(session_name)}.json"
        execution_path.write_text(json_dumps(record), encoding="utf-8")

        result_payload: dict[str, Any] = {
            "session_name": session_name,
            "timeout": timeout,
            "outputs": outputs,
            "execution_record": str(execution_path),
        }
        if repeated_count > 3:
            result_payload["warning"] = (
                f"This exact execute_code payload has been used {repeated_count} times. "
                "If progress stalls, split the code further or adjust the timeout."
            )

        candidate_flags = self._serialize_candidate_flags(
            self._extract_candidate_flags_from_execution_outputs(outputs=outputs, code=code, step=step)
        )
        if candidate_flags:
            result_payload["candidate_flags"] = candidate_flags
            result_payload["auto_submittable_flags"] = [
                item["value"] for item in candidate_flags if bool(item.get("auto_submittable"))
            ]
        result_text = truncate_text(json_dumps(result_payload))
        flag = next(
            (
                item["value"]
                for item in candidate_flags
                if item.get("confidence") == FLAG_CONFIDENCE_HIGH and bool(item.get("auto_submittable"))
            ),
            None,
        )
        self.event_logger(
            "tool_call",
            {
                "tool": "mcp__sandbox__execute_code",
                "arguments": {"session_name": session_name, "timeout": timeout, "code": code},
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
                "flag": flag,
                "candidate_flags": candidate_flags,
            },
        )
        solved = flag is not None and not self.has_challenge_tools()
        return ToolInvocationResult(
            name="mcp__sandbox__execute_code",
            content=result_text,
            solved=solved,
            flag=flag,
            candidate_flags=candidate_flags,
        )

    def _execute_code_with_guard(
        self,
        *,
        session_name: str,
        code: str,
        timeout: int,
        step: int,
        tool_name: str = "mcp__sandbox__execute_code",
        log_arguments: dict[str, Any] | None = None,
        reset_session_on_timeout: bool = True,
    ) -> list[dict[str, Any]]:
        result_queue: Queue[tuple[str, Any]] = Queue(maxsize=1)
        safe_arguments = log_arguments or {"session_name": session_name, "timeout": timeout, "code": code}

        def worker() -> None:
            try:
                outputs = self.executor.execute_code(session_name=session_name, code=code, timeout=timeout)
            except Exception as exc:
                result_queue.put(
                    (
                        "error",
                        {
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                    )
                )
                return
            result_queue.put(("ok", outputs))

        thread = threading.Thread(
            target=worker,
            name=f"execute-code-{session_name}",
            daemon=True,
        )
        thread.start()

        wall_timeout = self._execute_code_wall_timeout(timeout)
        thread.join(wall_timeout)
        if thread.is_alive():
            reset_message = (
                f"[SYSTEM] execute_code exceeded wall timeout after {wall_timeout:.1f} seconds "
                f"(requested tool timeout: {timeout}s)."
            )
            if reset_session_on_timeout:
                closed, close_error = self._close_executor_session_with_timeout(session_name)
                if close_error:
                    reset_message += (
                        " Session reset was attempted but did not finish cleanly: "
                        f"{close_error}."
                    )
                elif closed:
                    reset_message += " The Python session was reset to unblock subsequent steps."
                else:
                    reset_message += " Session reset was attempted, but the executor reported it was already closed."

            self.event_logger(
                "tool_error",
                {
                    "tool": tool_name,
                    "arguments": safe_arguments,
                    "message": reset_message,
                    "step": step,
                },
            )
            return [
                {
                    "type": "display_data",
                    "data": {"text/plain": reset_message},
                }
            ]

        try:
            status, payload = result_queue.get_nowait()
        except Empty as exc:
            raise RuntimeError(f"{tool_name} worker finished without returning outputs.") from exc

        if status == "error":
            message = str(payload.get("message") or "unknown execute_code failure")
            worker_traceback = str(payload.get("traceback") or "").strip()
            if worker_traceback:
                raise RuntimeError(f"{tool_name} failed: {message}\n{worker_traceback}")
            raise RuntimeError(f"{tool_name} failed: {message}")

        return list(payload)

    def _extract_candidate_flags_from_execution_outputs(
        self,
        *,
        outputs: list[dict[str, Any]],
        code: str,
        step: int,
    ) -> list[CandidateFlagObservation]:
        code_literals = {match.group(0).lower() for match in flag_PATTERN.finditer(code)}
        observations: list[CandidateFlagObservation] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for excerpt in self._iter_execution_output_texts(outputs):
            for match in flag_PATTERN.finditer(excerpt):
                candidate = match.group(0)
                source_type, confidence = self._classify_flag_source(
                    flag_value=candidate,
                    evidence_excerpt=excerpt,
                    code_literals=code_literals,
                )
                observation = CandidateFlagObservation(
                    value=candidate,
                    source_type=source_type,
                    confidence=confidence,
                    observed_in_step=step,
                    evidence_excerpt=self._clip_excerpt(excerpt),
                    auto_submittable=self._should_auto_submit_candidate_flag(
                        value=candidate,
                        source_type=source_type,
                        confidence=confidence,
                    ),
                )
                key = (observation.value, observation.source_type, observation.evidence_excerpt)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                observations.append(observation)
        return observations

    def _iter_execution_output_texts(self, outputs: list[dict[str, Any]]) -> list[str]:
        snippets: list[str] = []
        for output in outputs:
            output_type = str(output.get("type", "")).strip().lower()
            if output_type == "stream":
                text = self._optional_text(output.get("text"))
                if text:
                    snippets.extend(self._split_output_snippets(text))
                continue
            if output_type == "error":
                traceback_lines = output.get("traceback") or []
                if isinstance(traceback_lines, list):
                    snippets.extend(self._split_output_snippets("\n".join(str(line) for line in traceback_lines)))
                    continue
                text = self._optional_text(output.get("evalue"))
                if text:
                    snippets.extend(self._split_output_snippets(text))
        return [snippet for snippet in snippets if snippet]

    def _split_output_snippets(self, text: str) -> list[str]:
        snippets: list[str] = []
        for raw_line in str(text).splitlines():
            line = raw_line.strip()
            if line:
                snippets.append(line)
        return snippets

    def _classify_flag_source(
        self,
        *,
        flag_value: str,
        evidence_excerpt: str,
        code_literals: set[str],
    ) -> tuple[str, str]:
        excerpt = str(evidence_excerpt or "").strip()
        lowered = excerpt.lower()

        if flag_value.lower() in code_literals:
            return FLAG_SOURCE_SELF_GENERATED_CODE_LITERAL, FLAG_CONFIDENCE_LOW
        if SELF_GENERATED_FLAG_PREFIX_RE.search(excerpt):
            return FLAG_SOURCE_SELF_GENERATED_PAYLOAD, FLAG_CONFIDENCE_LOW
        if SUBMITTED_FLAG_ECHO_RE.search(excerpt):
            return FLAG_SOURCE_SUBMITTED_FLAG_ECHO, FLAG_CONFIDENCE_LOW
        if SELF_GENERATED_FLAG_CONTEXT_RE.search(excerpt) and "response" not in lowered and "body" not in lowered:
            return FLAG_SOURCE_SELF_GENERATED_PAYLOAD, FLAG_CONFIDENCE_LOW
        if OBSERVED_RESPONSE_HINT_RE.search(excerpt):
            return FLAG_SOURCE_OBSERVED_TOOL_OUTPUT, FLAG_CONFIDENCE_HIGH
        return FLAG_SOURCE_OBSERVED_TOOL_OUTPUT, FLAG_CONFIDENCE_MEDIUM

    def _should_auto_submit_candidate_flag(
        self,
        *,
        value: str,
        source_type: str,
        confidence: str,
    ) -> bool:
        del value
        if confidence != FLAG_CONFIDENCE_HIGH:
            return False
        return source_type in {
            FLAG_SOURCE_OBSERVED_TARGET_RESPONSE,
            FLAG_SOURCE_OBSERVED_PLATFORM_RESPONSE,
            FLAG_SOURCE_OBSERVED_HINT,
            FLAG_SOURCE_OBSERVED_TOOL_OUTPUT,
        }

    def _serialize_candidate_flags(
        self,
        observations: list[CandidateFlagObservation],
    ) -> list[dict[str, Any]]:
        return [
            {
                "value": observation.value,
                "source_type": observation.source_type,
                "confidence": observation.confidence,
                "observed_in_step": observation.observed_in_step,
                "evidence_excerpt": observation.evidence_excerpt,
                "auto_submittable": observation.auto_submittable,
            }
            for observation in observations
        ]

    @staticmethod
    def _clip_excerpt(text: str, limit: int = 240) -> str:
        cleaned = str(text or "").strip()
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[:limit].rstrip() + "...[truncated]"

    def _list_sessions(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        del arguments
        sessions = self.executor.list_sessions()
        content = json_dumps({"sessions": sessions})
        self.event_logger(
            "tool_call",
            {
                "tool": "mcp__sandbox__list_sessions",
                "arguments": {},
                "result_preview": content,
                "step": step,
            },
        )
        return ToolInvocationResult(name="mcp__sandbox__list_sessions", content=content)

    def _toolset_browser(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        url = self._optional_text(arguments.get("url"))
        timeout_ms = self._safe_positive_int(arguments.get("timeout_ms"), default=15_000) or 15_000
        session_name = self._optional_text(arguments.get("session_name")) or "browser_session"
        code_lines = [
            "import toolset",
            "",
            "context = await toolset.browser.get_context()",
            "page = context.pages[0] if context.pages else await context.new_page()",
        ]
        if url:
            code_lines.extend(
                [
                    f'await page.goto({json.dumps(url, ensure_ascii=False)}, timeout={timeout_ms}, wait_until="domcontentloaded")',
                    'print({"url": page.url, "title": await page.title()})',
                ]
            )
        else:
            code_lines.append('print({"pages": [page.url for page in context.pages]})')

        payload = {
            "success": True,
            "tool": "toolset.browser",
            "message": (
                "toolset.browser is available inside the PythonExecutor-backed toolset runtime. "
                "Use it through mcp__sandbox__execute_code so browser state, page objects, and async Playwright "
                "calls stay in the same Python session."
            ),
            "recommended_tool": "mcp__sandbox__execute_code",
            "recommended_session_name": session_name,
            "example_timeout": min(max(timeout_ms // 1000, 5), 60),
            "example_code": "\n".join(code_lines),
        }
        result_text = truncate_text(json_dumps(payload))
        self.event_logger(
            "tool_call",
            {
                "tool": "toolset.browser",
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
            },
        )
        return ToolInvocationResult(name="toolset.browser", content=result_text)

    def _toolset_browser_get_context(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        session_name = self._optional_text(arguments.get("session_name")) or "toolset_browser_runtime"
        timeout = max(20, self._safe_positive_int(arguments.get("timeout"), default=20) or 20)
        example_code = (
            'context = globals().get("_toolset_browser_context") or await toolset.browser.get_context()\n'
            'page = context.pages[0] if context.pages else await context.new_page()\n'
            'print({"pages": [page.url for page in context.pages]})'
        )
        code = f"""
import json

import toolset

_result_prefix = {json.dumps(TOOLSET_WRAPPER_PREFIX)}
payload = {{
    "success": False,
    "tool": "toolset.browser.get_context",
}}

try:
    context = await toolset.browser.get_context()
    globals()["_toolset_browser_context"] = context
    page_summaries = []
    for index, page in enumerate(getattr(context, "pages", []) or []):
        try:
            page_summaries.append({{"index": index, "url": page.url}})
        except Exception as exc:
            page_summaries.append({{"index": index, "error": str(exc)}})
    payload["success"] = True
    payload["result"] = {{
        "message": "Browser context initialized and stored in _toolset_browser_context. Reuse the returned session_name with mcp__sandbox__execute_code to continue browser operations.",
        "session_name": {python_literal(session_name)},
        "stored_variable": "_toolset_browser_context",
        "page_count": len(getattr(context, "pages", []) or []),
        "pages": page_summaries,
        "recommended_tool": "mcp__sandbox__execute_code",
        "example_code": {python_literal(example_code)},
    }}
except Exception as exc:
    payload["error"] = str(exc)
    payload["error_type"] = exc.__class__.__name__

print(_result_prefix + json.dumps(payload, ensure_ascii=False, default=str))
""".strip()
        return self._invoke_wrapped_toolset_executor_tool(
            tool_name="toolset.browser.get_context",
            arguments={"session_name": session_name, "timeout": timeout},
            code=code,
            step=step,
            timeout=timeout,
            session_name=session_name,
        )

    def _toolset_terminal_list_sessions(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        del arguments
        code = self._build_wrapped_toolset_code(
            tool_name="toolset.terminal.list_sessions",
            expression="toolset.terminal.list_sessions()",
        )
        return self._invoke_wrapped_toolset_executor_tool(
            tool_name="toolset.terminal.list_sessions",
            arguments={},
            code=code,
            step=step,
        )

    def _toolset_terminal_kill_session(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        session_id = self._safe_positive_int(arguments.get("session_id"), default=None)
        if session_id is None:
            return ToolInvocationResult(
                name="toolset.terminal.kill_session",
                content="toolset.terminal.kill_session requires a positive integer 'session_id'.",
            )
        code = self._build_wrapped_toolset_code(
            tool_name="toolset.terminal.kill_session",
            expression=f"toolset.terminal.kill_session(session_id={session_id})",
        )
        return self._invoke_wrapped_toolset_executor_tool(
            tool_name="toolset.terminal.kill_session",
            arguments={"session_id": session_id},
            code=code,
            step=step,
        )

    def _toolset_terminal_new_session(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        del arguments
        code = self._build_wrapped_toolset_code(
            tool_name="toolset.terminal.new_session",
            expression="toolset.terminal.new_session()",
        )
        return self._invoke_wrapped_toolset_executor_tool(
            tool_name="toolset.terminal.new_session",
            arguments={},
            code=code,
            step=step,
        )

    def _toolset_terminal_get_output(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        session_id = self._safe_positive_int(arguments.get("session_id"), default=None)
        if session_id is None:
            return ToolInvocationResult(
                name="toolset.terminal.get_output",
                content="toolset.terminal.get_output requires a positive integer 'session_id'.",
            )
        start = self._optional_text(arguments.get("start"))
        end = self._optional_text(arguments.get("end"))
        code = self._build_wrapped_toolset_code(
            tool_name="toolset.terminal.get_output",
            expression=(
                f"toolset.terminal.get_output(session_id={session_id}, "
                f"start={python_literal(start if start is not None else '')}, "
                f"end={json.dumps(end if end is not None else '', ensure_ascii=False)})"
            ),
        )
        return self._invoke_wrapped_toolset_executor_tool(
            tool_name="toolset.terminal.get_output",
            arguments={"session_id": session_id, "start": start, "end": end},
            code=code,
            step=step,
            timeout=max(20, self._safe_positive_int(arguments.get("timeout"), default=20) or 20),
        )

    def _toolset_terminal_send_keys(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        session_id = self._safe_positive_int(arguments.get("session_id"), default=None)
        keys = self._optional_text(arguments.get("keys"))
        enter = bool(arguments.get("enter", False))
        if session_id is None or keys is None:
            return ToolInvocationResult(
                name="toolset.terminal.send_keys",
                content=(
                    "toolset.terminal.send_keys requires 'session_id' (positive integer) and 'keys' (non-empty string)."
                ),
            )
        code = self._build_wrapped_toolset_code(
            tool_name="toolset.terminal.send_keys",
            expression=(
                f"toolset.terminal.send_keys(session_id={session_id}, "
                f"keys={python_literal(keys)}, enter={python_literal(enter)})"
            ),
        )
        return self._invoke_wrapped_toolset_executor_tool(
            tool_name="toolset.terminal.send_keys",
            arguments={"session_id": session_id, "keys": keys, "enter": enter},
            code=code,
            step=step,
            timeout=max(20, self._safe_positive_int(arguments.get("timeout"), default=20) or 20),
        )

    def _close_session(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        session_name = str(arguments.get("session_name", ""))
        closed = self.executor.close_session(session_name)
        content = json_dumps({"session_name": session_name, "closed": closed})
        self.event_logger(
            "tool_call",
            {
                "tool": "mcp__sandbox__close_session",
                "arguments": {"session_name": session_name},
                "result_preview": content,
                "step": step,
            },
        )
        return ToolInvocationResult(name="mcp__sandbox__close_session", content=content)

    def _task(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        description = (
            arguments.get("description")
            or arguments.get("goal")
            or arguments.get("prompt")
            or "Local compatibility task created."
        )
        entry = {
            "timestamp": self._timestamp(),
            "step": step,
            "tool": "Task",
            "arguments": arguments,
        }
        with self.subtask_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

        content = (
            "Task compatibility mode recorded the subtask locally. "
            f"Description: {description}"
        )
        self.event_logger("tool_call", {"tool": "Task", "arguments": arguments, "result_preview": content, "step": step})
        return ToolInvocationResult(name="Task", content=content)

    def _enter_plan_mode(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        reason = str(arguments.get("reason", "")).strip()
        state = self._read_state()
        state["planning_mode"] = True
        state["last_plan_reason"] = reason
        state["updated_at"] = self._timestamp()
        self._write_state(state)
        content = "Plan mode enabled locally."
        if reason:
            content += f" Reason: {reason}"
        self.event_logger(
            "tool_call",
            {"tool": "EnterPlanMode", "arguments": arguments, "result_preview": content, "step": step},
        )
        return ToolInvocationResult(name="EnterPlanMode", content=content)

    def _exit_plan_mode(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        summary = str(arguments.get("summary", "")).strip()
        state = self._read_state()
        state["planning_mode"] = False
        state["last_plan_summary"] = summary
        state["updated_at"] = self._timestamp()
        self._write_state(state)
        content = "Plan mode disabled locally."
        if summary:
            content += f" Summary: {summary}"
        self.event_logger(
            "tool_call",
            {"tool": "ExitPlanMode", "arguments": arguments, "result_preview": content, "step": step},
        )
        return ToolInvocationResult(name="ExitPlanMode", content=content)

    def _todo_write(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        append = bool(arguments.get("append", False))
        todo_content = self._render_todos(arguments)
        existing = self.todo_path.read_text(encoding="utf-8") if self.todo_path.exists() else ""
        if append and existing:
            final_content = existing.rstrip() + "\n" + todo_content.strip() + "\n"
        else:
            final_content = todo_content
        self.todo_path.write_text(final_content, encoding="utf-8")
        self.event_logger(
            "tool_call",
            {
                "tool": "TodoWrite",
                "arguments": arguments,
                "result_preview": truncate_text(final_content, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
            },
        )
        return ToolInvocationResult(
            name="TodoWrite",
            content=f"Todo file updated at {self.todo_path}\n\n{truncate_text(final_content)}",
        )

    def has_msf_tools(self) -> bool:
        return bool(self.msf_client is not None and getattr(self.msf_client, "is_available", lambda: False)())

    def has_challenge_tools(self) -> bool:
        return self.challenge_client is not None

    def _skill_tool_definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "ListSkills",
                    "description": (
                        "List the locally curated security skills library. "
                        "Use this first to inspect summaries before loading any full skill document."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "category": {
                                "type": "string",
                                "description": "Optional exact category filter such as 'web', 'cloud', 'internal', or 'agent-social'.",
                            },
                            "stage": {
                                "description": "Optional stage filter. Accepts a single stage or an array of stages.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "tags": {
                                "description": "Optional tag filter. Accepts a single tag or an array of tags.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Optional maximum number of skills to return.",
                                "minimum": 1,
                                "maximum": 50,
                            },
                        },
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "SearchSkills",
                    "description": (
                        "Search the local skills index by keyword, tags, category, or stage "
                        "without loading full documents."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Keyword query such as 'OA pivot', 'Kerberoast', 'prompt injection', or 'K8s SSRF'.",
                            },
                            "category": {
                                "type": "string",
                                "description": "Optional exact category filter.",
                            },
                            "stage": {
                                "description": "Optional stage filter. Accepts a single stage or an array of stages.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "tags": {
                                "description": "Optional tag filter. Accepts a single tag or an array of tags.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Optional maximum number of search results to return.",
                                "minimum": 1,
                                "maximum": 50,
                            },
                        },
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "LoadSkill",
                    "description": (
                        "Load one specific skill document from the local skills library. "
                        "Do this only after checking the summary list."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "slug": {
                                "type": "string",
                                "description": "Skill slug, for example 'core-methodology' or 'network-oa-pivot'.",
                            },
                            "max_chars": {
                                "type": "integer",
                                "description": "Optional character cap for the returned document body. Larger values may be truncated.",
                                "minimum": 1000,
                                "maximum": 14000,
                            },
                        },
                        "required": ["slug"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    def _toolset_runtime_tool_definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "toolset.browser.get_context",
                    "description": "Initialize toolset.browser in a stable PythonExecutor session and return the reusable session_name plus browser context summary.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_name": {
                                "type": "string",
                                "description": "Optional PythonExecutor session name used to persist the browser context for follow-up execute_code calls.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Optional executor timeout in seconds for initializing the browser context.",
                                "minimum": 1,
                            },
                        },
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "toolset.terminal.list_sessions",
                    "description": "List tmux-backed terminal sessions exposed by toolset.terminal.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "toolset.terminal.kill_session",
                    "description": "Kill a tmux-backed terminal session by session id.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "integer",
                                "description": "Terminal session id returned by toolset.terminal.new_session.",
                                "minimum": 0,
                            }
                        },
                        "required": ["session_id"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "toolset.terminal.new_session",
                    "description": "Create a new tmux-backed terminal session and return its session id.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "toolset.terminal.get_output",
                    "description": "Read captured output from a terminal session.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "integer",
                                "description": "Terminal session id returned by toolset.terminal.new_session.",
                                "minimum": 0,
                            },
                            "start": {
                                "type": "string",
                                "description": "Optional start line selector passed through to toolset.terminal.get_output.",
                            },
                            "end": {
                                "type": "string",
                                "description": "Optional end line selector passed through to toolset.terminal.get_output.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Optional executor timeout in seconds for this wrapper call.",
                                "minimum": 1,
                            },
                        },
                        "required": ["session_id"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "toolset.terminal.send_keys",
                    "description": "Send text or control keys to a terminal session and optionally press enter.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "integer",
                                "description": "Terminal session id returned by toolset.terminal.new_session.",
                                "minimum": 0,
                            },
                            "keys": {
                                "type": "string",
                                "description": "Text or control sequence to send, for example whoami or C-c.",
                            },
                            "enter": {
                                "type": "boolean",
                                "description": "Whether to press enter after sending keys.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Optional executor timeout in seconds for this wrapper call.",
                                "minimum": 1,
                            },
                        },
                        "required": ["session_id", "keys", "enter"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    def _pentest_tool_definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "run_httpx_scan",
                    "description": (
                        "Run a focused httpx scan through the existing PythonExecutor + toolset.terminal workflow. "
                        "Returns structured live-host findings plus a truncated raw output summary."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target URL or host for httpx, for example http://10.10.10.10 or example.com.",
                            },
                            "ports": {
                                "description": "Optional port list. Accepts a comma-separated string or an array of ports.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Optional extra httpx CLI arguments appended as-is.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds for the wrapped command.",
                                "minimum": 1,
                            },
                        },
                        "required": ["target"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_katana_crawl",
                    "description": (
                        "Run a focused katana crawl through the existing PythonExecutor + toolset.terminal workflow. "
                        "Returns extracted URLs plus a truncated raw output summary."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "Base URL to crawl.",
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Optional extra katana CLI arguments appended as-is.",
                            },
                            "timeout_hint": {
                                "type": "integer",
                                "description": "Optional crawl timeout in seconds.",
                                "minimum": 1,
                            },
                        },
                        "required": ["url"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_ffuf_scan",
                    "description": (
                        "Run a focused ffuf scan through the existing PythonExecutor + toolset.terminal workflow. "
                        "Returns match summaries plus a truncated raw output summary."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url_template": {
                                "type": "string",
                                "description": "ffuf target URL template, usually containing FUZZ.",
                            },
                            "wordlist": {
                                "type": "string",
                                "description": (
                                    "Optional local wordlist path accessible from the runtime host. "
                                    f"Defaults to {DEFAULT_FFUF_WORDLIST}."
                                ),
                            },
                            "headers": {
                                "type": "object",
                                "description": "Optional HTTP headers passed with repeated -H arguments.",
                                "additionalProperties": {"type": "string"},
                            },
                            "match_regex": {
                                "type": "string",
                                "description": "Optional ffuf match regex (-mr).",
                            },
                            "filter_regex": {
                                "type": "string",
                                "description": "Optional ffuf filter regex (-fr).",
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Optional extra ffuf CLI arguments appended as-is.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds for the wrapped command.",
                                "minimum": 1,
                            },
                        },
                        "required": ["url_template"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_nuclei_scan",
                    "description": (
                        "Run a focused nuclei scan through the existing PythonExecutor + toolset.terminal workflow. "
                        "Returns finding summaries plus a truncated raw output summary."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target URL, host, or file supported by nuclei.",
                            },
                            "templates": {
                                "description": "Optional template or template list passed with -t.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "severity": {
                                "description": "Optional severity filter passed with -severity.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Optional extra nuclei CLI arguments appended as-is.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds for the wrapped command.",
                                "minimum": 1,
                            },
                        },
                        "required": ["target"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_sqlmap_scan",
                    "description": (
                        "Run a focused sqlmap scan through the existing PythonExecutor + toolset.terminal workflow. "
                        "Returns a compact injection summary plus a truncated raw output summary."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "Target URL for sqlmap -u.",
                            },
                            "data": {
                                "type": "string",
                                "description": "Optional POST body for --data.",
                            },
                            "cookie": {
                                "type": "string",
                                "description": "Optional Cookie header value.",
                            },
                            "headers": {
                                "type": "object",
                                "description": "Optional extra headers merged into --headers.",
                                "additionalProperties": {"type": "string"},
                            },
                            "risk": {
                                "type": "integer",
                                "description": "Optional sqlmap risk value.",
                                "minimum": 1,
                                "maximum": 3,
                            },
                            "level": {
                                "type": "integer",
                                "description": "Optional sqlmap level value.",
                                "minimum": 1,
                                "maximum": 5,
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Optional extra sqlmap CLI arguments appended as-is.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds for the wrapped command.",
                                "minimum": 1,
                            },
                        },
                        "required": ["url"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "extract_secrets_and_flags",
                    "description": (
                        "Extract flags, URLs, IPs, domains, credentials, tokens, versions, and CVE hints from arbitrary text."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Arbitrary text such as page source, HTTP responses, or command output.",
                            }
                        },
                        "required": ["text"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "build_target_profile",
                    "description": (
                        "Heuristically build a target profile from one or more text blobs without calling an extra LLM."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "texts": {
                                "description": "One text blob or an array of text blobs to profile.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            }
                        },
                        "required": ["texts"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "SearchCVEKnowledge",
                    "description": (
                        "Search the local structured CVE / POC JSON knowledge base by product family, version, "
                        "severity, tags, or fuzzy framework keywords without loading full entries."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Optional fuzzy query matching id, product, aliases, tags, fingerprints, signals, or CVE text.",
                            },
                            "family": {
                                "type": "string",
                                "description": "Optional product family such as thinkphp, spring, struts, fastjson, or weblogic.",
                            },
                            "product": {
                                "type": "string",
                                "description": "Optional product name filter, for example ThinkPHP.",
                            },
                            "version": {
                                "type": "string",
                                "description": "Optional loose version filter such as 5.0 or 5.1.x.",
                            },
                            "tags": {
                                "description": "Optional tag filter. Accepts a single tag or an array of tags.",
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}},
                                ],
                            },
                            "severity": {
                                "type": "string",
                                "description": "Optional severity filter: critical, high, medium, or low.",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return.",
                                "minimum": 1,
                                "maximum": 20,
                            },
                        },
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "LoadCVEKnowledge",
                    "description": (
                        "Load one local CVE / POC JSON entry by id and return an agent-friendly detail summary with "
                        "verification, exploitation, and stabilization guidance."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Exact local CVE knowledge id returned by SearchCVEKnowledge.",
                            }
                        },
                        "required": ["id"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    def _msf_tool_definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__get_status",
                    "description": "Get MSF sidecar availability, warmup state, and runtime diagnostics.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__execute_command",
                    "description": "Execute a focused msfconsole batch command through the local ctf adapter.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Metasploit console command such as 'hosts' or 'search type:exploit smb'.",
                            },
                            "workspace": {
                                "type": "string",
                                "description": "Optional workspace to switch into before executing the command.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Optional timeout in seconds.",
                                "minimum": 1,
                            },
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__search_modules",
                    "description": "Search Metasploit modules with pagination support.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query, for example 'platform:windows smb'.",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results per page.",
                                "minimum": 1,
                                "maximum": 50,
                            },
                            "page": {
                                "type": "integer",
                                "description": "1-based result page number.",
                                "minimum": 1,
                            },
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__workspace",
                    "description": "List or manage Metasploit workspaces.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "description": "One of: list, current, create, delete, switch, rename.",
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name used by create, delete, switch, or rename.",
                            },
                            "new_name": {
                                "type": "string",
                                "description": "New workspace name for rename.",
                            },
                        },
                        "required": ["action"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__db_query",
                    "description": "Query common Metasploit database-backed views such as hosts, services, vulns, creds, or sessions.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "One of: status, hosts, services, vulns, creds, loot, notes, sessions.",
                            },
                            "filters": {
                                "type": "string",
                                "description": "Optional extra arguments appended to the Metasploit DB command.",
                            },
                            "workspace": {
                                "type": "string",
                                "description": "Optional workspace to activate before the query.",
                            },
                        },
                        "required": ["operation"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__session",
                    "description": "List or manage active Metasploit sessions.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "description": "One of: list, interact, execute, kill, upgrade.",
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Session identifier for non-list actions.",
                            },
                            "command": {
                                "type": "string",
                                "description": "Command to execute inside the session when action=execute.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Optional timeout in seconds.",
                                "minimum": 1,
                            },
                        },
                        "required": ["action"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__msf__module",
                    "description": "Inspect, configure, or execute a Metasploit module through a stable wrapper.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "description": "One of: info, use, options, set, execute, run, check, search_payloads.",
                            },
                            "module_path": {
                                "type": "string",
                                "description": "Metasploit module path such as exploit/windows/smb/ms17_010_eternalblue.",
                            },
                            "options": {
                                "type": "object",
                                "description": "Optional module options as key/value pairs.",
                                "additionalProperties": True,
                            },
                            "run_action": {
                                "type": "string",
                                "description": "Optional run verb override for execute actions: run, exploit, or check.",
                            },
                            "workspace": {
                                "type": "string",
                                "description": "Optional workspace to activate before the module action.",
                            },
                        },
                        "required": ["action", "module_path"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    def _challenge_tool_definitions(self) -> list[dict[str, Any]]:
        definitions = [
            {
                "type": "function",
                "function": {
                    "name": "mcp__challenge__list_challenges",
                    "description": (
                        "List currently visible hackathon challenges and their platform progress. "
                        "Use this to inspect challenge codes, titles, difficulty, and solved counts."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mcp__challenge__submit_flag",
                    "description": (
                        "Submit one candidate flag for an official hackathon challenge. "
                        "The platform response is authoritative; multiple flags may be required."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": "Exact challenge code from the official platform.",
                            },
                            "flag": {
                                "type": "string",
                                "description": "Candidate flag value, usually in the form flag{...}.",
                            },
                        },
                        "required": ["code", "flag"],
                        "additionalProperties": False,
                    },
                },
            },
        ]
        if self.allow_challenge_lifecycle_tools:
            definitions.extend([
                {
                    "type": "function",
                    "function": {
                        "name": "mcp__challenge__start_challenge",
                        "description": (
                            "Start one official hackathon challenge instance by challenge code and return entrypoint metadata."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "Exact challenge code from the official platform.",
                                }
                            },
                            "required": ["code"],
                            "additionalProperties": False,
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "mcp__challenge__stop_challenge",
                        "description": "Stop one official hackathon challenge instance by challenge code.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "Exact challenge code from the official platform.",
                                }
                            },
                            "required": ["code"],
                            "additionalProperties": False,
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "mcp__challenge__view_hint",
                        "description": (
                            "View the official hint for a challenge by code. The first view costs 10% of that challenge's total score."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "Exact challenge code from the official platform.",
                                }
                            },
                            "required": ["code"],
                            "additionalProperties": False,
                        },
                    },
                },
            ])
        return definitions

    def _msf_get_status(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        return self._invoke_msf_tool("mcp__msf__get_status", arguments, step, lambda: self.msf_client.get_status())

    def _msf_execute_command(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        return self._invoke_msf_tool(
            "mcp__msf__execute_command",
            arguments,
            step,
            lambda: self.msf_client.execute_command(
                command=str(arguments.get("command", "")),
                workspace=arguments.get("workspace"),
                timeout=arguments.get("timeout"),
            ),
        )

    def _msf_search_modules(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        return self._invoke_msf_tool(
            "mcp__msf__search_modules",
            arguments,
            step,
            lambda: self.msf_client.search_modules(
                query=str(arguments.get("query", "")),
                limit=int(arguments.get("limit") or 10),
                page=int(arguments.get("page") or 1),
            ),
        )

    def _msf_workspace(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        return self._invoke_msf_tool(
            "mcp__msf__workspace",
            arguments,
            step,
            lambda: self.msf_client.workspace(
                action=str(arguments.get("action", "")),
                workspace_name=arguments.get("workspace_name"),
                new_name=arguments.get("new_name"),
            ),
        )

    def _msf_db_query(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        return self._invoke_msf_tool(
            "mcp__msf__db_query",
            arguments,
            step,
            lambda: self.msf_client.db_query(
                operation=str(arguments.get("operation", "")),
                filters=arguments.get("filters"),
                workspace=arguments.get("workspace"),
            ),
        )

    def _msf_session(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        return self._invoke_msf_tool(
            "mcp__msf__session",
            arguments,
            step,
            lambda: self.msf_client.session(
                action=str(arguments.get("action", "")),
                session_id=arguments.get("session_id"),
                command=arguments.get("command"),
                timeout=arguments.get("timeout"),
            ),
        )

    def _msf_module(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        options = arguments.get("options")
        if not isinstance(options, dict):
            options = None
        return self._invoke_msf_tool(
            "mcp__msf__module",
            arguments,
            step,
            lambda: self.msf_client.module_action(
                action=str(arguments.get("action", "")),
                module_path=str(arguments.get("module_path", "")),
                options=options,
                run_action=arguments.get("run_action"),
                workspace=arguments.get("workspace"),
            ),
        )

    def _invoke_msf_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        callback: Callable[[], dict[str, Any]],
    ) -> ToolInvocationResult:
        if self.msf_client is None:
            content = json_dumps(
                {
                    "success": False,
                    "status": "unavailable",
                    "tool": tool_name,
                    "error": "MSF integration is not enabled for this runtime.",
                }
            )
            self.event_logger("tool_error", {"tool": tool_name, "arguments": arguments, "message": content, "step": step})
            return ToolInvocationResult(name=tool_name, content=content)

        try:
            payload = callback()
        except Exception as exc:
            payload = {
                "success": False,
                "status": "error",
                "tool": tool_name,
                "error": f"MSF tool invocation failed: {exc}",
            }

        result_text = truncate_text(json_dumps(payload))
        flag = extract_flag(result_text)
        self.event_logger(
            "tool_call",
            {
                "tool": tool_name,
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
                "flag": flag,
            },
        )
        solved = flag is not None and not self.has_challenge_tools()
        return ToolInvocationResult(name=tool_name, content=result_text, solved=solved, flag=flag)

    def _challenge_list_challenges(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        del arguments
        return self._invoke_challenge_tool(
            "mcp__challenge__list_challenges",
            {},
            step,
            lambda: self.challenge_client.list_challenges(),
        )

    def _challenge_start_challenge(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        code = str(arguments.get("code", "")).strip()
        return self._invoke_challenge_tool(
            "mcp__challenge__start_challenge",
            {"code": code},
            step,
            lambda: self.challenge_client.start_challenge(code),
        )

    def _challenge_stop_challenge(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        code = str(arguments.get("code", "")).strip()
        return self._invoke_challenge_tool(
            "mcp__challenge__stop_challenge",
            {"code": code},
            step,
            lambda: self.challenge_client.stop_challenge(code),
        )

    def _challenge_submit_flag(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        code = str(arguments.get("code", "")).strip()
        flag = str(arguments.get("flag", "")).strip()
        return self._invoke_challenge_tool(
            "mcp__challenge__submit_flag",
            {"code": code, "flag": flag},
            step,
            lambda: self.challenge_client.submit_flag(code, flag),
            solved_evaluator=self._is_submit_flag_fully_solved,
            progress_evaluator=self._extract_submit_flag_progress,
            result_flag=flag or None,
        )

    def _challenge_view_hint(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        code = str(arguments.get("code", "")).strip()
        return self._invoke_challenge_tool(
            "mcp__challenge__view_hint",
            {"code": code},
            step,
            lambda: self.challenge_client.view_hint(code),
        )

    def _invoke_challenge_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        callback: Callable[[], dict[str, Any]],
        solved_evaluator: Callable[[dict[str, Any]], bool] | None = None,
        progress_evaluator: Callable[[dict[str, Any]], tuple[bool, str | None]] | None = None,
        result_flag: str | None = None,
    ) -> ToolInvocationResult:
        if self.challenge_client is None:
            return self._challenge_tool_unavailable(tool_name, arguments, step)

        try:
            payload = callback()
        except Exception as exc:
            payload = {
                "success": False,
                "status": "error",
                "tool": tool_name,
                "error": str(exc),
            }
            result_text = self._format_platform_payload(payload)
            self.event_logger(
                "tool_error",
                {
                    "tool": tool_name,
                    "arguments": arguments,
                    "message": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                    "step": step,
                },
            )
            return ToolInvocationResult(name=tool_name, content=result_text)

        solved = solved_evaluator(payload) if solved_evaluator is not None else False
        if progress_evaluator is not None:
            progress, progress_detail = progress_evaluator(payload)
        else:
            progress = solved
            progress_detail = "challenge fully solved" if solved else None
        result_text = self._format_platform_payload(payload)
        extracted_flag = result_flag if (solved or progress) and result_flag else extract_flag(result_text)
        candidate_flags = self._build_platform_candidate_flags(
            tool_name=tool_name,
            flag_value=extracted_flag,
            progress=progress,
            solved=solved,
            step=step,
            result_text=result_text,
        )
        self.event_logger(
            "tool_call",
            {
                "tool": tool_name,
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
                "solved": solved,
                "progress": progress,
                "progress_detail": progress_detail,
                "flag": extracted_flag,
                "candidate_flags": candidate_flags,
            },
        )
        return ToolInvocationResult(
            name=tool_name,
            content=result_text,
            solved=solved,
            flag=extracted_flag,
            progress=progress,
            progress_detail=progress_detail,
            candidate_flags=candidate_flags,
        )

    def _challenge_tool_unavailable(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
    ) -> ToolInvocationResult:
        content = self._format_platform_payload(
            {
                "success": False,
                "status": "unavailable",
                "tool": tool_name,
                "error": "Challenge platform client is not enabled for this runtime.",
            }
        )
        self.event_logger(
            "tool_error",
            {"tool": tool_name, "arguments": arguments, "message": content, "step": step},
        )
        return ToolInvocationResult(name=tool_name, content=content)

    def _build_platform_candidate_flags(
        self,
        *,
        tool_name: str,
        flag_value: str | None,
        progress: bool,
        solved: bool,
        step: int,
        result_text: str,
    ) -> list[dict[str, Any]]:
        if not flag_value:
            return []

        source_type = FLAG_SOURCE_OBSERVED_PLATFORM_RESPONSE
        if tool_name == "mcp__challenge__view_hint":
            source_type = FLAG_SOURCE_OBSERVED_HINT
        confidence = FLAG_CONFIDENCE_HIGH if (progress or solved or tool_name == "mcp__challenge__view_hint") else FLAG_CONFIDENCE_MEDIUM
        observation = CandidateFlagObservation(
            value=flag_value,
            source_type=source_type,
            confidence=confidence,
            observed_in_step=step,
            evidence_excerpt=self._clip_excerpt(result_text),
            auto_submittable=self._should_auto_submit_candidate_flag(
                value=flag_value,
                source_type=source_type,
                confidence=confidence,
            ),
        )
        return self._serialize_candidate_flags([observation])

    def _format_platform_payload(self, payload: dict[str, Any]) -> str:
        return truncate_text(json_dumps(payload))

    def _is_submit_flag_fully_solved(self, payload: dict[str, Any]) -> bool:
        flag_got_count = self._as_int(payload.get("flag_got_count"))
        flag_count = self._as_int(payload.get("flag_count"))
        if flag_got_count is not None and flag_count is not None:
            return flag_count > 0 and flag_got_count >= flag_count

        if payload.get("correct") is not True:
            return False

        message = str(payload.get("message", "")).strip().lower()
        if any(
            token in message
            for token in (
                "全部完成",
                "全部提交成功",
                "challenge solved",
                "fully solved",
                "all flags",
                "completed",
                "完成该题",
            )
        ):
            return True

        match = re.search(r"\((\d+)\s*/\s*(\d+)\)", message)
        if match is None:
            return False
        return int(match.group(1)) >= int(match.group(2))

    def _extract_submit_flag_progress(self, payload: dict[str, Any]) -> tuple[bool, str | None]:
        if not isinstance(payload, dict):
            return False, None

        if payload.get("correct") is not True:
            return False, None

        if self._is_submit_flag_fully_solved(payload):
            return True, "challenge fully solved"

        flag_got_count = self._as_int(payload.get("flag_got_count"))
        flag_count = self._as_int(payload.get("flag_count"))
        if flag_got_count is not None and flag_count is not None:
            if flag_count > 0 and flag_got_count < flag_count:
                return True, f"platform flag progress increased to {flag_got_count}/{flag_count}"
            return True, "correct flag accepted by platform"

        message = self._platform_message(payload)
        if re.search(r"\b\d+\s*/\s*\d+\b", message):
            return True, "platform flag progress increased"

        acceptance_markers = (
            "答案正确",
            "提交正确",
            "accepted",
            "correct flag",
            "correct answer",
            "partial progress",
            "部分完成",
            "部分进度",
            "scored",
        )
        duplicate_markers = (
            "already submitted",
            "already got",
            "duplicate",
            "重复",
            "已提交",
            "已获得",
        )
        if any(marker in message for marker in acceptance_markers) and not any(
            marker in message for marker in duplicate_markers
        ):
            return True, "correct flag accepted by platform"

        return False, None

    @staticmethod
    def _platform_message(payload: dict[str, Any]) -> str:
        candidates = (
            payload.get("message"),
            payload.get("raw_text"),
            payload.get("content"),
            payload.get("detail"),
        )
        for candidate in candidates:
            if candidate is None:
                continue
            text = str(candidate).strip()
            if text:
                return text.lower()
        return ""

    def _list_skills(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        if self.skill_manager is None:
            content = json_dumps({"success": False, "error": "Skill manager is not configured."})
            self.event_logger(
                "tool_error",
                {"tool": "ListSkills", "arguments": arguments, "message": content, "step": step},
            )
            return ToolInvocationResult(name="ListSkills", content=content)

        payload = self.skill_manager.list_skills(
            category=self._optional_text(arguments.get("category")),
            stage=arguments.get("stage"),
            tags=arguments.get("tags"),
            limit=arguments.get("limit"),
            step=step,
        )
        result_text = truncate_text(json_dumps(payload))
        self.event_logger(
            "tool_call",
            {
                "tool": "ListSkills",
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
            },
        )
        return ToolInvocationResult(name="ListSkills", content=result_text)

    def _search_skills(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        if self.skill_manager is None:
            content = json_dumps({"success": False, "error": "Skill manager is not configured."})
            self.event_logger(
                "tool_error",
                {"tool": "SearchSkills", "arguments": arguments, "message": content, "step": step},
            )
            return ToolInvocationResult(name="SearchSkills", content=content)

        payload = self.skill_manager.search_skills(
            query=self._optional_text(arguments.get("query")),
            category=self._optional_text(arguments.get("category")),
            stage=arguments.get("stage"),
            tags=arguments.get("tags"),
            limit=arguments.get("limit"),
            step=step,
        )
        result_text = truncate_text(json_dumps(payload))
        self.event_logger(
            "tool_call",
            {
                "tool": "SearchSkills",
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
            },
        )
        return ToolInvocationResult(name="SearchSkills", content=result_text)

    def _load_skill(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        if self.skill_manager is None:
            content = json_dumps({"success": False, "error": "Skill manager is not configured."})
            self.event_logger(
                "tool_error",
                {"tool": "LoadSkill", "arguments": arguments, "message": content, "step": step},
            )
            return ToolInvocationResult(name="LoadSkill", content=content)

        payload = self.skill_manager.load_skill(
            str(arguments.get("slug", "")),
            max_chars=arguments.get("max_chars"),
            step=step,
        )
        result_text = truncate_text(json_dumps(payload))
        self.event_logger(
            "tool_call",
            {
                "tool": "LoadSkill",
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
            },
        )
        return ToolInvocationResult(name="LoadSkill", content=result_text)

    def _run_httpx_scan(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        target = str(arguments.get("target", "")).strip()
        if not target:
            return self._structured_tool_error("run_httpx_scan", arguments, step, "target is required")
        ports = self._normalize_string_list(arguments.get("ports"))
        base_parts = ["httpx", "-silent", "-json", "-u", target]
        if ports:
            base_parts.extend(["-ports", ",".join(ports)])
        command = self._build_command(base_parts, self._optional_text(arguments.get("extra_args")))
        return self._invoke_terminal_scan_tool(
            tool_name="run_httpx_scan",
            arguments=arguments,
            step=step,
            command=command,
            timeout=self._safe_positive_int(arguments.get("timeout"), default=45),
            summarizer=self._summarize_httpx_output,
        )

    def _run_katana_crawl(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        url = str(arguments.get("url", "")).strip()
        if not url:
            return self._structured_tool_error("run_katana_crawl", arguments, step, "url is required")
        base_parts = ["katana", "-u", url, "-silent", "-jsonl"]
        command = self._build_command(base_parts, self._optional_text(arguments.get("extra_args")))
        return self._invoke_terminal_scan_tool(
            tool_name="run_katana_crawl",
            arguments=arguments,
            step=step,
            command=command,
            timeout=self._safe_positive_int(arguments.get("timeout_hint"), default=60),
            summarizer=self._summarize_katana_output,
        )

    def _run_ffuf_scan(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        url_template = str(arguments.get("url_template", "")).strip()
        wordlist = str(arguments.get("wordlist") or DEFAULT_FFUF_WORDLIST).strip()
        if not url_template:
            return self._structured_tool_error(
                "run_ffuf_scan",
                arguments,
                step,
                "url_template is required",
            )
        base_parts = ["ffuf", "-u", url_template, "-w", wordlist, "-json"]
        headers = arguments.get("headers")
        if isinstance(headers, dict):
            for key, value in headers.items():
                header_key = str(key).strip()
                header_value = str(value).strip()
                if header_key and header_value:
                    base_parts.extend(["-H", f"{header_key}: {header_value}"])
        match_regex = self._optional_text(arguments.get("match_regex"))
        if match_regex:
            base_parts.extend(["-mr", match_regex])
        filter_regex = self._optional_text(arguments.get("filter_regex"))
        if filter_regex:
            base_parts.extend(["-fr", filter_regex])
        command = self._build_command(base_parts, self._optional_text(arguments.get("extra_args")))
        return self._invoke_terminal_scan_tool(
            tool_name="run_ffuf_scan",
            arguments=arguments,
            step=step,
            command=command,
            timeout=self._safe_positive_int(arguments.get("timeout"), default=90),
            summarizer=self._summarize_ffuf_output,
        )

    def _run_nuclei_scan(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        target = str(arguments.get("target", "")).strip()
        if not target:
            return self._structured_tool_error("run_nuclei_scan", arguments, step, "target is required")
        base_parts = ["nuclei", "-u", target, "-silent", "-jsonl"]
        templates = self._normalize_string_list(arguments.get("templates"))
        for template in templates:
            base_parts.extend(["-t", template])
        severity = self._normalize_string_list(arguments.get("severity"))
        if severity:
            base_parts.extend(["-severity", ",".join(severity)])
        command = self._build_command(base_parts, self._optional_text(arguments.get("extra_args")))
        return self._invoke_terminal_scan_tool(
            tool_name="run_nuclei_scan",
            arguments=arguments,
            step=step,
            command=command,
            timeout=self._safe_positive_int(arguments.get("timeout"), default=120),
            summarizer=self._summarize_nuclei_output,
        )

    def _run_sqlmap_scan(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        url = str(arguments.get("url", "")).strip()
        if not url:
            return self._structured_tool_error("run_sqlmap_scan", arguments, step, "url is required")
        base_parts = ["sqlmap", "-u", url, "--batch"]
        data = self._optional_text(arguments.get("data"))
        if data:
            base_parts.extend(["--data", data])
        cookie = self._optional_text(arguments.get("cookie"))
        if cookie:
            base_parts.extend(["--cookie", cookie])
        headers = arguments.get("headers")
        header_lines: list[str] = []
        if isinstance(headers, dict):
            for key, value in headers.items():
                header_key = str(key).strip()
                header_value = str(value).strip()
                if header_key and header_value:
                    header_lines.append(f"{header_key}: {header_value}")
        if header_lines:
            base_parts.extend(["--headers", "\\n".join(header_lines)])
        risk = self._safe_positive_int(arguments.get("risk"), default=None)
        if risk is not None:
            base_parts.extend(["--risk", str(risk)])
        level = self._safe_positive_int(arguments.get("level"), default=None)
        if level is not None:
            base_parts.extend(["--level", str(level)])
        command = self._build_command(base_parts, self._optional_text(arguments.get("extra_args")))
        return self._invoke_terminal_scan_tool(
            tool_name="run_sqlmap_scan",
            arguments=arguments,
            step=step,
            command=command,
            timeout=self._safe_positive_int(arguments.get("timeout"), default=180),
            summarizer=self._summarize_sqlmap_output,
        )

    def _extract_secrets_and_flags_tool(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        text = str(arguments.get("text", ""))
        return self._invoke_structured_local_tool(
            "extract_secrets_and_flags",
            arguments,
            step,
            lambda: {"success": True, "artifacts": extract_artifacts_from_text(text)},
        )

    def _build_target_profile_tool(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        texts = arguments.get("texts")
        return self._invoke_structured_local_tool(
            "build_target_profile",
            arguments,
            step,
            lambda: {"success": True, "profile": build_target_profile_from_text(texts)},
        )

    def _search_cve_knowledge(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        tags = arguments.get("tags")
        normalized_tags = self._normalize_string_list(tags)
        limit = self._safe_positive_int(arguments.get("limit"), default=5) or 5
        return self._invoke_structured_local_tool(
            "SearchCVEKnowledge",
            arguments,
            step,
            lambda: self.cve_knowledge.search(
                query=str(arguments.get("query", "")).strip(),
                family=str(arguments.get("family", "")).strip(),
                product=str(arguments.get("product", "")).strip(),
                version=str(arguments.get("version", "")).strip(),
                tags=normalized_tags or None,
                severity=str(arguments.get("severity", "")).strip(),
                limit=limit,
            ),
        )

    def _load_cve_knowledge(self, arguments: dict[str, Any], step: int) -> ToolInvocationResult:
        entry_id = str(arguments.get("id", "")).strip()
        if not entry_id:
            return self._structured_tool_error("LoadCVEKnowledge", arguments, step, "id is required")
        return self._invoke_structured_local_tool(
            "LoadCVEKnowledge",
            arguments,
            step,
            lambda: self.cve_knowledge.load_by_id(entry_id),
        )

    def _invoke_structured_local_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        callback: Callable[[], dict[str, Any]],
    ) -> ToolInvocationResult:
        try:
            payload = callback()
        except Exception as exc:
            payload = {"success": False, "tool": tool_name, "error": str(exc)}
        result_text = truncate_text(json_dumps(payload))
        flag = extract_flag(result_text)
        self.event_logger(
            "tool_call",
            {
                "tool": tool_name,
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
                "flag": flag,
            },
        )
        solved = flag is not None and not self.has_challenge_tools()
        return ToolInvocationResult(name=tool_name, content=result_text, solved=solved, flag=flag)

    def _invoke_terminal_scan_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        command: str,
        timeout: int,
        summarizer: Callable[[str], dict[str, Any]],
    ) -> ToolInvocationResult:
        try:
            execution = self._run_terminal_command_via_executor(
                tool_name=tool_name,
                step=step,
                command=command,
                timeout=timeout,
            )
            helper_payload = execution["helper_payload"]
            raw_output = str(helper_payload.get("output", ""))
            summary = summarizer(raw_output)
            result_payload = {
                "success": bool(helper_payload.get("success")),
                "command": command,
                "timeout": timeout,
                "returncode": helper_payload.get("returncode"),
                "timed_out": bool(helper_payload.get("timed_out")),
                "summary": summary,
                "raw_output_summary": truncate_lines(raw_output),
                "execution_record": execution["execution_record"],
            }
            if helper_payload.get("error"):
                result_payload["error"] = helper_payload.get("error")
        except Exception as exc:
            result_payload = {
                "success": False,
                "command": command,
                "timeout": timeout,
                "error": str(exc),
            }

        result_text = truncate_text(json_dumps(result_payload))
        flag = extract_flag(result_text)
        self.event_logger(
            "tool_call",
            {
                "tool": tool_name,
                "arguments": {**arguments, "resolved_command": command},
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
                "flag": flag,
            },
        )
        solved = flag is not None and not self.has_challenge_tools()
        return ToolInvocationResult(name=tool_name, content=result_text, solved=solved, flag=flag)

    def _build_wrapped_toolset_code(self, *, tool_name: str, expression: str) -> str:
        return f"""
import json

import toolset

_result_prefix = {json.dumps(TOOLSET_WRAPPER_PREFIX)}
payload = {{
    "success": False,
    "tool": {json.dumps(tool_name, ensure_ascii=False)},
}}

try:
    result = {expression}
    payload["success"] = True
    payload["result"] = result
except Exception as exc:
    payload["error"] = str(exc)
    payload["error_type"] = exc.__class__.__name__

print(_result_prefix + json.dumps(payload, ensure_ascii=False, default=str))
""".strip()

    def _parse_wrapped_toolset_payload(self, outputs: list[dict[str, Any]]) -> dict[str, Any]:
        flattened = self._flatten_executor_outputs(outputs)
        if "execute_code exceeded wall timeout" in flattened:
            return {
                "success": False,
                "result": None,
                "timed_out": True,
                "error": flattened.strip(),
            }
        marker_index = flattened.rfind(TOOLSET_WRAPPER_PREFIX)
        if marker_index >= 0:
            payload_text = flattened[marker_index + len(TOOLSET_WRAPPER_PREFIX) :].strip().splitlines()[0]
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                return payload
        return {
            "success": False,
            "result": None,
            "error": "Failed to parse wrapped toolset output.",
            "raw_output": flattened,
        }

    def _invoke_wrapped_toolset_executor_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        code: str,
        step: int,
        timeout: int = 20,
        session_name: str = "toolset_runtime_wrappers",
    ) -> ToolInvocationResult:
        outputs = self._execute_code_with_guard(
            session_name=session_name,
            code=code,
            timeout=timeout,
            step=step,
            tool_name=tool_name,
            log_arguments={"session_name": session_name, **arguments},
        )
        payload = self._parse_wrapped_toolset_payload(outputs)

        self.execution_counter += 1
        record = {
            "step": step,
            "tool": tool_name,
            "arguments": arguments,
            "timeout": timeout,
            "payload": payload,
            "outputs": outputs,
        }
        execution_path = self.execution_dir / f"{self.execution_counter:04d}_{self._safe_name(tool_name)}.json"
        execution_path.write_text(json_dumps(record), encoding="utf-8")

        result_text = truncate_text(json_dumps(payload))
        flag = extract_flag(result_text)
        self.event_logger(
            "tool_call",
            {
                "tool": tool_name,
                "arguments": arguments,
                "result_preview": truncate_text(result_text, MAX_RESULT_PREVIEW_CHARS),
                "step": step,
                "flag": flag,
            },
        )
        solved = flag is not None and not self.has_challenge_tools()
        return ToolInvocationResult(name=tool_name, content=result_text, solved=solved, flag=flag)

    def _run_terminal_command_via_executor(
        self,
        *,
        tool_name: str,
        step: int,
        command: str,
        timeout: int,
    ) -> dict[str, Any]:
        session_name = f"{tool_name}_step_{step}"
        code = self._build_terminal_helper_code(command=command, timeout=timeout)
        executor_timeout = max(timeout + 15, 25)
        try:
            outputs = self._execute_code_with_guard(
                session_name=session_name,
                code=code,
                timeout=executor_timeout,
                step=step,
                tool_name=tool_name,
                log_arguments={
                    "session_name": session_name,
                    "command": command,
                    "timeout": timeout,
                    "executor_timeout": executor_timeout,
                },
            )
        finally:
            try:
                self._close_executor_session_with_timeout(session_name)
            except Exception:
                pass
        helper_payload = self._parse_terminal_helper_payload(outputs)

        self.execution_counter += 1
        record = {
            "step": step,
            "tool": tool_name,
            "command": command,
            "timeout": timeout,
            "helper_payload": helper_payload,
            "outputs": outputs,
        }
        execution_path = self.execution_dir / f"{self.execution_counter:04d}_{self._safe_name(tool_name)}.json"
        execution_path.write_text(json_dumps(record), encoding="utf-8")
        return {
            "helper_payload": helper_payload,
            "outputs": outputs,
            "execution_record": str(execution_path),
        }

    def _build_terminal_helper_code(self, *, command: str, timeout: int) -> str:
        return f"""
import json
import shlex
import time
import uuid

import toolset

_result_prefix = {json.dumps(TERMINAL_HELPER_PREFIX)}
command = {json.dumps(command, ensure_ascii=False)}
timeout = int({int(timeout)})
session_id = None
payload = {{
    "success": False,
    "command": command,
    "timeout": timeout,
    "output": "",
    "returncode": None,
    "timed_out": False,
}}

try:
    session_id = toolset.terminal.new_session()
    marker = "__PENTEST_DONE__" + uuid.uuid4().hex
    wrapped = "set -o pipefail; " + command + " 2>&1; rc=$?; printf '\\n" + marker + ":%s\\n' \\"$rc\\""
    toolset.terminal.send_keys(session_id=session_id, keys="bash -lc " + shlex.quote(wrapped), enter=True)
    latest_output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        latest_output = toolset.terminal.get_output(session_id=session_id, start="-", end="-")
        if marker in latest_output:
            payload["output"] = latest_output
            for line in reversed(latest_output.splitlines()):
                if line.startswith(marker + ":"):
                    try:
                        payload["returncode"] = int(line.split(":", 1)[1].strip())
                    except Exception:
                        payload["returncode"] = None
                    break
            payload["success"] = payload["returncode"] == 0
            break
        time.sleep(1.0)
    else:
        payload["timed_out"] = True
        payload["error"] = f"Command timed out after {{timeout}} seconds."
        payload["output"] = latest_output
        try:
            toolset.terminal.send_keys(session_id=session_id, keys="C-c", enter=False)
        except Exception:
            pass
except Exception as exc:
    payload["error"] = str(exc)
finally:
    if session_id is not None:
        try:
            toolset.terminal.kill_session(session_id=session_id)
        except Exception:
            pass

print(_result_prefix + json.dumps(payload, ensure_ascii=False))
""".strip()

    def _parse_terminal_helper_payload(self, outputs: list[dict[str, Any]]) -> dict[str, Any]:
        flattened = self._flatten_executor_outputs(outputs)
        if "execute_code exceeded wall timeout" in flattened:
            return {
                "success": False,
                "output": flattened,
                "returncode": None,
                "timed_out": True,
                "error": flattened.strip(),
            }
        marker_index = flattened.rfind(TERMINAL_HELPER_PREFIX)
        if marker_index >= 0:
            payload_text = flattened[marker_index + len(TERMINAL_HELPER_PREFIX) :].strip().splitlines()[0]
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                output = str(payload.get("output", ""))
                payload["output"] = self._remove_terminal_marker(output)
                return payload
        return {
            "success": False,
            "output": flattened,
            "returncode": None,
            "timed_out": False,
            "error": "Failed to parse terminal helper output.",
        }

    def _flatten_executor_outputs(self, outputs: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for output in outputs:
            output_type = output.get("type")
            if output_type == "stream":
                parts.append(str(output.get("text", "")))
                continue
            if output_type in {"display_data", "execute_result"}:
                data = output.get("data") or {}
                if isinstance(data, dict):
                    text_value = data.get("text/plain")
                    if isinstance(text_value, list):
                        parts.append("\n".join(str(item) for item in text_value))
                    elif text_value is not None:
                        parts.append(str(text_value))
                continue
            if output_type == "error":
                traceback_lines = output.get("traceback") or []
                if traceback_lines:
                    parts.append("\n".join(str(line) for line in traceback_lines))
                else:
                    parts.append(f"{output.get('ename', 'Error')}: {output.get('evalue', '')}")
        return "\n".join(part for part in parts if part)

    def _remove_terminal_marker(self, output: str) -> str:
        lines = []
        for line in output.splitlines():
            if line.startswith("__PENTEST_DONE__") and ":" in line:
                continue
            lines.append(line)
        return "\n".join(lines).strip()

    def _summarize_httpx_output(self, output: str) -> dict[str, Any]:
        items = load_json_lines(output)
        results: list[dict[str, Any]] = []
        urls: list[str] = []
        for item in items:
            url = self._optional_text(item.get("url")) or self._optional_text(item.get("input")) or self._optional_text(item.get("host"))
            if not url:
                continue
            urls.append(url)
            result: dict[str, Any] = {"url": url}
            status_code = self._as_int(item.get("status_code"))
            if status_code is not None:
                result["status_code"] = status_code
            title = self._optional_text(item.get("title"))
            if title:
                result["title"] = title
            webserver = self._optional_text(item.get("webserver"))
            if webserver:
                result["webserver"] = webserver
            tech = item.get("tech")
            if isinstance(tech, list) and tech:
                result["tech"] = [str(entry) for entry in tech[:5]]
            results.append(result)

        if not results:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                url = line.split()[0]
                if url.startswith("http://") or url.startswith("https://"):
                    urls.append(url)
                    results.append({"url": url})
        return {
            "count": len(results),
            "urls": dedupe_list(urls)[:20],
            "results": results[:20],
        }

    def _summarize_katana_output(self, output: str) -> dict[str, Any]:
        items = load_json_lines(output)
        urls: list[str] = []
        for item in items:
            url = self._optional_text(item.get("url"))
            if not url and isinstance(item.get("request"), dict):
                url = self._optional_text(item["request"].get("endpoint")) or self._optional_text(item["request"].get("url"))
            if url:
                urls.append(url)
        if not urls:
            urls.extend(
                line.strip()
                for line in output.splitlines()
                if line.strip().startswith("http://") or line.strip().startswith("https://")
            )
        deduped = dedupe_list(urls)
        return {
            "url_count": len(deduped),
            "urls": deduped[:30],
            "interesting_urls": [url for url in deduped if any(token in url.lower() for token in ("admin", "login", "api", "upload", "graphql"))][:15],
        }

    def _summarize_ffuf_output(self, output: str) -> dict[str, Any]:
        items = load_json_lines(output)
        matches: list[dict[str, Any]] = []
        for item in items:
            if "results" in item and isinstance(item["results"], list):
                iterable = [entry for entry in item["results"] if isinstance(entry, dict)]
            else:
                iterable = [item]
            for entry in iterable:
                url = self._optional_text(entry.get("url"))
                if not url:
                    continue
                match_item: dict[str, Any] = {"url": url}
                for key in ("status", "length", "words", "lines"):
                    value = self._as_int(entry.get(key))
                    if value is not None:
                        match_item[key] = value
                redirect = self._optional_text(entry.get("redirectlocation"))
                if redirect:
                    match_item["redirect"] = redirect
                matches.append(match_item)
        return {
            "match_count": len(matches),
            "matches": matches[:30],
        }

    def _summarize_nuclei_output(self, output: str) -> dict[str, Any]:
        items = load_json_lines(output)
        findings: list[dict[str, Any]] = []
        for item in items:
            finding = {
                "template_id": self._optional_text(item.get("template-id")),
                "matched_at": self._optional_text(item.get("matched-at")),
            }
            info = item.get("info")
            if isinstance(info, dict):
                name = self._optional_text(info.get("name"))
                severity = self._optional_text(info.get("severity"))
                if name:
                    finding["name"] = name
                if severity:
                    finding["severity"] = severity
            finding = {key: value for key, value in finding.items() if value}
            if finding:
                findings.append(finding)
        return {
            "finding_count": len(findings),
            "findings": findings[:30],
        }

    def _summarize_sqlmap_output(self, output: str) -> dict[str, Any]:
        lowered = output.lower()
        dbms_match = re.search(r"(?im)back-end dbms:\s*(.+)$", output)
        current_db_match = re.search(r"(?im)current database:\s*[\"']?([^\"'\r\n]+)", output)
        interesting_lines = [
            line.strip()
            for line in output.splitlines()
            if any(
                token in line.lower()
                for token in (
                    "is vulnerable",
                    "identified the following injection point",
                    "back-end dbms",
                    "current user",
                    "current database",
                    "available databases",
                    "parameter",
                )
            )
        ]
        return {
            "injectable": "is vulnerable" in lowered or "identified the following injection point" in lowered,
            "dbms": dbms_match.group(1).strip() if dbms_match else None,
            "current_database": current_db_match.group(1).strip() if current_db_match else None,
            "interesting_lines": interesting_lines[:20],
            "artifacts": extract_artifacts_from_text(output),
        }

    def _structured_tool_error(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        message: str,
    ) -> ToolInvocationResult:
        payload = {"success": False, "tool": tool_name, "error": message}
        result_text = json_dumps(payload)
        self.event_logger(
            "tool_error",
            {"tool": tool_name, "arguments": arguments, "message": result_text, "step": step},
        )
        return ToolInvocationResult(name=tool_name, content=result_text)

    def _render_todos(self, arguments: dict[str, Any]) -> str:
        raw_content = arguments.get("content")
        if isinstance(raw_content, str) and raw_content.strip():
            return raw_content.strip() + "\n"

        items = arguments.get("items") or arguments.get("todos") or arguments.get("entries")
        lines: list[str] = []
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str):
                    lines.append(f"- [ ] {item}")
                    continue
                if isinstance(item, dict):
                    status = str(item.get("status", "pending")).lower()
                    checked = "x" if status in {"done", "complete", "completed"} else " "
                    text = item.get("content") or item.get("task") or item.get("title")
                    if not text:
                        text = json.dumps(item, ensure_ascii=False)
                    line = f"- [{checked}] {text}"
                    note = item.get("note") or item.get("reason")
                    if note:
                        line += f" - {note}"
                    lines.append(line)

        if not lines:
            lines.append("- [ ] (empty todo update)")
        return "\n".join(lines) + "\n"

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _write_state(self, state: dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_name(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "session"

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _normalize_string_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    @staticmethod
    def _safe_positive_int(value: Any, *, default: int | None) -> int | None:
        if value is None:
            return default
        try:
            parsed = int(str(value).strip())
        except (TypeError, ValueError):
            return default
        if parsed <= 0:
            return default
        return parsed

    @staticmethod
    def _build_command(parts: list[str], extra_args: str | None) -> str:
        command = shlex.join(parts)
        if extra_args:
            command += " " + extra_args.strip()
        return command

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


def dedupe_list(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for value in values:
        cleaned = str(value).strip()
        if cleaned and cleaned not in deduped:
            deduped.append(cleaned)
    return deduped
