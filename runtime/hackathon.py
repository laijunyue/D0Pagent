from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from types import SimpleNamespace
from typing import Any
import json
import multiprocessing
import os
import re
import signal
import threading
import time
import traceback
from uuid import uuid4

from .evidence_store import EvidenceStore
from .challenge_platform import ChallengePlatformClient
from .runtime import (
    CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN,
    CHALLENGE_MODE_SINGLE_FLAG,
    Runtime,
    build_hackathon_task,
    resolve_challenge_mode,
    resolve_runtime_max_steps,
)
from .skills import SkillManager


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = PROJECT_ROOT / "skills"
MAIN_BATTLEFIELD_STAGE_THRESHOLDS: dict[int, int] = {
    1: 14,
    2: 6,
    3: 9,
}
_NAMED_STAGE_MARKERS: dict[int, tuple[str, ...]] = {
    1: ("第一赛区", "识器·明理"),
    2: ("第二赛区", "洞见·虚实"),
    3: ("第三赛区", "执刃·循迹"),
    4: ("第四赛区", "铸剑·止戈"),
}
_STAGE_FALLBACK_FIELDS: tuple[str, ...] = ("title", "description", "mode", "summary", "content", "category", "tags")
_STAGE_REGEXES: tuple[str, ...] = (
    r"(?:zone|stage|track|level)\s*[-_ ]?\s*([1-4])",
    r"第\s*([一二三四1234])\s*(?:赛区|阶段|关卡)",
    r"(?:赛区|阶段|关卡)\s*([一二三四1234])",
)


def _serialize_runtime_result_payload(result: Any) -> dict[str, Any]:
    return {
        "final_output": str(getattr(result, "final_output", "") or ""),
        "flag": getattr(result, "flag", None),
        "steps_taken": int(getattr(result, "steps_taken", 0) or 0),
        "workspace": str(getattr(result, "workspace", "") or ""),
        "log_path": str(getattr(result, "log_path", "") or ""),
        "runtime_id": getattr(result, "runtime_id", None),
        "agent_id": getattr(result, "agent_id", None),
        "flags": list(getattr(result, "flags", []) or []),
        "candidate_flags": list(getattr(result, "candidate_flags", []) or []),
    }


def _run_runtime_attempt_worker(payload: dict[str, Any], result_queue: Any) -> None:
    runtime: Runtime | None = None

    def _emit(message: dict[str, Any]) -> None:
        try:
            result_queue.put(message)
        except Exception:
            pass

    def _handle_termination(signum: int, _frame: Any) -> None:
        nonlocal runtime
        if runtime is not None:
            try:
                runtime.cleanup()
            except Exception:
                pass
        raise SystemExit(128 + int(signum))

    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _handle_termination)
        except Exception:
            pass

    client_payload = payload.get("challenge_client") if isinstance(payload, dict) else None
    challenge_client = None
    if isinstance(client_payload, dict):
        challenge_client = ChallengePlatformClient(
            server_host=client_payload.get("server_host"),
            mcp_url=client_payload.get("mcp_url"),
            agent_token=client_payload.get("agent_token"),
            min_interval=float(client_payload.get("min_interval") or 0.4),
            max_retries=int(client_payload.get("max_retries") or 0),
            retry_backoff=float(client_payload.get("retry_backoff") or 1.5),
            request_timeout=client_payload.get("request_timeout"),
            sse_read_timeout=client_payload.get("sse_read_timeout"),
            tool_timeout=client_payload.get("tool_timeout"),
        )

    try:
        runtime = Runtime(
            workspace=Path(str(payload["workspace"])),
            max_steps=int(payload.get("max_steps") or 0) or None,
            browser_port=None,
            challenge_client=challenge_client,
            stop_on_flag_text=bool(payload.get("stop_on_flag_text", False)),
            challenge_mode=str(payload.get("challenge_mode") or CHALLENGE_MODE_SINGLE_FLAG),
        )
        forced_runtime_id = str(payload.get("runtime_id") or "").strip()
        if forced_runtime_id:
            runtime.runtime_id = forced_runtime_id
        result = runtime.run(str(payload.get("task") or ""))
        _emit({"status": "ok", "result": _serialize_runtime_result_payload(result)})
    except BaseException as exc:
        _emit(
            {
                "status": "error",
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        if runtime is not None:
            try:
                runtime.cleanup()
            except Exception:
                pass


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _stage_token_to_int(token: str) -> int | None:
    normalized = str(token).strip()
    chinese_digits = {"一": 1, "二": 2, "三": 3, "四": 4}
    if normalized in chinese_digits:
        return chinese_digits[normalized]
    if normalized in {"1", "2", "3", "4"}:
        return int(normalized)
    return None


def _flatten_stage_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for nested_value in value.values():
            values.extend(_flatten_stage_value(nested_value))
        return values
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for nested_value in value:
            values.extend(_flatten_stage_value(nested_value))
        return values
    text = str(value).strip()
    return [text] if text else []


def _extract_stage_number_from_value(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        stage_number = int(value)
        return stage_number if stage_number in {1, 2, 3, 4} else None

    text = str(value).strip().lower()
    if text in {"1", "2", "3", "4"}:
        return int(text)

    demo_match = re.search(r"\bdemo\s*([1-4])\b|\bdemo([1-4])\b", text, flags=re.IGNORECASE)
    if demo_match is not None:
        token = demo_match.group(1) or demo_match.group(2)
        if token is not None:
            return int(token)

    for stage_number, markers in _NAMED_STAGE_MARKERS.items():
        if any(marker.lower() in text for marker in markers):
            return stage_number

    for pattern in _STAGE_REGEXES:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match is None:
            continue
        stage_number = _stage_token_to_int(match.group(1))
        if stage_number is not None:
            return stage_number
    return None


def _extract_stage_number_from_challenge(challenge: dict[str, Any]) -> int | None:
    """Best-effort stage detection for the main battlefield.

    This intentionally mirrors the field priority used by the runtime mode
    resolver while staying local to this module, so the orchestrator can be
    tested independently and does not introduce a circular dependency.
    """

    if not isinstance(challenge, dict):
        return None

    for key in ("stage", "zone", "track", "level"):
        stage_number = _extract_stage_number_from_value(challenge.get(key))
        if stage_number is not None:
            return stage_number

    for key in _STAGE_FALLBACK_FIELDS:
        for candidate in _flatten_stage_value(challenge.get(key)):
            stage_number = _extract_stage_number_from_value(candidate)
            if stage_number is not None:
                return stage_number
    return None


def _group_challenges_by_stage(challenges: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for challenge in challenges:
        stage_number = _extract_stage_number_from_challenge(challenge)
        if stage_number is None:
            continue
        grouped.setdefault(stage_number, []).append(challenge)
    return {stage_number: grouped[stage_number] for stage_number in sorted(grouped)}


def _challenge_is_fully_solved(challenge: dict[str, Any]) -> bool:
    if not isinstance(challenge, dict):
        return False

    flag_got_count = _coerce_int(challenge.get("flag_got_count"))
    flag_count = _coerce_int(challenge.get("flag_count"))
    if flag_got_count is not None and flag_count is not None:
        return flag_count > 0 and flag_got_count >= flag_count

    if challenge.get("solved") is True or challenge.get("completed") is True:
        return True

    status = str(challenge.get("status", "")).strip().lower()
    return status in {"solved", "completed", "finished"}


def _calculate_stage_progress(challenges: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Aggregate visible-stage progress without pretending unlock succeeded.

    `stage_completed_by_threshold` means the visible flag counts meet the
    theoretical unlock threshold for that stage. `unlocked_next_stage` is
    stricter: it is true only when `list_challenges()` already shows the next
    stage's challenges, because the platform response is authoritative.
    """

    grouped = _group_challenges_by_stage(challenges)
    visible_stages = set(grouped)
    all_stages = sorted(set(grouped) | set(MAIN_BATTLEFIELD_STAGE_THRESHOLDS) | {4})

    progress: dict[int, dict[str, Any]] = {}
    for stage_number in all_stages:
        stage_challenges = grouped.get(stage_number, [])
        total_flag_got_count = sum(_coerce_int(item.get("flag_got_count")) or 0 for item in stage_challenges)
        total_flag_count = sum(_coerce_int(item.get("flag_count")) or 0 for item in stage_challenges)
        unlock_threshold = MAIN_BATTLEFIELD_STAGE_THRESHOLDS.get(stage_number)
        progress[stage_number] = {
            "stage": stage_number,
            "visible_challenges_count": len(stage_challenges),
            "fully_solved_challenges_count": sum(1 for item in stage_challenges if _challenge_is_fully_solved(item)),
            "total_flag_got_count": total_flag_got_count,
            "total_flag_count": total_flag_count,
            "unlock_threshold": unlock_threshold,
            "unlocked_next_stage": False,
            "stage_completed_by_threshold": (
                total_flag_got_count >= unlock_threshold if unlock_threshold is not None else None
            ),
        }

    for stage_number, snapshot in progress.items():
        next_stage = stage_number + 1
        snapshot["unlocked_next_stage"] = next_stage in visible_stages if stage_number < 4 else False

    return progress


def _detect_newly_visible_stages(previous_visible: set[int], current_visible: set[int]) -> list[int]:
    return sorted(stage_number for stage_number in current_visible if stage_number not in previous_visible)


def _serialize_stage_progress(progress: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(progress[stage_number]) for stage_number in sorted(progress)]


def _resolve_current_stage(progress: dict[int, dict[str, Any]]) -> int | None:
    visible_stages = [
        stage_number
        for stage_number, snapshot in progress.items()
        if (_coerce_int(snapshot.get("visible_challenges_count")) or 0) > 0
    ]
    if not visible_stages:
        return None
    return max(visible_stages)


@dataclass(slots=True)
class ChallengeAttemptSummary:
    attempt: int
    with_hint: bool
    status: str
    workspace: str
    runtime_id: str | None = None
    agent_id: str | None = None
    step_budget: int | None = None
    current_runtime_step: int | None = None
    steps_taken: int | None = None
    runtime_log_path: str | None = None
    final_output_preview: str | None = None
    extracted_flag: str | None = None
    found_flags: list[str] = field(default_factory=list)
    candidate_flags_high_confidence: list[dict[str, Any]] = field(default_factory=list)
    candidate_flags_low_confidence: list[dict[str, Any]] = field(default_factory=list)
    submitted_flag_results: list[dict[str, Any]] = field(default_factory=list)
    submitted_progress: dict[str, Any] = field(default_factory=dict)
    progress_made: bool = False
    progress_note: str | None = None
    evidence_summary: str | None = None
    known_hosts: list[str] = field(default_factory=list)
    known_creds: list[str] = field(default_factory=list)
    known_pivots: list[str] = field(default_factory=list)
    extracted_artifacts_count: int = 0
    recommended_skills: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class ChallengeRunSummary:
    index: int
    code: str
    title: str
    challenge_mode: str
    used_hint: bool
    solved: bool
    gave_up: bool
    challenge_worker_id: str | None = None
    attempt1: ChallengeAttemptSummary | None = None
    attempt2: ChallengeAttemptSummary | None = None
    attempts: list[ChallengeAttemptSummary] = field(default_factory=list)
    attempts_used: int = 0
    total_steps_used: int = 0
    final_platform_progress: dict[str, Any] = field(default_factory=dict)
    platform_progress_history: list[dict[str, Any]] = field(default_factory=list)
    known_submitted_flags: list[str] = field(default_factory=list)
    candidate_flags_high_confidence: list[dict[str, Any]] = field(default_factory=list)
    candidate_flags_low_confidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_summary: str | None = None
    known_hosts: list[str] = field(default_factory=list)
    known_creds: list[str] = field(default_factory=list)
    known_pivots: list[str] = field(default_factory=list)
    extracted_artifacts_count: int = 0
    recommended_skills: list[str] = field(default_factory=list)
    no_progress_attempts: int = 0
    latest_attempt_workspace: str | None = None
    workspaces: dict[str, str] = field(default_factory=dict)
    entrypoints: list[str] = field(default_factory=list)
    stop_result: dict[str, Any] | None = None
    error: str | None = None


class HackathonOrchestrator:
    """Run official hackathon challenges with isolated per-challenge runtimes.

    single_flag is for the first/second zones and keeps the two-attempt flow.
    multi_flag_campaign is for the third/fourth zones and keeps retrying with
    fresh runtimes so context does not explode while multi-stage progress
    continues across the same challenge instance.
    """

    def __init__(
        self,
        *,
        workspace: Path,
        max_steps: int | None,
        browser_port: int | None = None,
        only_codes: list[str] | None = None,
        skip_codes: list[str] | None = None,
        max_attempts_single_flag: int = 2,
        max_attempts_multi_flag: int = 4,
        campaign_total_step_budget: int | None = None,
        campaign_no_progress_attempt_limit: int = 2,
        hint_after_attempt: int = 1,
        hint_policy_mode: str = "default",
        max_concurrent_challenges: int = 3,
    ) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.requested_max_steps = max_steps
        self.max_steps = resolve_runtime_max_steps(max_steps)
        self.browser_port = browser_port
        self.only_codes = [code for code in (only_codes or []) if code]
        self.skip_codes = [code for code in (skip_codes or []) if code]
        self.max_attempts_single_flag = max(int(max_attempts_single_flag), 1)
        self.max_attempts_multi_flag = max(int(max_attempts_multi_flag), 1)
        self.campaign_total_step_budget = (
            max(int(campaign_total_step_budget), 1) if campaign_total_step_budget is not None else None
        )
        self.campaign_no_progress_attempt_limit = max(int(campaign_no_progress_attempt_limit), 1)
        self.hint_after_attempt = max(int(hint_after_attempt), 1)
        self.hint_policy_mode = str(hint_policy_mode or "default").strip().lower() or "default"
        self.max_concurrent_challenges = min(max(int(max_concurrent_challenges), 1), 3)
        self._io_lock = threading.RLock()
        self._live_challenge_states: dict[str, dict[str, Any]] = {}
        self.challenge_client = ChallengePlatformClient()
        self.challenge_client.ensure_configured()

        self.hackathon_dir = self.workspace / "hackathon"
        self._ensure_hackathon_dir()
        self.orchestrator_log_path = self.hackathon_dir / "orchestrator.jsonl"
        self.summary_path = self.hackathon_dir / "summary.json"
        self.skill_manager = SkillManager(
            skills_root=SKILLS_DIR,
            workspace=self.workspace,
            event_logger=self._log,
        )
        try:
            self.skill_manager.refresh_index()
        except Exception as exc:
            self._log("skills_index_error", {"message": str(exc), "traceback": traceback.format_exc()})

        self._log(
            "orchestrator_initialized",
            {
                "workspace": str(self.workspace),
                "hackathon_dir": str(self.hackathon_dir),
                "max_steps": self.max_steps,
                "browser_port": self.browser_port,
                "only_codes": self.only_codes,
                "skip_codes": self.skip_codes,
                "mcp_url": self.challenge_client.mcp_url,
                "max_attempts_single_flag": self.max_attempts_single_flag,
                "max_attempts_multi_flag": self.max_attempts_multi_flag,
                "campaign_total_step_budget": self.campaign_total_step_budget,
                "campaign_no_progress_attempt_limit": self.campaign_no_progress_attempt_limit,
                "hint_after_attempt": self.hint_after_attempt,
                "hint_policy_mode": self.hint_policy_mode,
                "max_concurrent_challenges": self.max_concurrent_challenges,
                "skills_root": str(self.skill_manager.skills_root),
            },
        )

    def _ensure_hackathon_dir(self) -> None:
        self.hackathon_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _resolve_attempt_hard_timeout_seconds(runtime_max_steps: int) -> float:
        env_value = (os.getenv("CTF_ATTEMPT_HARD_TIMEOUT_SECONDS") or "").strip()
        if env_value:
            try:
                resolved = float(env_value)
            except ValueError:
                resolved = 0.0
            if resolved > 0:
                return resolved
        return max(float(max(int(runtime_max_steps), 1)) * 60.0, 900.0)


    @staticmethod
    def _resolve_attempt_idle_timeout_seconds(runtime_max_steps: int) -> float:
        env_value = (os.getenv("CTF_ATTEMPT_IDLE_TIMEOUT_SECONDS") or "").strip()
        if env_value:
            try:
                resolved = float(env_value)
            except ValueError:
                resolved = 0.0
            if resolved > 0:
                return resolved
        # Keep this above the per-step LLM hard timeout (default ~135s) while
        # still recovering from deadlocked attempts in a few minutes rather than
        # appearing stuck for a long time.
        return max(min(float(max(int(runtime_max_steps), 1)) * 6.0, 180.0), 150.0)

    @staticmethod
    def _runtime_worker_context_name() -> str:
        override = (os.getenv("CTF_RUNTIME_MP_START_METHOD") or "").strip().lower()
        available_methods = set(multiprocessing.get_all_start_methods())
        if override in available_methods:
            return override
        if "spawn" in available_methods:
            return "spawn"
        if "forkserver" in available_methods:
            return "forkserver"
        if "fork" in available_methods:
            return "fork"
        return multiprocessing.get_start_method()

    @staticmethod
    def _read_process_queue_payload(result_queue: Any) -> dict[str, Any]:
        get_nowait = getattr(result_queue, "get_nowait", None)
        if callable(get_nowait):
            return get_nowait()

        empty_fn = getattr(result_queue, "empty", None)
        if callable(empty_fn):
            try:
                if empty_fn():
                    raise Empty
            except Empty:
                raise
            except Exception:
                pass

        get_fn = getattr(result_queue, "get", None)
        if not callable(get_fn):
            raise Empty

        try:
            return get_fn(timeout=0)
        except TypeError:
            pass
        except Empty:
            raise

        try:
            return get_fn(False)
        except TypeError:
            pass
        except Empty:
            raise

        return get_fn()

    def _build_runtime_worker_payload(self, *, runtime: Runtime, task: str) -> dict[str, Any]:
        client_payload: dict[str, Any] | None = None
        if self.challenge_client is not None:
            client_payload = {
                "server_host": self.challenge_client.server_host,
                "mcp_url": self.challenge_client.mcp_url,
                "agent_token": self.challenge_client.agent_token,
                "min_interval": self.challenge_client.min_interval,
                "max_retries": self.challenge_client.max_retries,
                "retry_backoff": self.challenge_client.retry_backoff,
                "request_timeout": self.challenge_client.request_timeout,
                "sse_read_timeout": self.challenge_client.sse_read_timeout,
                "tool_timeout": self.challenge_client.tool_timeout,
            }
        return {
            "workspace": str(runtime.workspace),
            "max_steps": runtime.max_steps,
            "stop_on_flag_text": runtime.stop_on_flag_text,
            "challenge_mode": runtime.challenge_mode,
            "runtime_id": runtime.runtime_id,
            "task": task,
            "challenge_client": client_payload,
        }

    @staticmethod
    def _resolve_runtime_retry_limit() -> int:
        env_value = (os.getenv("CTF_RUNTIME_RETRY_LIMIT") or "").strip()
        if not env_value:
            return 2
        try:
            resolved = int(env_value)
        except ValueError:
            return 2
        return max(resolved, 0)

    @staticmethod
    def _runtime_retry_delay_seconds(retry_attempt: int) -> float:
        return min(3.0 * (2 ** max(retry_attempt, 0)), 20.0)

    @staticmethod
    def _is_retryable_runtime_error(exc: Exception | str) -> bool:
        message = str(exc).lower()
        retry_markers = (
            "502 bad gateway",
            "503",
            "504",
            "gateway timeout",
            "service unavailable",
            "internal server error",
            "temporarily unavailable",
            "temporary failure",
            "connection reset",
            "connection aborted",
            "connection refused",
            "server disconnected",
            "read timed out",
            "timed out",
            "timeout",
            "rate limit",
            "too many requests",
            "429",
            "overloaded",
            "resource exhausted",
            "remoteprotocolerror",
            "apiconnectionerror",
            "apitimeouterror",
            "runtime attempt exceeded watchdog timeout",
            "potential multiprocessing deadlock",
        )
        return any(marker in message for marker in retry_markers)

    @staticmethod
    def _extract_runtime_progress_from_log(log_path: Path) -> int | None:
        if not log_path.exists():
            return None
        last_step: int | None = None
        try:
            with log_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    payload = record.get("payload") if isinstance(record, dict) else None
                    if not isinstance(payload, dict):
                        continue
                    for key in ("step", "steps_taken", "current_runtime_step"):
                        value = payload.get(key)
                        if value is None:
                            continue
                        try:
                            candidate = int(value)
                        except (TypeError, ValueError):
                            continue
                        last_step = candidate
        except Exception:
            return last_step
        return last_step

    def _run_runtime_with_watchdog(
        self,
        *,
        runtime: Runtime,
        task: str,
        runtime_max_steps: int,
    ) -> Any:
        timeout_seconds = self._resolve_attempt_hard_timeout_seconds(runtime_max_steps)
        idle_timeout_seconds = self._resolve_attempt_idle_timeout_seconds(runtime_max_steps)

        ctx = multiprocessing.get_context(self._runtime_worker_context_name())
        queue_factory = getattr(ctx, "SimpleQueue", None)
        if callable(queue_factory):
            result_queue = queue_factory()
        else:
            result_queue = ctx.Queue()

        worker_payload = self._build_runtime_worker_payload(runtime=runtime, task=task)
        process = ctx.Process(
            target=_run_runtime_attempt_worker,
            args=(worker_payload, result_queue),
            name=f"runtime-attempt-{runtime.runtime_id}",
        )
        process.daemon = True

        start_error: list[BaseException] = []

        def _start_proc() -> None:
            try:
                process.start()
            except BaseException as exc:  # pragma: no cover
                start_error.append(exc)

        starter = threading.Thread(target=_start_proc, daemon=True)
        starter.start()
        starter.join(timeout=min(10.0, float(timeout_seconds)))
        if starter.is_alive():
            raise TimeoutError(
                "Runtime worker process failed to start in time (potential multiprocessing deadlock)."
            )
        if start_error:
            raise RuntimeError(f"Failed to start runtime worker process: {start_error[0]}")

        started_at = time.monotonic()
        last_activity_at = started_at
        last_log_mtime: float | None = None
        last_observed_step = 0
        timeout_reason: str | None = None
        timeout_message: str | None = None

        while process.is_alive():
            process.join(timeout=1.0)
            now = time.monotonic()
            if not process.is_alive():
                break

            try:
                if runtime.log_path.exists():
                    current_mtime = runtime.log_path.stat().st_mtime
                    if last_log_mtime is None or current_mtime > last_log_mtime:
                        last_log_mtime = current_mtime
                        last_activity_at = now
                observed_step = self._extract_runtime_progress_from_log(runtime.log_path)
                if observed_step is not None and observed_step > last_observed_step:
                    last_observed_step = observed_step
                    last_activity_at = now
            except Exception:
                pass

            total_elapsed = now - started_at
            idle_elapsed = now - last_activity_at
            if total_elapsed >= timeout_seconds:
                timeout_reason = "total_timeout"
                timeout_message = f"Runtime attempt exceeded watchdog timeout after {timeout_seconds:.1f} seconds."
                break
            if idle_elapsed >= idle_timeout_seconds:
                timeout_reason = "idle_timeout"
                timeout_message = (
                    f"Runtime attempt produced no new log/progress activity for {idle_timeout_seconds:.1f} seconds."
                )
                break

        try:
            if process.is_alive():
                self._log(
                    "attempt_timeout",
                    {
                        "runtime_id": runtime.runtime_id,
                        "agent_id": runtime.active_agent_id,
                        "workspace": str(runtime.workspace),
                        "runtime_log_path": str(runtime.log_path),
                        "watchdog_timeout_seconds": timeout_seconds,
                        "idle_timeout_seconds": idle_timeout_seconds,
                        "reason": timeout_reason,
                        "duration_seconds": round(time.monotonic() - started_at, 3),
                        "observed_step": last_observed_step or None,
                    },
                )
                process.terminate()
                process.join(timeout=5.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=2.0)
                try:
                    runtime._write_state(
                        {
                            **runtime._read_state(),
                            "status": "timed_out",
                            "runtime_id": runtime.runtime_id,
                            "agent_id": runtime.active_agent_id,
                            "updated_at": runtime._timestamp(),
                        }
                    )
                except Exception:
                    pass
                raise TimeoutError(timeout_message or "Runtime attempt timed out.")

            try:
                payload = self._read_process_queue_payload(result_queue)
            except Empty as exc:
                raise RuntimeError(
                    f"Runtime worker exited with code {process.exitcode} without returning a result."
                ) from exc
        finally:
            try:
                close = getattr(result_queue, "close", None)
                if callable(close):
                    close()
            finally:
                join_thread = getattr(result_queue, "join_thread", None)
                if callable(join_thread):
                    join_thread()

        if payload.get("status") == "error":
            message = str(payload.get("message") or "runtime attempt failed")
            worker_traceback = str(payload.get("traceback") or "").strip()
            if worker_traceback:
                raise RuntimeError(f"{message}\n{worker_traceback}")
            raise RuntimeError(message)

        result_payload = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(result_payload, dict):
            raise RuntimeError("Runtime worker returned an invalid result payload.")

        return SimpleNamespace(**result_payload)

    def _load_resume_state(self) -> dict[str, Any]:
        """Load minimal resume metadata from previous runs.

        This is intentionally conservative: we only mark a challenge as
        "processed" when it is clearly finished (solved or gave_up) in a
        persisted checkpoint/summary. This prevents repeating the same challenge
        after a crash/restart while still allowing unfinished challenges to
        retry.
        """

        processed_codes: list[str] = []
        seen_codes: list[str] = []
        source: str | None = None

        # 1) Prefer summary.json if present.
        if self.summary_path.exists():
            try:
                raw = json.loads(self.summary_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    source = "summary.json"
                    processed_codes = [str(code).strip() for code in raw.get("processed_codes", []) if str(code).strip()]
                    seen_codes = [str(code).strip() for code in raw.get("seen_codes", []) if str(code).strip()]
            except Exception as exc:
                self._log(
                    "orchestrator_resume_read_error",
                    {"path": str(self.summary_path), "message": str(exc), "traceback": traceback.format_exc()},
                )

        processed_set = set(processed_codes)

        # 2) Merge in completed checkpoints (solved/gave_up) even if summary is stale.
        try:
            for entry in self.hackathon_dir.iterdir():
                if not entry.is_dir():
                    continue
                checkpoint_path = entry / "checkpoint.json"
                if not checkpoint_path.exists():
                    continue
                try:
                    payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                except Exception:
                    self._log(
                        "orchestrator_resume_checkpoint_parse_error",
                        {"path": str(checkpoint_path), "traceback": traceback.format_exc()},
                    )
                    continue

                if not isinstance(payload, dict):
                    continue

                code = str(payload.get("challenge_code", "")).strip()
                if not code:
                    continue

                if payload.get("solved") is True or payload.get("gave_up") is True:
                    if code not in processed_set:
                        processed_set.add(code)
                        processed_codes.append(code)
                    if code and code not in seen_codes:
                        seen_codes.append(code)
        except Exception as exc:
            self._log(
                "orchestrator_resume_checkpoint_scan_error",
                {"message": str(exc), "traceback": traceback.format_exc()},
            )

        # 3) Compute the next challenge index based on existing challenge roots.
        next_index = 1
        indices: list[int] = []
        for entry in self.hackathon_dir.iterdir():
            if not entry.is_dir():
                continue
            match = re.match(r"^(\d{4})_", entry.name)
            if match:
                try:
                    indices.append(int(match.group(1)))
                except ValueError:
                    continue
        if indices:
            next_index = max(indices) + 1

        return {
            "processed_codes": processed_codes,
            "seen_codes": seen_codes,
            "next_challenge_index": next_index,
            "source": source or "checkpoint_scan",
        }

    def run(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "generated_at": self._timestamp(),
            "last_updated_at": self._timestamp(),
            "workspace": str(self.workspace),
            "hackathon_dir": str(self.hackathon_dir),
            "summary_path": str(self.summary_path),
            "orchestrator_log_path": str(self.orchestrator_log_path),
            "challenge_execution_mode": "parallel",
            "agent_execution_mode": "per_attempt_isolated_runtime_agent",
            "max_concurrent_challenges": self.max_concurrent_challenges,
            "max_concurrent_agents": self.max_concurrent_challenges,
            "total_visible": 0,
            "total_attempted": 0,
            "total_solved": 0,
            "total_give_up": 0,
            "challenge_summaries": [],
            "rounds": [],
            "stage_progress": [],
            "stage_progress_history": [],
            "processed_codes": [],
            "seen_codes": [],
            "unlocked_stage_history": [],
            "final_visible_codes": [],
            "final_current_stage": None,
            "challenges_in_progress": [],
            "challenge_checkpoints": {},
            "live_attempt_index": None,
            "current_runtime_step": None,
            "candidate_flags_summary": {},
        }
        # --- Resume support (prevents repeating the same challenge after a restart) ---
        resume_state = self._load_resume_state()
        processed_codes_in_order: list[str] = list(resume_state["processed_codes"])
        processed_codes: set[str] = set(processed_codes_in_order)
        seen_codes_in_order: list[str] = list(resume_state["seen_codes"])
        seen_codes: set[str] = set(seen_codes_in_order)
        challenge_index = int(resume_state["next_challenge_index"])
        self._log(
            "orchestrator_resume_state",
            {
                "processed_codes": processed_codes_in_order,
                "seen_codes_count": len(seen_codes_in_order),
                "next_challenge_index": challenge_index,
                "resume_source": resume_state.get("source"),
            },
        )
        self._write_live_summary(summary)
        previous_visible_stages: set[int] = set()
        threshold_logged_stages: set[int] = set()
        round_index = 0

        while True:
            round_index += 1
            challenges_payload = self.challenge_client.list_challenges()
            visible_challenges = self.challenge_client.extract_challenges(challenges_payload)
            visible_codes = self._collect_challenge_codes(visible_challenges)

            stage_progress = _calculate_stage_progress(visible_challenges)
            serialized_stage_progress = _serialize_stage_progress(stage_progress)
            visible_stages = {
                stage_number
                for stage_number, snapshot in stage_progress.items()
                if (_coerce_int(snapshot.get("visible_challenges_count")) or 0) > 0
            }
            newly_visible_stages = (
                _detect_newly_visible_stages(previous_visible_stages, visible_stages) if round_index > 1 else []
            )
            new_codes = [code for code in visible_codes if code not in seen_codes]
            for code in new_codes:
                seen_codes.add(code)
                seen_codes_in_order.append(code)
                self._log(
                    "challenge_discovered",
                    {
                        "round_index": round_index,
                        "code": code,
                        "visible_codes": visible_codes,
                    },
                )

            pending_challenges, filter_details = self._filter_challenges_with_details(visible_challenges)
            attemptable_challenges: list[dict[str, Any]] = []
            already_processed_codes: list[str] = []
            for challenge in pending_challenges:
                code = str(challenge.get("code", "")).strip()
                if code in processed_codes:
                    already_processed_codes.append(code)
                    self._log(
                        "challenge_already_processed_skip",
                        {
                            "round_index": round_index,
                            "code": code,
                            "title": challenge.get("title"),
                        },
                    )
                    continue
                attemptable_challenges.append(challenge)

            if round_index == 1:
                self._log(
                    "challenges_loaded",
                    {
                        "total_visible": len(visible_challenges),
                        "total_attempted": len(attemptable_challenges),
                        "visible_codes": visible_codes,
                        "attempt_codes": [challenge.get("code") for challenge in attemptable_challenges],
                    },
                )
                self._update_summary_state(
                    summary=summary,
                    visible_challenges=visible_challenges,
                    stage_progress=stage_progress,
                    processed_codes=processed_codes_in_order,
                    seen_codes=seen_codes_in_order,
                    round_index=round_index,
                )
                self._write_live_summary(summary)

            for stage_number in sorted(stage_progress):
                snapshot = stage_progress[stage_number]
                if not snapshot.get("stage_completed_by_threshold"):
                    continue
                if stage_number in threshold_logged_stages:
                    continue
                threshold_logged_stages.add(stage_number)
                self._log(
                    "unlock_threshold_reached",
                    {
                        "round_index": round_index,
                        **snapshot,
                    },
                )

            if newly_visible_stages:
                event_payload = {
                    "round_index": round_index,
                    "newly_visible_stages": newly_visible_stages,
                    "visible_codes": visible_codes,
                }
                self._log("new_stage_visible", event_payload)
                with self._io_lock:
                    summary["unlocked_stage_history"].append(event_payload)

            stage_progress_payload = {
                "round_index": round_index,
                "stages": serialized_stage_progress,
            }
            self._log("stage_progress_snapshot", stage_progress_payload)

            round_record: dict[str, Any] = {
                "round_index": round_index,
                "visible_codes": visible_codes,
                "new_codes": new_codes,
                "attempted_codes": [str(challenge.get("code", "")).strip() for challenge in attemptable_challenges],
                "skipped_solved_codes": filter_details["skipped_solved_codes"],
                "already_processed_codes": already_processed_codes,
                "stage_progress_snapshot": serialized_stage_progress,
                "newly_unlocked_stages": newly_visible_stages,
                "challenge_execution_mode": "parallel",
                "max_concurrent_challenges": self.max_concurrent_challenges,
            }
            self._log(
                "orchestrator_round_begin",
                {
                    "round_index": round_index,
                    "visible_codes": visible_codes,
                    "new_codes": new_codes,
                    "attemptable_codes": [challenge.get("code") for challenge in attemptable_challenges],
                    "already_processed_codes": already_processed_codes,
                    "skipped_solved_codes": filter_details["skipped_solved_codes"],
                    "newly_unlocked_stages": newly_visible_stages,
                    "challenge_execution_mode": "parallel",
                    "max_concurrent_challenges": self.max_concurrent_challenges,
                },
            )

            challenge_summaries = self._run_challenges_concurrently(
                challenge_index_start=challenge_index,
                challenges=attemptable_challenges,
                orchestrator_summary=summary,
            )
            for challenge_summary in challenge_summaries:
                code = str(challenge_summary.code).strip()
                with self._io_lock:
                    summary["challenge_summaries"].append(asdict(challenge_summary))
                    if code and code not in processed_codes:
                        processed_codes.add(code)
                        processed_codes_in_order.append(code)
                    self._update_summary_state(
                        summary=summary,
                        visible_challenges=visible_challenges,
                        stage_progress=stage_progress,
                        processed_codes=processed_codes_in_order,
                        seen_codes=seen_codes_in_order,
                        round_index=round_index,
                    )
                    self._write_live_summary(summary)
            challenge_index += len(challenge_summaries)

            with self._io_lock:
                summary["rounds"].append(round_record)
                summary["stage_progress_history"].append(stage_progress_payload)
            self._update_summary_state(
                summary=summary,
                visible_challenges=visible_challenges,
                stage_progress=stage_progress,
                processed_codes=processed_codes_in_order,
                seen_codes=seen_codes_in_order,
                round_index=round_index,
            )

            if not attemptable_challenges:
                break_payload = {
                    "round_index": round_index,
                    "visible_codes": visible_codes,
                    "already_processed_codes": already_processed_codes,
                    "stage_progress_snapshot": serialized_stage_progress,
                    "reason": "no_unprocessed_visible_challenges",
                }
                self._log("no_more_progress_break", break_payload)
                self._log(
                    "orchestrator_round_end",
                    {
                        "round_index": round_index,
                        "attempted_codes": round_record["attempted_codes"],
                        "newly_unlocked_stages": newly_visible_stages,
                        "break_reason": break_payload["reason"],
                    },
                )
                self._write_live_summary(summary)
                break

            self._log(
                "orchestrator_round_end",
                {
                    "round_index": round_index,
                    "attempted_codes": round_record["attempted_codes"],
                    "newly_unlocked_stages": newly_visible_stages,
                    "break_reason": None,
                },
            )
            self._write_live_summary(summary)
            previous_visible_stages = visible_stages

        self._log("orchestrator_finished", summary)
        self._write_live_summary(summary)
        return summary

    def _run_challenges_concurrently(
        self,
        challenge_index_start: int,
        challenges: list[dict[str, Any]],
        orchestrator_summary: dict[str, Any] | None = None,
    ) -> list[ChallengeRunSummary]:
        """Run one round's visible challenges with a bounded per-challenge worker pool.

        The returned summaries always preserve the input order, even if worker
        futures finish out of order. Per-challenge failures are converted into
        fallback summaries so one bad runtime does not collapse the whole round.
        """

        if not challenges:
            return []

        ordered_results: list[ChallengeRunSummary | None] = [None] * len(challenges)
        future_map: dict[Future[ChallengeRunSummary], tuple[int, int, dict[str, Any], str]] = {}

        with ThreadPoolExecutor(max_workers=self.max_concurrent_challenges) as executor:
            for position, challenge in enumerate(challenges):
                challenge_index = challenge_index_start + position
                code = str(challenge.get("code", "")).strip()
                self._log(
                    "challenge_future_submitted",
                    {
                        "position": position,
                        "index": challenge_index,
                        "code": code,
                        "title": challenge.get("title"),
                        "max_concurrent_challenges": self.max_concurrent_challenges,
                    },
                )
                future = executor.submit(
                    self._run_single_challenge,
                    challenge_index,
                    challenge,
                    orchestrator_summary=orchestrator_summary,
                )
                future_map[future] = (position, challenge_index, challenge, code)

            for future in as_completed(future_map):
                position, challenge_index, challenge, code = future_map[future]
                try:
                    ordered_results[position] = future.result()
                except Exception as exc:
                    title = str(challenge.get("title", "")).strip() or code or f"challenge-{challenge_index}"
                    ordered_results[position] = self._build_fallback_summary(
                        challenge_index,
                        code,
                        title,
                        challenge,
                        exc,
                    )
                    self._log(
                        "challenge_unhandled_error",
                        {
                            "index": challenge_index,
                            "code": code,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                    )

        fallback_error = RuntimeError("Challenge future finished without producing a summary.")
        finalized_results: list[ChallengeRunSummary] = []
        for position, challenge in enumerate(challenges):
            challenge_index = challenge_index_start + position
            code = str(challenge.get("code", "")).strip()
            result = ordered_results[position]
            if result is None:
                title = str(challenge.get("title", "")).strip() or code or f"challenge-{challenge_index}"
                result = self._build_fallback_summary(
                    challenge_index,
                    code,
                    title,
                    challenge,
                    fallback_error,
                )
            finalized_results.append(result)
        return finalized_results

    def _filter_challenges(self, challenges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered, _details = self._filter_challenges_with_details(challenges)
        return filtered

    def _filter_challenges_with_details(
        self,
        challenges: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
        filtered: list[dict[str, Any]] = []
        only_codes = set(self.only_codes)
        skip_codes = set(self.skip_codes)
        details = {
            "skipped_solved_codes": [],
            "skipped_only_codes": [],
            "skipped_skip_codes": [],
            "invalid_codes": [],
        }

        for challenge in challenges:
            code = str(challenge.get("code", "")).strip()
            if not code:
                self._log("challenge_skip_invalid", {"challenge": challenge})
                details["invalid_codes"].append(code)
                continue

            if self.challenge_client.is_challenge_fully_solved(challenge):
                self._log("challenge_skip_solved", {"code": code, "title": challenge.get("title")})
                details["skipped_solved_codes"].append(code)
                continue
            if only_codes and code not in only_codes:
                self._log("challenge_skip_only_filter", {"code": code, "title": challenge.get("title")})
                details["skipped_only_codes"].append(code)
                continue
            if code in skip_codes:
                self._log("challenge_skip_skip_filter", {"code": code, "title": challenge.get("title")})
                details["skipped_skip_codes"].append(code)
                continue

            filtered.append(challenge)
        return filtered, details

    def _update_summary_state(
        self,
        *,
        summary: dict[str, Any],
        visible_challenges: list[dict[str, Any]],
        stage_progress: dict[int, dict[str, Any]],
        processed_codes: list[str],
        seen_codes: list[str],
        round_index: int,
    ) -> None:
        with self._io_lock:
            summary["total_visible"] = len(visible_challenges)
            summary["total_attempted"] = len(summary["challenge_summaries"])
            summary["total_solved"] = sum(1 for item in summary["challenge_summaries"] if item.get("solved"))
            summary["total_give_up"] = sum(1 for item in summary["challenge_summaries"] if item.get("gave_up"))
            summary["stage_progress"] = _serialize_stage_progress(stage_progress)
            summary["processed_codes"] = list(processed_codes)
            summary["seen_codes"] = list(seen_codes)
            summary["final_visible_codes"] = self._collect_challenge_codes(visible_challenges)
            summary["final_current_stage"] = _resolve_current_stage(stage_progress)
            summary["round_count"] = round_index
            summary["last_updated_at"] = self._timestamp()

    def _write_live_summary(
        self,
        summary: dict[str, Any],
        *,
        active_challenge: ChallengeRunSummary | None = None,
        live_attempt_index: int | None = None,
        current_runtime_step: int | None = None,
        clear_active_code: str | None = None,
    ) -> None:
        with self._io_lock:
            summary["last_updated_at"] = self._timestamp()
            if active_challenge is not None and active_challenge.code:
                checkpoint_path = self._write_challenge_checkpoint(
                    active_challenge,
                    live_attempt_index=live_attempt_index,
                    current_runtime_step=current_runtime_step,
                )
                summary["challenge_checkpoints"][active_challenge.code] = checkpoint_path
                self._live_challenge_states[active_challenge.code] = self._serialize_active_challenge_state(
                    active_challenge,
                    checkpoint_path=checkpoint_path,
                    live_attempt_index=live_attempt_index,
                    current_runtime_step=current_runtime_step,
                )

            if clear_active_code:
                self._live_challenge_states.pop(clear_active_code, None)

            active_challenges = [
                dict(item)
                for _code, item in sorted(
                    self._live_challenge_states.items(),
                    key=lambda pair: (self._as_int(pair[1].get("index")) or 0, pair[0]),
                )
            ]
            summary["challenges_in_progress"] = active_challenges
            if len(active_challenges) == 1:
                summary["live_attempt_index"] = active_challenges[0].get("live_attempt_index")
                summary["current_runtime_step"] = active_challenges[0].get("current_runtime_step")
            else:
                summary["live_attempt_index"] = None
                summary["current_runtime_step"] = None
            summary["candidate_flags_summary"] = self._build_candidate_flag_summary(
                challenge_summaries=summary.get("challenge_summaries", []),
                active_challenges=active_challenges,
            )
            self._write_summary(summary)

    def _checkpoint_path(self, summary: ChallengeRunSummary) -> str:
        challenge_root = Path(summary.workspaces.get("challenge_root", self.hackathon_dir))
        return str(challenge_root / "checkpoint.json")

    @staticmethod
    def _build_challenge_worker_id(*, index: int, code: str) -> str:
        normalized_code = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(code or "challenge")).strip("_") or "challenge"
        return f"worker-{index:04d}-{normalized_code}-{uuid4().hex[:8]}"

    @staticmethod
    def _latest_attempt_runtime_id(summary: ChallengeRunSummary) -> str | None:
        if summary.attempts:
            return summary.attempts[-1].runtime_id
        if summary.attempt2 is not None and summary.attempt2.runtime_id:
            return summary.attempt2.runtime_id
        if summary.attempt1 is not None:
            return summary.attempt1.runtime_id
        return None

    @staticmethod
    def _latest_attempt_agent_id(summary: ChallengeRunSummary) -> str | None:
        if summary.attempts:
            return summary.attempts[-1].agent_id
        if summary.attempt2 is not None and summary.attempt2.agent_id:
            return summary.attempt2.agent_id
        if summary.attempt1 is not None:
            return summary.attempt1.agent_id
        return None

    def _serialize_active_challenge_state(
        self,
        summary: ChallengeRunSummary,
        *,
        checkpoint_path: str,
        live_attempt_index: int | None,
        current_runtime_step: int | None,
    ) -> dict[str, Any]:
        return {
            "index": summary.index,
            "code": summary.code,
            "title": summary.title,
            "challenge_mode": summary.challenge_mode,
            "challenge_worker_id": summary.challenge_worker_id,
            "attempts_used": summary.attempts_used,
            "used_hint": summary.used_hint,
            "latest_attempt_workspace": summary.latest_attempt_workspace,
            "latest_runtime_id": self._latest_attempt_runtime_id(summary),
            "latest_agent_id": self._latest_attempt_agent_id(summary),
            "checkpoint": checkpoint_path,
            "live_attempt_index": live_attempt_index,
            "current_runtime_step": current_runtime_step,
            "candidate_flags_high_confidence": list(summary.candidate_flags_high_confidence),
            "candidate_flags_low_confidence": list(summary.candidate_flags_low_confidence),
        }

    def _write_challenge_checkpoint(
        self,
        summary: ChallengeRunSummary,
        *,
        live_attempt_index: int | None,
        current_runtime_step: int | None,
    ) -> str:
        with self._io_lock:
            checkpoint_path = Path(self._checkpoint_path(summary))
            payload = {
                "challenge_code": summary.code,
                "challenge_title": summary.title,
                "challenge_mode": summary.challenge_mode,
                "challenge_worker_id": summary.challenge_worker_id,
                "attempts_used": summary.attempts_used,
                "used_hint": summary.used_hint,
                "solved": summary.solved,
                "gave_up": summary.gave_up,
                "last_platform_progress": summary.final_platform_progress,
                "known_submitted_flags": list(summary.known_submitted_flags),
                "candidate_flags_high_confidence": list(summary.candidate_flags_high_confidence),
                "candidate_flags_low_confidence": list(summary.candidate_flags_low_confidence),
                "evidence_summary": summary.evidence_summary,
                "latest_attempt_workspace": summary.latest_attempt_workspace,
                "latest_runtime_id": self._latest_attempt_runtime_id(summary),
                "latest_agent_id": self._latest_attempt_agent_id(summary),
                "live_attempt_index": live_attempt_index,
                "current_runtime_step": current_runtime_step,
                "recommended_skills": list(summary.recommended_skills),
                "attempts": [asdict(item) for item in summary.attempts],
                "updated_at": self._timestamp(),
            }
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            checkpoint_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            return str(checkpoint_path)

    def _build_candidate_flag_summary(
        self,
        *,
        challenge_summaries: list[dict[str, Any]],
        active_challenges: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        summary_payload: dict[str, Any] = {}
        for challenge in challenge_summaries:
            if not isinstance(challenge, dict):
                continue
            code = str(challenge.get("code", "")).strip()
            if not code:
                continue
            summary_payload[code] = {
                "high_confidence": list(challenge.get("candidate_flags_high_confidence", [])),
                "low_confidence": list(challenge.get("candidate_flags_low_confidence", [])),
            }
        for challenge in active_challenges or []:
            if not isinstance(challenge, dict):
                continue
            code = str(challenge.get("code", "")).strip()
            if not code:
                continue
            summary_payload[code] = {
                "high_confidence": list(challenge.get("candidate_flags_high_confidence", [])),
                "low_confidence": list(challenge.get("candidate_flags_low_confidence", [])),
            }
        return summary_payload

    @staticmethod
    def _collect_challenge_codes(challenges: list[dict[str, Any]]) -> list[str]:
        codes: list[str] = []
        seen_codes: set[str] = set()
        for challenge in challenges:
            code = str(challenge.get("code", "")).strip()
            if not code or code in seen_codes:
                continue
            seen_codes.add(code)
            codes.append(code)
        return codes

    def _run_single_challenge(
        self,
        index: int,
        challenge: dict[str, Any],
        *,
        orchestrator_summary: dict[str, Any] | None = None,
    ) -> ChallengeRunSummary:
        code = str(challenge.get("code", "")).strip()
        title = str(challenge.get("title", "")).strip() or code or f"challenge-{index}"
        challenge_mode = resolve_challenge_mode(challenge)
        challenge_root = self.hackathon_dir / f"{index:04d}_{self._safe_name(code or title)}"
        challenge_root.mkdir(parents=True, exist_ok=True)
        challenge_worker_id = self._build_challenge_worker_id(index=index, code=code or title)
        evidence_store = EvidenceStore(
            path=challenge_root / "evidence_store.json",
            challenge_code=code,
            event_logger=self._log,
        )
        recommended_skills = self._recommend_skills(challenge)

        summary = ChallengeRunSummary(
            index=index,
            code=code,
            title=title,
            challenge_mode=challenge_mode,
            challenge_worker_id=challenge_worker_id,
            used_hint=False,
            solved=False,
            gave_up=False,
            workspaces={
                "challenge_root": str(challenge_root),
                "evidence_store": str(evidence_store.path),
            },
            recommended_skills=recommended_skills,
        )
        initial_progress = self._extract_platform_progress(challenge)
        if initial_progress:
            summary.final_platform_progress = initial_progress
            summary.platform_progress_history.append(initial_progress)
        self._apply_evidence_context(summary=summary, attempt_summary=None, evidence_store=evidence_store)

        start_result: dict[str, Any] | None = None
        instance_started = False
        self._log(
            "challenge_begin",
            {
                "index": index,
                "code": code,
                "title": title,
                "challenge_mode": challenge_mode,
                "challenge_worker_id": challenge_worker_id,
                "recommended_skills": recommended_skills,
                "challenge": challenge,
            },
        )
        if orchestrator_summary is not None:
            self._write_live_summary(orchestrator_summary, active_challenge=summary, live_attempt_index=None)

        try:
            start_result = self.challenge_client.start_challenge(code)
            instance_started = True
            summary.entrypoints = self._normalize_entrypoints(start_result.get("entrypoint"))
            self._safe_seed_entrypoints(evidence_store, summary.entrypoints, code=code)
            self._apply_evidence_context(summary=summary, attempt_summary=None, evidence_store=evidence_store)
            self._refresh_dynamic_recommendations(summary=summary, challenge=challenge, evidence_store=evidence_store)
            self._log(
                "challenge_started",
                {
                    "code": code,
                    "title": title,
                    "challenge_mode": challenge_mode,
                    "start_result": start_result,
                    "entrypoints": summary.entrypoints,
                    "evidence_summary": summary.evidence_summary,
                },
            )
            if orchestrator_summary is not None:
                self._write_live_summary(orchestrator_summary, active_challenge=summary, live_attempt_index=0, current_runtime_step=0)

            if challenge_mode == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN:
                self._run_multi_flag_campaign(
                    summary=summary,
                    challenge=challenge,
                    challenge_root=challenge_root,
                    evidence_store=evidence_store,
                    orchestrator_summary=orchestrator_summary,
                )
            else:
                self._run_single_flag_mode(
                    summary=summary,
                    challenge=challenge,
                    challenge_root=challenge_root,
                    evidence_store=evidence_store,
                    orchestrator_summary=orchestrator_summary,
                )
        except Exception as exc:
            summary.error = str(exc)
            summary.gave_up = True
            if start_result is None and summary.attempt1 is None:
                summary.attempt1 = ChallengeAttemptSummary(
                    attempt=1,
                    with_hint=False,
                    status="start_failed",
                    workspace=str(challenge_root / "attempt1_no_hint"),
                    recommended_skills=recommended_skills,
                    error=str(exc),
                )
            self._log(
                "challenge_error",
                {
                    "code": code,
                    "title": title,
                    "challenge_mode": challenge_mode,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
        finally:
            if instance_started:
                try:
                    stop_result = self.challenge_client.stop_challenge(code)
                    summary.stop_result = stop_result
                    self._log("challenge_stopped", {"code": code, "stop_result": stop_result})
                    if orchestrator_summary is not None:
                        self._write_live_summary(
                            orchestrator_summary, active_challenge=summary, live_attempt_index=None
                        )
                except Exception as exc:
                    summary.stop_result = {"success": False, "error": str(exc)}
                    self._log(
                        "challenge_stop_error",
                        {
                            "code": code,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                    )
            else:
                # Avoid calling stop_challenge when start_challenge failed.
                # Otherwise we can thrash the platform's start/stop state machine and
                # trigger visible start/stop loops.
                self._log(
                    "challenge_stop_skipped",
                    {
                        "code": code,
                        "reason": "start_failed_or_not_started",
                    },
                )

            latest_challenge = self._safe_refresh_challenge_status(code)
            latest_progress = self._extract_platform_progress(latest_challenge)
            if latest_progress:
                summary.final_platform_progress = latest_progress
                if not summary.platform_progress_history or summary.platform_progress_history[-1] != latest_progress:
                    summary.platform_progress_history.append(latest_progress)
            if latest_challenge is not None and self.challenge_client.is_challenge_fully_solved(latest_challenge):
                summary.solved = True
                summary.gave_up = False
            elif not summary.solved:
                summary.gave_up = True

            self._sync_attempt_compatibility_fields(summary)
            self._log("challenge_summary", asdict(summary))
            if orchestrator_summary is not None:
                self._write_live_summary(orchestrator_summary, active_challenge=summary, live_attempt_index=None)
                self._write_live_summary(orchestrator_summary, clear_active_code=summary.code)

        return summary

    def _run_single_flag_mode(
        self,
        *,
        summary: ChallengeRunSummary,
        challenge: dict[str, Any],
        challenge_root: Path,
        evidence_store: EvidenceStore,
        orchestrator_summary: dict[str, Any] | None,
    ) -> None:
        code = summary.code
        title = summary.title
        hint_content: str | None = None
        progress_before_attempt = summary.final_platform_progress

        max_attempts = min(self.max_attempts_single_flag, 2)
        for attempt_index in range(1, max_attempts + 1):
            evidence_context = evidence_store.build_prompt_context(submitted_flags=summary.known_submitted_flags)
            self._refresh_dynamic_recommendations(summary=summary, challenge=challenge, evidence_store=evidence_store)
            with_hint, _reason = self.should_use_hint(
                challenge_mode=summary.challenge_mode,
                attempt_index=attempt_index,
                total_steps_used=summary.total_steps_used,
                progress_made=False,
                no_progress_attempts=summary.no_progress_attempts,
                used_hint=summary.used_hint,
            )
            if with_hint and not summary.used_hint:
                hint_payload = self.challenge_client.view_hint(code)
                summary.used_hint = True
                hint_content = self._extract_hint_content(hint_payload)
                self._log(
                    "hint_viewed",
                    {
                        "code": code,
                        "attempt": attempt_index,
                        "hint_payload": hint_payload,
                        "hint_preview": self._preview_text(hint_content),
                    },
                )
                if orchestrator_summary is not None:
                    self._write_live_summary(
                        orchestrator_summary,
                        active_challenge=summary,
                        live_attempt_index=attempt_index,
                        current_runtime_step=0,
                    )

            workspace_name = "attempt1_no_hint" if attempt_index == 1 else "attempt2_with_hint"
            workspace = challenge_root / workspace_name
            summary.workspaces[workspace_name] = str(workspace)
            summary.latest_attempt_workspace = str(workspace)
            workspace.mkdir(parents=True, exist_ok=True)
            runtime_budget = self._resolve_single_flag_attempt_budget(
                challenge=challenge,
                summary=summary,
                attempt_index=attempt_index,
            )
            attempt_context = self._build_attempt_context(summary)
            if orchestrator_summary is not None:
                self._write_live_summary(
                    orchestrator_summary,
                    active_challenge=summary,
                    live_attempt_index=attempt_index,
                    current_runtime_step=0,
                )

            task = build_hackathon_task(
                challenge_code=code,
                challenge_title=title,
                challenge_description=self._challenge_description(challenge),
                challenge_metadata=self._build_runtime_challenge_metadata(challenge, summary),
                challenge_mode=summary.challenge_mode,
                attempt_index=attempt_index,
                entrypoint=summary.entrypoints,
                hint_content=hint_content if with_hint else None,
                first_attempt=attempt_index == 1,
                total_steps_used=summary.total_steps_used,
                hint_already_used=summary.used_hint,
                known_progress=progress_before_attempt,
                known_flags=summary.known_submitted_flags,
                evidence_context=evidence_context,
                recommended_skills=summary.recommended_skills,
                attempt_context=attempt_context,
            )
            attempt_summary = self._run_attempt(
                attempt=attempt_index,
                with_hint=with_hint,
                workspace=workspace,
                task=task,
                code=code,
                title=title,
                challenge_mode=summary.challenge_mode,
                runtime_max_steps=runtime_budget,
            )
            attempt_summary.recommended_skills = list(summary.recommended_skills)
            evidence_result = self._absorb_attempt_evidence(
                evidence_store=evidence_store,
                workspace=workspace,
                code=code,
                attempt=attempt_index,
            )
            attempt_summary.extracted_artifacts_count = int(evidence_result.get("artifact_count", 0))
            latest_challenge, progress_after_attempt = self._record_attempt_outcome(
                summary=summary,
                attempt_summary=attempt_summary,
                progress_before_attempt=progress_before_attempt,
            )
            if attempt_summary.progress_made:
                summary.no_progress_attempts = 0
            else:
                summary.no_progress_attempts += 1
            self._safe_mark_submitted_flags(
                evidence_store=evidence_store,
                flags=summary.known_submitted_flags,
                code=code,
                attempt=attempt_index,
            )
            self._apply_evidence_context(
                summary=summary,
                attempt_summary=attempt_summary,
                evidence_store=evidence_store,
            )
            self._refresh_dynamic_recommendations(summary=summary, challenge=challenge, evidence_store=evidence_store)
            if orchestrator_summary is not None:
                self._write_live_summary(
                    orchestrator_summary,
                    active_challenge=summary,
                    live_attempt_index=attempt_index,
                    current_runtime_step=attempt_summary.current_runtime_step,
                )

            if latest_challenge is not None and self.challenge_client.is_challenge_fully_solved(latest_challenge):
                summary.solved = True
                attempt_summary.status = "solved"
                return

            if attempt_summary.status == "completed":
                attempt_summary.status = "finished_unsolved"

            if (
                attempt_index == 1
                and not attempt_summary.progress_made
                and self._looks_like_easy_single_flag(challenge)
            ):
                self._log(
                    "single_flag_fast_path_rollover",
                    {
                        "code": code,
                        "attempt": attempt_index,
                        "reason": "easy single_flag attempt hit no-progress boundary, moving to hint-assisted retry",
                        "step_budget": runtime_budget,
                    },
                )

            progress_before_attempt = progress_after_attempt or progress_before_attempt

        summary.gave_up = not summary.solved

    def should_use_hint(
        self,
        *,
        challenge_mode: str,
        attempt_index: int,
        total_steps_used: int,
        progress_made: bool,
        no_progress_attempts: int,
        used_hint: bool,
    ) -> tuple[bool, str]:
        """Decide whether the orchestrator should consume the official hint now."""

        mode = self.hint_policy_mode
        if used_hint:
            decision = (False, "hint already used earlier")
        elif mode == "never":
            decision = (False, "hint policy mode is never")
        elif challenge_mode == CHALLENGE_MODE_SINGLE_FLAG:
            decision = (
                attempt_index > 1,
                "single_flag default: reveal hint on the retry attempt"
                if attempt_index > 1
                else "single_flag default: keep first attempt hint-free",
            )
        elif mode == "conservative":
            minimum_attempt = max(self.hint_after_attempt, 2)
            should_use = attempt_index >= minimum_attempt and (not progress_made or no_progress_attempts >= 1)
            decision = (
                should_use,
                "conservative multi_flag policy: delay hint until later/no-progress attempts"
                if should_use
                else "conservative multi_flag policy: keep trying without hint",
            )
        elif mode == "aggressive":
            should_use = attempt_index >= 1
            decision = (
                should_use,
                "aggressive policy: allow hint as soon as the orchestrator reaches the policy checkpoint",
            )
        else:
            should_use = challenge_mode == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN and attempt_index >= self.hint_after_attempt
            decision = (
                should_use,
                "default multi_flag policy: reveal hint after the configured attempt threshold"
                if should_use
                else "default multi_flag policy: continue without hint for now",
            )

        self._log(
            "hint_policy_evaluated",
            {
                "challenge_mode": challenge_mode,
                "attempt_index": attempt_index,
                "total_steps_used": total_steps_used,
                "progress_made": progress_made,
                "no_progress_attempts": no_progress_attempts,
                "used_hint": used_hint,
                "hint_policy_mode": mode,
                "decision": decision[0],
                "reason": decision[1],
            },
        )
        return decision

    def _recommend_skills(self, challenge: dict[str, Any]) -> list[str]:
        try:
            return self.skill_manager.recommend_skills_for_challenge(challenge)
        except Exception as exc:
            self._log(
                "skill_recommendation_error",
                {
                    "challenge_code": challenge.get("code") if isinstance(challenge, dict) else None,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
            return []

    def _safe_seed_entrypoints(self, evidence_store: EvidenceStore, entrypoints: list[str], *, code: str) -> None:
        if not entrypoints:
            return
        try:
            evidence_store.seed_entrypoints(entrypoints)
        except Exception as exc:
            self._log(
                "evidence_seed_error",
                {
                    "code": code,
                    "entrypoints": entrypoints,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )

    def _absorb_attempt_evidence(
        self,
        *,
        evidence_store: EvidenceStore,
        workspace: Path,
        code: str,
        attempt: int,
    ) -> dict[str, Any]:
        try:
            payload = evidence_store.absorb_attempt_workspace(workspace)
        except Exception as exc:
            self._log(
                "evidence_absorb_error",
                {
                    "code": code,
                    "attempt": attempt,
                    "workspace": str(workspace),
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
            return {"artifact_count": 0, "summary": evidence_store.build_prompt_context()}
        self._log(
            "evidence_absorbed",
            {
                "code": code,
                "attempt": attempt,
                "workspace": str(workspace),
                "artifact_count": payload.get("artifact_count", 0),
                "absorbed_files_count": payload.get("absorbed_files_count", 0),
                "extracted_flags_count": payload.get("extracted_flags_count", 0),
                "skipped_invalid_urls_count": payload.get("skipped_invalid_urls_count", 0),
                "parse_errors_count": payload.get("parse_errors_count", 0),
                "merge_counts": payload.get("merge_counts", {}),
                "summary": payload.get("summary", {}),
            },
        )
        if payload.get("skipped_invalid_urls_count") or payload.get("parse_errors_count"):
            self._log(
                "evidence_absorb_warning",
                {
                    "code": code,
                    "attempt": attempt,
                    "workspace": str(workspace),
                    "skipped_invalid_url_count": payload.get("skipped_invalid_urls_count", 0),
                    "parse_errors_count": payload.get("parse_errors_count", 0),
                },
            )
        return payload

    def _safe_mark_submitted_flags(
        self,
        *,
        evidence_store: EvidenceStore,
        flags: list[str],
        code: str,
        attempt: int,
    ) -> None:
        if not flags:
            return
        try:
            evidence_store.mark_flags_submitted(flags)
        except Exception as exc:
            self._log(
                "evidence_mark_flags_error",
                {
                    "code": code,
                    "attempt": attempt,
                    "flags": flags,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )

    def _apply_evidence_context(
        self,
        *,
        summary: ChallengeRunSummary,
        attempt_summary: ChallengeAttemptSummary | None,
        evidence_store: EvidenceStore,
    ) -> None:
        try:
            context = evidence_store.build_prompt_context(submitted_flags=summary.known_submitted_flags)
        except Exception as exc:
            self._log(
                "evidence_context_error",
                {
                    "code": summary.code,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
            return

        summary.evidence_summary = context.get("summary")
        summary.known_hosts = list(context.get("known_hosts_services", []))
        summary.known_creds = list(context.get("known_credentials", []))
        summary.known_pivots = list(context.get("known_pivots", []))
        summary.recommended_skills = list(summary.recommended_skills or [])

        if attempt_summary is not None:
            attempt_summary.evidence_summary = context.get("summary")
            attempt_summary.known_hosts = list(context.get("known_hosts_services", []))
            attempt_summary.known_creds = list(context.get("known_credentials", []))
            attempt_summary.known_pivots = list(context.get("known_pivots", []))
            attempt_summary.recommended_skills = list(summary.recommended_skills)
            summary.extracted_artifacts_count += int(attempt_summary.extracted_artifacts_count or 0)
            summary.candidate_flags_high_confidence = self._merge_candidate_flag_records(
                summary.candidate_flags_high_confidence,
                attempt_summary.candidate_flags_high_confidence,
            )
            summary.candidate_flags_low_confidence = self._merge_candidate_flag_records(
                summary.candidate_flags_low_confidence,
                attempt_summary.candidate_flags_low_confidence,
            )


    @staticmethod
    def _build_runtime_challenge_metadata(challenge: dict[str, Any], summary: ChallengeRunSummary) -> dict[str, Any]:
        metadata = dict(challenge) if isinstance(challenge, dict) else {}
        metadata["code"] = summary.code
        metadata["title"] = summary.title
        metadata["flag_count"] = metadata.get("flag_count") or summary.final_platform_progress.get("flag_count")
        metadata["flag_got_count"] = summary.final_platform_progress.get("flag_got_count", metadata.get("flag_got_count"))
        metadata["total_score"] = summary.final_platform_progress.get("total_score", metadata.get("total_score"))
        metadata["total_got_score"] = summary.final_platform_progress.get("total_got_score", metadata.get("total_got_score"))
        metadata["status"] = summary.final_platform_progress.get("status", metadata.get("status"))
        metadata["entrypoint"] = list(summary.entrypoints or [])
        metadata["instance_status"] = "running" if summary.entrypoints else metadata.get("instance_status") or "running"
        metadata["hint_viewed"] = bool(summary.used_hint)
        return metadata

    def _run_multi_flag_campaign(
        self,
        *,
        summary: ChallengeRunSummary,
        challenge: dict[str, Any],
        challenge_root: Path,
        evidence_store: EvidenceStore,
        orchestrator_summary: dict[str, Any] | None,
    ) -> None:
        code = summary.code
        title = summary.title
        hint_content: str | None = None
        progress_before_attempt = summary.final_platform_progress

        for attempt_index in range(1, self.max_attempts_multi_flag + 1):
            runtime_max_steps = self._resolve_campaign_runtime_max_steps(summary.total_steps_used)
            if runtime_max_steps is not None and runtime_max_steps <= 0:
                self._log(
                    "campaign_budget_exhausted",
                    {
                        "code": code,
                        "attempt": attempt_index,
                        "total_steps_used": summary.total_steps_used,
                        "campaign_total_step_budget": self.campaign_total_step_budget,
                    },
                )
                break

            workspace_name = f"attempt{attempt_index}_campaign"
            workspace = challenge_root / workspace_name
            summary.workspaces[workspace_name] = str(workspace)
            summary.latest_attempt_workspace = str(workspace)
            workspace.mkdir(parents=True, exist_ok=True)
            evidence_context = evidence_store.build_prompt_context(submitted_flags=summary.known_submitted_flags)
            self._refresh_dynamic_recommendations(summary=summary, challenge=challenge, evidence_store=evidence_store)
            if orchestrator_summary is not None:
                self._write_live_summary(
                    orchestrator_summary,
                    active_challenge=summary,
                    live_attempt_index=attempt_index,
                    current_runtime_step=0,
                )

            task = build_hackathon_task(
                challenge_code=code,
                challenge_title=title,
                challenge_description=self._challenge_description(challenge),
                challenge_metadata=self._build_runtime_challenge_metadata(challenge, summary),
                challenge_mode=summary.challenge_mode,
                attempt_index=attempt_index,
                entrypoint=summary.entrypoints,
                hint_content=hint_content if summary.used_hint else None,
                first_attempt=attempt_index == 1,
                total_steps_used=summary.total_steps_used,
                hint_already_used=summary.used_hint,
                known_progress=progress_before_attempt,
                known_flags=summary.known_submitted_flags,
                evidence_context=evidence_context,
                recommended_skills=summary.recommended_skills,
                attempt_context=self._build_attempt_context(summary),
            )
            attempt_summary = self._run_attempt(
                attempt=attempt_index,
                with_hint=summary.used_hint,
                workspace=workspace,
                task=task,
                code=code,
                title=title,
                challenge_mode=summary.challenge_mode,
                runtime_max_steps=runtime_max_steps or self.max_steps,
            )
            attempt_summary.recommended_skills = list(summary.recommended_skills)
            evidence_result = self._absorb_attempt_evidence(
                evidence_store=evidence_store,
                workspace=workspace,
                code=code,
                attempt=attempt_index,
            )
            attempt_summary.extracted_artifacts_count = int(evidence_result.get("artifact_count", 0))
            latest_challenge, progress_after_attempt = self._record_attempt_outcome(
                summary=summary,
                attempt_summary=attempt_summary,
                progress_before_attempt=progress_before_attempt,
            )
            self._safe_mark_submitted_flags(
                evidence_store=evidence_store,
                flags=summary.known_submitted_flags,
                code=code,
                attempt=attempt_index,
            )
            self._apply_evidence_context(
                summary=summary,
                attempt_summary=attempt_summary,
                evidence_store=evidence_store,
            )
            self._refresh_dynamic_recommendations(summary=summary, challenge=challenge, evidence_store=evidence_store)
            if orchestrator_summary is not None:
                self._write_live_summary(
                    orchestrator_summary,
                    active_challenge=summary,
                    live_attempt_index=attempt_index,
                    current_runtime_step=attempt_summary.current_runtime_step,
                )

            if latest_challenge is not None and self.challenge_client.is_challenge_fully_solved(latest_challenge):
                summary.solved = True
                attempt_summary.status = "solved"
                return

            if attempt_summary.status == "completed":
                attempt_summary.status = "finished_unsolved"

            if attempt_summary.progress_made:
                summary.no_progress_attempts = 0
            elif summary.used_hint:
                summary.no_progress_attempts += 1

            progress_before_attempt = progress_after_attempt or progress_before_attempt

            should_use_hint, _reason = self.should_use_hint(
                challenge_mode=summary.challenge_mode,
                attempt_index=attempt_index,
                total_steps_used=summary.total_steps_used,
                progress_made=attempt_summary.progress_made,
                no_progress_attempts=summary.no_progress_attempts,
                used_hint=summary.used_hint,
            )
            if should_use_hint:
                hint_payload = self.challenge_client.view_hint(code)
                summary.used_hint = True
                summary.no_progress_attempts = 0
                hint_content = self._extract_hint_content(hint_payload)
                self._log(
                    "hint_viewed",
                    {
                        "code": code,
                        "attempt": attempt_index,
                        "hint_payload": hint_payload,
                        "hint_preview": self._preview_text(hint_content),
                    },
                )
                if orchestrator_summary is not None:
                    self._write_live_summary(
                        orchestrator_summary,
                        active_challenge=summary,
                        live_attempt_index=attempt_index,
                        current_runtime_step=attempt_summary.current_runtime_step,
                    )

            if self.campaign_total_step_budget is not None and summary.total_steps_used >= self.campaign_total_step_budget:
                self._log(
                    "campaign_stop_total_budget",
                    {
                        "code": code,
                        "attempt": attempt_index,
                        "total_steps_used": summary.total_steps_used,
                        "campaign_total_step_budget": self.campaign_total_step_budget,
                    },
                )
                break

            if summary.used_hint and summary.no_progress_attempts >= self.campaign_no_progress_attempt_limit:
                self._log(
                    "campaign_stop_no_progress",
                    {
                        "code": code,
                        "attempt": attempt_index,
                        "no_progress_attempts": summary.no_progress_attempts,
                        "campaign_no_progress_attempt_limit": self.campaign_no_progress_attempt_limit,
                    },
                )
                break

        summary.gave_up = not summary.solved

    def _record_attempt_outcome(
        self,
        *,
        summary: ChallengeRunSummary,
        attempt_summary: ChallengeAttemptSummary,
        progress_before_attempt: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        latest_challenge = self._safe_refresh_challenge_status(summary.code)
        progress_after_attempt = self._extract_platform_progress(latest_challenge)

        attempt_summary.submitted_progress = progress_after_attempt
        progress_made, progress_note = self._detect_platform_progress(
            before=progress_before_attempt,
            after=progress_after_attempt,
            found_flags=attempt_summary.found_flags,
        )
        attempt_summary.progress_made = progress_made
        attempt_summary.progress_note = progress_note

        summary.attempts.append(attempt_summary)
        summary.attempts_used = len(summary.attempts)
        summary.total_steps_used += attempt_summary.steps_taken or 0
        summary.latest_attempt_workspace = attempt_summary.workspace

        if progress_after_attempt:
            summary.final_platform_progress = progress_after_attempt
            summary.platform_progress_history.append(progress_after_attempt)

        if attempt_summary.progress_made:
            summary.known_submitted_flags = self._merge_flags(summary.known_submitted_flags, attempt_summary.found_flags)

        self._sync_attempt_compatibility_fields(summary)
        return latest_challenge, progress_after_attempt

    def _run_attempt(
        self,
        *,
        attempt: int,
        with_hint: bool,
        workspace: Path,
        task: str,
        code: str,
        title: str,
        challenge_mode: str,
        runtime_max_steps: int,
    ) -> ChallengeAttemptSummary:
        runtime_retry_limit = self._resolve_runtime_retry_limit()
        last_error_message: str | None = None
        last_runtime_id: str | None = None
        last_agent_id: str | None = None
        last_runtime_log_path: str | None = None
        last_observed_step: int | None = None

        for runtime_retry in range(runtime_retry_limit + 1):
            runtime = Runtime(
                workspace=workspace,
                max_steps=runtime_max_steps,
                browser_port=None,
                challenge_client=self.challenge_client,
                stop_on_flag_text=False,
                challenge_mode=challenge_mode,
            )
            last_runtime_id = runtime.runtime_id
            last_agent_id = runtime.active_agent_id
            last_runtime_log_path = str(runtime.log_path)
            self._log(
                "attempt_begin",
                {
                    "code": code,
                    "title": title,
                    "attempt": attempt,
                    "with_hint": with_hint,
                    "runtime_id": runtime.runtime_id,
                    "workspace": str(workspace),
                    "challenge_mode": challenge_mode,
                    "runtime_max_steps": runtime_max_steps,
                    "runtime_retry": runtime_retry,
                    "runtime_retry_limit": runtime_retry_limit,
                },
            )

            try:
                result = self._run_runtime_with_watchdog(
                    runtime=runtime,
                    task=task,
                    runtime_max_steps=runtime_max_steps,
                )
                found_flags = list(result.flags)
                if not found_flags and result.flag:
                    found_flags = [result.flag]
                candidate_high, candidate_low = self._split_candidate_flags_by_confidence(result.candidate_flags)
                submitted_flag_results = self._load_submit_flag_results(result.log_path)
                summary = ChallengeAttemptSummary(
                    attempt=attempt,
                    with_hint=with_hint,
                    status="completed",
                    workspace=str(workspace),
                    runtime_id=result.runtime_id,
                    agent_id=result.agent_id,
                    step_budget=runtime_max_steps,
                    current_runtime_step=result.steps_taken,
                    steps_taken=result.steps_taken,
                    runtime_log_path=str(result.log_path),
                    final_output_preview=self._preview_text(result.final_output, limit=2000),
                    extracted_flag=result.flag,
                    found_flags=found_flags,
                    candidate_flags_high_confidence=candidate_high,
                    candidate_flags_low_confidence=candidate_low,
                    submitted_flag_results=submitted_flag_results,
                )
                for item in submitted_flag_results:
                    self._log(
                        "submit_flag_result",
                        {
                            "code": code,
                            "attempt": attempt,
                            **item,
                        },
                    )
                self._log(
                    "attempt_finished",
                    {
                        "code": code,
                        "attempt": attempt,
                        "with_hint": with_hint,
                        "challenge_mode": challenge_mode,
                        "runtime_retry": runtime_retry,
                        "result": asdict(summary),
                    },
                )
                return summary
            except Exception as exc:
                observed_step = self._extract_runtime_progress_from_log(runtime.log_path)
                if observed_step is not None:
                    last_observed_step = max(last_observed_step or 0, observed_step)
                last_error_message = str(exc)
                retryable = self._is_retryable_runtime_error(exc)
                self._log(
                    "attempt_error",
                    {
                        "code": code,
                        "attempt": attempt,
                        "with_hint": with_hint,
                        "challenge_mode": challenge_mode,
                        "runtime_retry": runtime_retry,
                        "runtime_retry_limit": runtime_retry_limit,
                        "message": last_error_message,
                        "retryable": retryable,
                        "traceback": traceback.format_exc(),
                        "runtime_log_path": str(runtime.log_path),
                        "observed_step": observed_step,
                    },
                )
                if retryable and runtime_retry < runtime_retry_limit:
                    delay_seconds = self._runtime_retry_delay_seconds(runtime_retry)
                    self._log(
                        "attempt_retry_scheduled",
                        {
                            "code": code,
                            "attempt": attempt,
                            "with_hint": with_hint,
                            "challenge_mode": challenge_mode,
                            "runtime_retry": runtime_retry + 1,
                            "runtime_retry_limit": runtime_retry_limit,
                            "delay_seconds": delay_seconds,
                            "reason": last_error_message,
                        },
                    )
                    time.sleep(delay_seconds)
                    continue

                return ChallengeAttemptSummary(
                    attempt=attempt,
                    with_hint=with_hint,
                    status="runtime_error",
                    workspace=str(workspace),
                    runtime_id=runtime.runtime_id,
                    agent_id=runtime.active_agent_id,
                    step_budget=runtime_max_steps,
                    current_runtime_step=last_observed_step,
                    steps_taken=last_observed_step,
                    runtime_log_path=str(runtime.log_path),
                    error=last_error_message,
                )
            finally:
                runtime.cleanup()

        return ChallengeAttemptSummary(
            attempt=attempt,
            with_hint=with_hint,
            status="runtime_error",
            workspace=str(workspace),
            runtime_id=last_runtime_id,
            agent_id=last_agent_id,
            step_budget=runtime_max_steps,
            current_runtime_step=last_observed_step,
            steps_taken=last_observed_step,
            runtime_log_path=last_runtime_log_path,
            error=last_error_message or "runtime retries exhausted",
        )

    def _refresh_challenge_status(self, code: str) -> dict[str, Any] | None:
        payload = self.challenge_client.list_challenges()
        challenge = self.challenge_client.find_challenge(payload, code)
        self._log("challenge_refresh", {"code": code, "challenge": challenge})
        return challenge

    def _safe_refresh_challenge_status(self, code: str) -> dict[str, Any] | None:
        try:
            return self._refresh_challenge_status(code)
        except Exception as exc:
            self._log(
                "challenge_refresh_error",
                {
                    "code": code,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
            return None

    def _extract_platform_progress(self, challenge: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(challenge, dict):
            return {}
        return {
            "code": challenge.get("code"),
            "title": challenge.get("title"),
            "difficulty": challenge.get("difficulty"),
            "flag_got_count": challenge.get("flag_got_count"),
            "flag_count": challenge.get("flag_count"),
            "total_got_score": challenge.get("total_got_score"),
            "total_score": challenge.get("total_score"),
            "status": challenge.get("status"),
        }

    def _extract_hint_content(self, hint_payload: dict[str, Any]) -> str:
        candidates = (
            hint_payload.get("hint_content"),
            hint_payload.get("content"),
            hint_payload.get("message"),
            hint_payload.get("raw_text"),
        )
        for candidate in candidates:
            if candidate is None:
                continue
            text = str(candidate).strip()
            if text:
                return text
        data = hint_payload.get("data")
        if data is not None:
            return json.dumps(data, ensure_ascii=False, indent=2, default=str)
        return ""

    def _detect_platform_progress(
        self,
        *,
        before: dict[str, Any],
        after: dict[str, Any],
        found_flags: list[str],
    ) -> tuple[bool, str | None]:
        before_count = self._as_int(before.get("flag_got_count"))
        after_count = self._as_int(after.get("flag_got_count"))
        total_count = self._as_int(after.get("flag_count"))

        if before_count is not None and after_count is not None and after_count > before_count:
            before_total = before.get("flag_count")
            before_ratio = f"{before_count}/{before_total}" if before_total is not None else str(before_count)
            after_ratio = f"{after_count}/{total_count}" if total_count is not None else str(after_count)
            return True, f"platform flag progress increased from {before_ratio} to {after_ratio}"

        if before_count is None and after_count is not None and after_count > 0:
            ratio = f"{after_count}/{total_count}" if total_count is not None else str(after_count)
            return True, f"platform flag progress is now {ratio}"

        if found_flags and not after:
            return False, "runtime reported candidate flags but platform progress refresh was unavailable"

        return False, None

    @staticmethod
    def _challenge_description(challenge: dict[str, Any]) -> str | None:
        for key in ("description", "content", "summary"):
            value = challenge.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return None

    @staticmethod
    def _normalize_entrypoints(entrypoint: Any) -> list[str]:
        if entrypoint is None:
            return []
        if isinstance(entrypoint, str):
            text = entrypoint.strip()
            return [text] if text else []
        if isinstance(entrypoint, (list, tuple, set)):
            values: list[str] = []
            for item in entrypoint:
                values.extend(HackathonOrchestrator._normalize_entrypoints(item))
            return values
        if isinstance(entrypoint, dict):
            values: list[str] = []
            for key in ("url", "entrypoint", "value", "host"):
                values.extend(HackathonOrchestrator._normalize_entrypoints(entrypoint.get(key)))
            return values
        return [str(entrypoint)]

    def _refresh_dynamic_recommendations(
        self,
        *,
        summary: ChallengeRunSummary,
        challenge: dict[str, Any],
        evidence_store: EvidenceStore,
    ) -> None:
        try:
            context = evidence_store.build_prompt_context(submitted_flags=summary.known_submitted_flags)
            recommendation_input = dict(challenge)
            recommendation_input["dynamic_skill_signals"] = (
                list(context.get("known_urls", []))
                + list(context.get("notable_notes", []))
                + list(context.get("known_hosts_services", []))
            )
            recommended = self._recommend_skills(recommendation_input)
        except Exception as exc:
            self._log(
                "skill_recommendation_error",
                {
                    "challenge_code": summary.code,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
            return
        if recommended:
            summary.recommended_skills = recommended

    def _resolve_single_flag_attempt_budget(
        self,
        *,
        challenge: dict[str, Any],
        summary: ChallengeRunSummary,
        attempt_index: int,
    ) -> int:
        if summary.challenge_mode != CHALLENGE_MODE_SINGLE_FLAG:
            return self.max_steps
        if not self._looks_like_easy_single_flag(challenge):
            return self.max_steps
        if attempt_index <= 1:
            return min(self.max_steps, 24)
        remaining = max(self.max_steps - min(self.max_steps, 24), 1)
        return min(self.max_steps, max(32, remaining))

    def _looks_like_easy_single_flag(self, challenge: dict[str, Any]) -> bool:
        if not isinstance(challenge, dict):
            return False
        difficulty_text = str(challenge.get("difficulty") or challenge.get("level") or "").strip().lower()
        flag_count = _coerce_int(challenge.get("flag_count"))
        combined = " ".join(
            str(value).strip()
            for key in ("title", "description", "content", "summary", "category", "tags")
            for value in _flatten_stage_value(challenge.get(key))
        ).lower()
        easy_markers = ("easy", "very easy", "level 0", "level 1", "简单", "入门", "初级")
        signal_markers = (
            "admin",
            "private",
            "login",
            "api",
            "docs",
            "swagger",
            "fastapi",
            "demo",
            "filter",
            "job",
            "unauthorized",
            "forbidden",
            "admin only",
            "not allowed",
            "only admins can see private jobs",
        )
        return (flag_count in {None, 1}) and (
            any(marker in difficulty_text for marker in easy_markers)
            or any(marker in combined for marker in signal_markers)
        )

    def _build_attempt_context(self, summary: ChallengeRunSummary) -> dict[str, Any]:
        high_value_evidence: list[str] = []
        disproven_hypotheses: list[str] = []
        failed_submitted_flags: list[str] = []
        low_confidence_flags: list[str] = []
        key_response_diffs: list[str] = []

        for attempt in summary.attempts:
            if attempt.progress_note:
                high_value_evidence.append(attempt.progress_note)
                key_response_diffs.append(attempt.progress_note)
            if attempt.evidence_summary:
                high_value_evidence.append(attempt.evidence_summary)
            for candidate in attempt.candidate_flags_high_confidence:
                value = str(candidate.get("value", "")).strip()
                if value:
                    high_value_evidence.append(f"Observed high-confidence candidate: {value}")
            for candidate in attempt.candidate_flags_low_confidence:
                value = str(candidate.get("value", "")).strip()
                if value:
                    low_confidence_flags.append(value)
            for submit_result in attempt.submitted_flag_results:
                flag = str(submit_result.get("flag", "")).strip()
                if not flag:
                    continue
                if bool(submit_result.get("progress")) or bool(submit_result.get("solved")):
                    high_value_evidence.append(f"Platform accepted progress for {flag}")
                    detail = str(submit_result.get("progress_detail", "")).strip()
                    if detail:
                        key_response_diffs.append(detail)
                else:
                    failed_submitted_flags.append(flag)
                    disproven_hypotheses.append(f"Platform rejected submitted candidate flag: {flag}")

        return {
            "high_value_evidence": self._merge_flags([], high_value_evidence),
            "disproven_hypotheses": self._merge_flags([], disproven_hypotheses),
            "failed_submitted_flags": self._merge_flags([], failed_submitted_flags),
            "low_confidence_flags": self._merge_flags([], low_confidence_flags),
            "key_response_diffs": self._merge_flags([], key_response_diffs),
        }

    def _split_candidate_flags_by_confidence(
        self,
        candidate_flags: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        high: list[dict[str, Any]] = []
        low: list[dict[str, Any]] = []
        for item in candidate_flags:
            if not isinstance(item, dict):
                continue
            confidence = str(item.get("confidence", "")).strip().lower()
            if confidence == "high":
                high.append(item)
            else:
                low.append(item)
        return high, low

    def _merge_candidate_flag_records(
        self,
        existing: list[dict[str, Any]],
        new_items: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        merged = list(existing)
        seen = {
            (
                str(item.get("value", "")).strip(),
                str(item.get("source_type", "")).strip(),
                str(item.get("confidence", "")).strip(),
            )
            for item in merged
            if isinstance(item, dict)
        }
        for item in new_items:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("value", "")).strip(),
                str(item.get("source_type", "")).strip(),
                str(item.get("confidence", "")).strip(),
            )
            if not key[0] or key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    def _load_submit_flag_results(self, runtime_log_path: str | Path | None) -> list[dict[str, Any]]:
        if runtime_log_path is None:
            return []
        path = Path(runtime_log_path)
        if not path.exists():
            return []
        results: list[dict[str, Any]] = []
        try:
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                if not raw_line.strip():
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                payload = record.get("payload") if isinstance(record, dict) else None
                if not isinstance(payload, dict):
                    continue
                if payload.get("tool") != "mcp__challenge__submit_flag":
                    continue
                arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
                results.append(
                    {
                        "flag": str(arguments.get("flag", "")).strip(),
                        "progress": bool(payload.get("progress")),
                        "solved": bool(payload.get("solved")),
                        "progress_detail": str(payload.get("progress_detail", "")).strip(),
                    }
                )
        except Exception:
            return []
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, bool, bool, str]] = set()
        for item in results:
            key = (
                item["flag"],
                item["progress"],
                item["solved"],
                item["progress_detail"],
            )
            if key[0] and key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    def _resolve_campaign_runtime_max_steps(self, total_steps_used: int) -> int | None:
        if self.campaign_total_step_budget is None:
            return self.max_steps
        remaining = self.campaign_total_step_budget - total_steps_used
        if remaining <= 0:
            return 0
        return min(self.max_steps, remaining)

    def _sync_attempt_compatibility_fields(self, summary: ChallengeRunSummary) -> None:
        summary.attempt1 = summary.attempts[0] if len(summary.attempts) >= 1 else summary.attempt1
        summary.attempt2 = summary.attempts[1] if len(summary.attempts) >= 2 else summary.attempt2

    @staticmethod
    def _merge_flags(existing: list[str], new_flags: list[str]) -> list[str]:
        merged = list(existing)
        for flag in new_flags:
            text = str(flag).strip()
            if text and text not in merged:
                merged.append(text)
        return merged

    @staticmethod
    def _safe_name(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "challenge"

    @staticmethod
    def _preview_text(text: str, limit: int = 500) -> str:
        cleaned = text.strip()
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[:limit] + "...[truncated]"

    def _build_fallback_summary(
        self,
        index: int,
        code: str,
        title: str,
        challenge: dict[str, Any],
        exc: Exception,
    ) -> ChallengeRunSummary:
        challenge_mode = resolve_challenge_mode(challenge)
        challenge_root = self.hackathon_dir / f"{index:04d}_{self._safe_name(code or title)}"
        attempt1_dir = challenge_root / "attempt1_no_hint"
        attempt2_dir = challenge_root / "attempt2_with_hint"
        recommended_skills = self._recommend_skills(challenge)
        attempt1 = ChallengeAttemptSummary(
            attempt=1,
            with_hint=False,
            status="orchestrator_error",
            workspace=str(attempt1_dir),
            recommended_skills=recommended_skills,
            error=str(exc),
        )
        attempt2 = ChallengeAttemptSummary(
            attempt=2,
            with_hint=True,
            status="not_run",
            workspace=str(attempt2_dir),
            recommended_skills=recommended_skills,
        )
        return ChallengeRunSummary(
            index=index,
            code=code,
            title=title,
            challenge_mode=challenge_mode,
            used_hint=False,
            solved=False,
            gave_up=True,
            attempt1=attempt1,
            attempt2=attempt2,
            attempts=[attempt1],
            attempts_used=1,
            latest_attempt_workspace=str(attempt1_dir),
            workspaces={
                "challenge_root": str(challenge_root),
                "attempt1_no_hint": str(attempt1_dir),
                "attempt2_with_hint": str(attempt2_dir),
            },
            recommended_skills=recommended_skills,
            error=str(exc),
        )

    def _write_summary(self, payload: dict[str, Any]) -> None:
        with self._io_lock:
            self._ensure_hackathon_dir()
            try:
                self.summary_path.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                    encoding="utf-8",
                )
            except Exception:
                pass

    def _log(self, event: str, payload: Any) -> None:
        record = {
            "timestamp": self._timestamp(),
            "event": event,
            "payload": payload,
        }
        with self._io_lock:
            try:
                self._ensure_hackathon_dir()
                with self.orchestrator_log_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            except Exception:
                pass

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

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
