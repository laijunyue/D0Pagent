from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import logging
import multiprocessing
import os
from pathlib import Path
from queue import Empty
import threading
import time
import traceback
from typing import Any, Iterable, TypedDict
from uuid import uuid4

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    messages_from_dict,
    messages_to_dict,
)
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from .tools import CompatibleToolRegistry, ToolInvocationResult, extract_flag


CHALLENGE_MODE_SINGLE_FLAG = "single_flag"
CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN = "multi_flag_campaign"


class _RFC3339Formatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created).astimezone()
        return dt.isoformat(timespec="seconds")


def _configure_llm_worker_logging(console_log_path: str | None) -> None:
    formatter = _RFC3339Formatter("[%(asctime)s] %(levelname)s:%(name)s:%(message)s")
    handlers: list[logging.Handler] = []

    if console_log_path:
        log_path = Path(console_log_path).expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    handlers.append(stream_handler)

    root_logger = logging.getLogger()
    for existing in list(root_logger.handlers):
        root_logger.removeHandler(existing)
        try:
            existing.close()
        except Exception:
            pass
    root_logger.setLevel(logging.INFO)
    for handler in handlers:
        root_logger.addHandler(handler)

    for logger_name in ("httpx", "httpcore", "openai", "openai._base_client", "langchain_openai"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = True


class AgentState(TypedDict):
    messages: list[BaseMessage]
    steps_taken: int
    solved: bool
    final_response: str | None
    needs_submission_followup: bool
    needs_campaign_retry: bool
    challenge_mode: str
    continue_until_budget_exhausted: bool
    platform_progress_complete: bool
    last_progress_step: int
    consecutive_no_progress_steps: int
    submitted_flags: list[str]
    candidate_flags: list[dict[str, Any]]


@dataclass(slots=True)
class AgentResult:
    final_output: str
    flag: str | None
    steps_taken: int
    solved: bool
    agent_id: str | None = None
    flags: list[str] = field(default_factory=list)
    candidate_flags: list[dict[str, Any]] = field(default_factory=list)


def _invoke_bound_client_worker(payload: dict[str, Any], result_queue: Any) -> None:
    console_log_path = payload.get("console_log_path") or os.getenv("CTF_CONSOLE_LOG_PATH")
    _configure_llm_worker_logging(str(console_log_path) if console_log_path else None)
    try:
        client = ChatOpenAI(**dict(payload["llm_kwargs"]))
        bound_client = client.bind_tools(list(payload["tools"]))
        messages = messages_from_dict(list(payload["messages"]))
        response = bound_client.invoke(messages)
        if isinstance(response, BaseMessage):
            serialized_message = messages_to_dict([response])[0]
        else:
            serialized_message = messages_to_dict([AIMessage(content=str(response))])[0]
        result_queue.put({"ok": True, "message": serialized_message})
    except Exception as exc:
        result_queue.put(
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )


class LocalCTFSolverAgent:
    def __init__(
        self,
        *,
        system_prompt: str,
        tool_registry: CompatibleToolRegistry,
        event_logger,
        max_steps: int,
        base_url: str,
        api_key: str,
        model_name: str,
        max_tokens: int = 4096,
        temperature: float | None = None,
        request_timeout: float | None = None,
        hard_timeout_seconds: float | None = None,
        stop_on_flag_text: bool = True,
        challenge_mode: str = CHALLENGE_MODE_SINGLE_FLAG,
        agent_id: str | None = None,
        continue_until_budget_exhausted: bool | None = None,
        no_progress_text_retry_limit: int = 3,
    ) -> None:
        self.system_prompt = system_prompt
        self.tool_registry = tool_registry
        self.event_logger = event_logger
        self.max_steps = max_steps
        self.model_name = model_name
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.request_timeout = request_timeout
        self.hard_timeout_seconds = hard_timeout_seconds
        self.stop_on_flag_text = stop_on_flag_text
        self.agent_id = str(agent_id or f"agent-{uuid4().hex[:12]}")
        self.challenge_mode = self._normalize_challenge_mode(challenge_mode)
        default_continue = self.challenge_mode == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN
        if continue_until_budget_exhausted is None:
            self.continue_until_budget_exhausted = default_continue
        else:
            self.continue_until_budget_exhausted = bool(continue_until_budget_exhausted)
        self.no_progress_text_retry_limit = max(int(no_progress_text_retry_limit), 1)
        self.llm_error_retry_limit = self._resolve_llm_error_retry_limit()
        self.llm_error_retry_backoff_seconds = self._resolve_llm_error_retry_backoff_seconds()

        llm_kwargs: dict[str, Any] = {
            "base_url": base_url,
            "model": model_name,
            "api_key": api_key,
            "max_retries": 0,
            "max_tokens": max_tokens,
        }
        if temperature is not None:
            llm_kwargs["temperature"] = temperature
        if request_timeout is not None:
            llm_kwargs["timeout"] = request_timeout

        self.llm_kwargs = dict(llm_kwargs)
        self.client = ChatOpenAI(**llm_kwargs)
        self.tools = self.tool_registry.tool_definitions()
        self.bound_client = self.client.bind_tools(self.tools)
        self.graph = self._build_graph()

    @staticmethod
    def _resolve_llm_error_retry_limit() -> int:
        env_value = (os.getenv("CTF_LLM_ERROR_RETRY_LIMIT") or "").strip()
        if not env_value:
            return 2
        try:
            return max(int(env_value), 0)
        except ValueError:
            return 2

    @staticmethod
    def _resolve_llm_error_retry_backoff_seconds() -> float:
        env_value = (os.getenv("CTF_LLM_ERROR_RETRY_BACKOFF_SECONDS") or "").strip()
        if not env_value:
            return 3.0
        try:
            return max(float(env_value), 0.0)
        except ValueError:
            return 3.0

    def _llm_retry_delay_seconds(self, request_attempt: int) -> float:
        base = max(float(self.llm_error_retry_backoff_seconds), 0.0)
        if base <= 0:
            return 0.0
        exponent = max(int(request_attempt) - 1, 0)
        return min(base * (2 ** exponent), 30.0)

    @staticmethod
    def _is_retryable_llm_exception(exc: BaseException) -> bool:
        message = f"{type(exc).__name__}: {exc}".lower()
        status_code = getattr(exc, "status_code", None)
        response = getattr(exc, "response", None)
        if status_code is None and response is not None:
            status_code = getattr(response, "status_code", None)
        try:
            status_code_int = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            status_code_int = None

        if status_code_int in {408, 409, 425, 429, 500, 502, 503, 504}:
            return True

        retry_markers = (
            "429",
            "429001",
            "rate limit",
            "too many requests",
            "bad gateway",
            "gateway_error",
            "502",
            "503",
            "504",
            "timeout",
            "timed out",
            "readtimeout",
            "read timeout",
            "connecttimeout",
            "connect timeout",
            "connection reset",
            "connection aborted",
            "connection error",
            "remoteprotocolerror",
            "temporarily unavailable",
            "server disconnected",
            "eof occurred",
            "llm invoke exceeded hard timeout",
            "llm worker process failed to start in time",
            "llm worker exited with code",
        )
        return any(marker in message for marker in retry_markers)

    def run(self, task: str) -> AgentResult:
        initial_state: AgentState = {
            "messages": [HumanMessage(content=task)],
            "steps_taken": 0,
            "solved": False,
            "final_response": None,
            "needs_submission_followup": False,
            "needs_campaign_retry": False,
            "challenge_mode": self.challenge_mode,
            "continue_until_budget_exhausted": self.continue_until_budget_exhausted,
            "platform_progress_complete": False,
            "last_progress_step": 0,
            "consecutive_no_progress_steps": 0,
            "submitted_flags": [],
            "candidate_flags": [],
        }
        state = self.graph.invoke(initial_state, config={"recursion_limit": self.max_steps * 4})
        final_output = state.get("final_response") or self._fallback_final_output(state)
        submitted_flags = self._unique_flags(state.get("submitted_flags", []))
        candidate_flags = self._normalize_candidate_flags(state.get("candidate_flags", []))
        flag = submitted_flags[-1] if submitted_flags else self._select_best_candidate_flag(candidate_flags)
        if flag is None and self.stop_on_flag_text:
            flag = extract_flag(final_output)
        if flag is None and self.stop_on_flag_text:
            flag = self._extract_flag_from_messages(state.get("messages", []))
        if self.stop_on_flag_text and not submitted_flags and flag is not None:
            submitted_flags = [flag]
        return AgentResult(
            final_output=final_output,
            flag=flag,
            flags=submitted_flags,
            candidate_flags=candidate_flags,
            steps_taken=state.get("steps_taken", 0),
            solved=state.get("solved", False),
            agent_id=self.agent_id,
        )

    def _build_graph(self):
        builder = StateGraph(AgentState)
        builder.add_node("model", self._call_model)
        builder.add_node("tools", self._call_tools)
        builder.add_edge(START, "model")
        builder.add_conditional_edges(
            "model",
            self._route_after_model,
            {
                "tools": "tools",
                "retry_model": "model",
                "end": END,
            },
        )
        builder.add_conditional_edges(
            "tools",
            self._route_after_tools,
            {
                "model": "model",
                "end": END,
            },
        )
        return builder.compile()

    def _call_model(self, state: AgentState) -> AgentState:
        invocation_messages = [SystemMessage(content=self.system_prompt), *state["messages"]]
        request_step = state["steps_taken"] + 1
        overall_started_at = time.monotonic()
        request_attempt = 0

        while True:
            request_attempt += 1
            started_at = time.monotonic()
            self.event_logger(
                "assistant_request_start",
                {
                    "agent_id": self.agent_id,
                    "step": request_step,
                    "request_attempt": request_attempt,
                    "message_count": len(invocation_messages),
                    "request_timeout": self.request_timeout,
                    "hard_timeout_seconds": self.hard_timeout_seconds,
                    "challenge_mode": state["challenge_mode"],
                },
            )
            try:
                ai_message = self._invoke_bound_client(invocation_messages)
                break
            except Exception as exc:
                retryable = request_attempt <= self.llm_error_retry_limit and self._is_retryable_llm_exception(exc)
                self.event_logger(
                    "assistant_request_error",
                    {
                        "agent_id": self.agent_id,
                        "step": request_step,
                        "request_attempt": request_attempt,
                        "duration_seconds": round(time.monotonic() - started_at, 3),
                        "total_duration_seconds": round(time.monotonic() - overall_started_at, 3),
                        "message": str(exc),
                        "retryable": retryable,
                        "challenge_mode": state["challenge_mode"],
                    },
                )
                if not retryable:
                    raise
                delay_seconds = self._llm_retry_delay_seconds(request_attempt)
                self.event_logger(
                    "assistant_request_retry",
                    {
                        "agent_id": self.agent_id,
                        "step": request_step,
                        "request_attempt": request_attempt,
                        "delay_seconds": delay_seconds,
                        "challenge_mode": state["challenge_mode"],
                    },
                )
                if delay_seconds > 0:
                    time.sleep(delay_seconds)

        self.event_logger(
            "assistant_request_finish",
            {
                "agent_id": self.agent_id,
                "step": request_step,
                "request_attempts_used": request_attempt,
                "duration_seconds": round(time.monotonic() - overall_started_at, 3),
                "challenge_mode": state["challenge_mode"],
            },
        )
        text_content = self._message_text(ai_message.content)
        tool_names = [tool_call["name"] for tool_call in ai_message.tool_calls]

        self.event_logger(
            "assistant",
            {
                "agent_id": self.agent_id,
                "step": state["steps_taken"] + 1,
                "text": text_content,
                "tool_calls": ai_message.tool_calls,
                "stop_reason": self._stop_reason(ai_message),
                "challenge_mode": state["challenge_mode"],
                "consecutive_no_progress_steps": state["consecutive_no_progress_steps"],
                "platform_progress_complete": state["platform_progress_complete"],
            },
        )

        next_state: AgentState = {
            "messages": state["messages"] + [ai_message],
            "steps_taken": state["steps_taken"] + 1,
            "solved": state["solved"],
            "final_response": state.get("final_response"),
            "needs_submission_followup": False,
            "needs_campaign_retry": False,
            "challenge_mode": state["challenge_mode"],
            "continue_until_budget_exhausted": state["continue_until_budget_exhausted"],
            "platform_progress_complete": state["platform_progress_complete"],
            "last_progress_step": state["last_progress_step"],
            "consecutive_no_progress_steps": state["consecutive_no_progress_steps"],
            "submitted_flags": list(state.get("submitted_flags", [])),
            "candidate_flags": list(state.get("candidate_flags", [])),
        }

        flag = extract_flag(text_content)
        if flag and self.stop_on_flag_text:
            next_state["solved"] = True
            next_state["final_response"] = text_content
        elif flag:
            if (
                not tool_names
                and next_state["steps_taken"] < self.max_steps
                and not self._has_submit_flag_tool_call(ai_message)
            ):
                next_state["messages"] = next_state["messages"] + [
                    HumanMessage(content=self._candidate_flag_submission_reminder(flag))
                ]
                next_state["needs_submission_followup"] = True
            elif not tool_names and text_content:
                next_state["final_response"] = text_content
        elif not tool_names and text_content:
            next_state["final_response"] = text_content

        if (
            next_state["challenge_mode"] == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN
            and next_state["continue_until_budget_exhausted"]
            and not next_state["platform_progress_complete"]
            and not next_state["solved"]
            and not tool_names
            and not next_state["needs_submission_followup"]
        ):
            retry_count = state["consecutive_no_progress_steps"] + 1
            next_state["consecutive_no_progress_steps"] = retry_count
            if next_state["steps_taken"] >= self.max_steps:
                next_state["final_response"] = self._step_limit_message(ai_message)
            elif retry_count >= self.no_progress_text_retry_limit:
                next_state["final_response"] = self._campaign_no_progress_stop_message(
                    ai_message=ai_message,
                    retry_count=retry_count,
                )
            else:
                next_state["messages"] = next_state["messages"] + [
                    HumanMessage(
                        content=self._campaign_continue_reminder(
                            retry_count=retry_count,
                            last_progress_step=next_state["last_progress_step"],
                            latest_text=text_content,
                        )
                    )
                ]
                next_state["needs_campaign_retry"] = True

        if next_state["steps_taken"] >= self.max_steps and next_state["final_response"] is None:
            next_state["final_response"] = self._step_limit_message(ai_message)
        return next_state

    def _invoke_bound_client(self, messages: list[BaseMessage]) -> AIMessage:
        if self.hard_timeout_seconds is None:
            response = self.bound_client.invoke(messages)
            return response if isinstance(response, AIMessage) else AIMessage(content=self._message_text(response))

        # NOTE:
        # We use a subprocess-based hard timeout to prevent the main runtime from
        # hanging indefinitely on rare network/HTTP client deadlocks.
        #
        # IMPORTANT:
        # Prefer `spawn` over `forkserver` here. In practice, `forkserver` still
        # requires an initial `fork()` to start the forkserver process. If the
        # parent is multi-threaded (browser/proxy/logging threads), that initial
        # fork can deadlock and make the agent appear "stuck" forever.
        ctx = multiprocessing.get_context(self._multiprocessing_context_name())
        # Prefer SimpleQueue when available because it avoids the background
        # feeder thread used by Queue and is less prone to shutdown/flush
        # deadlocks. Fall back to Queue for compatibility with older/fake
        # multiprocessing contexts used in tests.
        queue_factory = getattr(ctx, "SimpleQueue", None)
        if callable(queue_factory):
            result_queue = queue_factory()
        else:
            result_queue = ctx.Queue()
        process = ctx.Process(
            target=_invoke_bound_client_worker,
            args=(
                {
                    "llm_kwargs": dict(self.llm_kwargs),
                    "tools": list(self.tools),
                    "messages": messages_to_dict(messages),
                    "console_log_path": os.getenv("CTF_CONSOLE_LOG_PATH"),
                },
                result_queue,
            ),
        )
        process.daemon = True

        # Guard against rare hangs in `process.start()` itself.
        # If this hangs, the hard timeout would never start counting.
        start_error: list[BaseException] = []

        def _start_proc() -> None:
            try:
                process.start()
            except BaseException as exc:  # pragma: no cover
                start_error.append(exc)

        starter = threading.Thread(target=_start_proc, daemon=True)
        starter.start()
        starter.join(timeout=min(10.0, float(self.hard_timeout_seconds)))
        if starter.is_alive():
            raise TimeoutError(
                "LLM worker process failed to start in time (potential multiprocessing deadlock)."
            )
        if start_error:
            raise RuntimeError(f"Failed to start LLM worker process: {start_error[0]}")

        process.join(self.hard_timeout_seconds)

        try:
            if process.is_alive():
                process.terminate()
                process.join(timeout=3.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1.0)
                raise TimeoutError(
                    f"LLM invoke exceeded hard timeout of {self.hard_timeout_seconds:.1f} seconds."
                )

            try:
                payload = self._read_result_queue_payload(result_queue)
            except Empty as exc:
                raise RuntimeError(
                    f"LLM worker exited with code {process.exitcode} without returning a response."
                ) from exc
        finally:
            # SimpleQueue has `close()` but no `join_thread()`.
            try:
                close = getattr(result_queue, "close", None)
                if callable(close):
                    close()
            finally:
                join_thread = getattr(result_queue, "join_thread", None)
                if callable(join_thread):
                    join_thread()

        if not payload.get("ok"):
            message = str(payload.get("error") or "unknown LLM worker error")
            worker_traceback = str(payload.get("traceback") or "").strip()
            if worker_traceback:
                raise RuntimeError(f"LLM worker failed: {message}\n{worker_traceback}")
            raise RuntimeError(f"LLM worker failed: {message}")

        returned_messages = messages_from_dict([payload["message"]])
        response = returned_messages[0] if returned_messages else AIMessage(content="")
        return response if isinstance(response, AIMessage) else AIMessage(content=self._message_text(response))

    @staticmethod
    def _multiprocessing_context_name() -> str:
        # Allow overriding via env for debugging:
        # - CTF_LLM_MP_START_METHOD=spawn|forkserver|fork
        override = (os.getenv("CTF_LLM_MP_START_METHOD") or "").strip().lower()
        available_methods = set(multiprocessing.get_all_start_methods())
        if override in available_methods:
            return override

        # Prefer spawn for robustness in multi-threaded runtimes.
        if "spawn" in available_methods:
            return "spawn"
        if "forkserver" in available_methods:
            return "forkserver"
        if "fork" in available_methods:
            return "fork"
        return multiprocessing.get_start_method()

    @staticmethod
    def _read_result_queue_payload(result_queue: Any) -> dict[str, Any]:
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

    def _call_tools(self, state: AgentState) -> AgentState:
        last_message = state["messages"][-1]
        if not isinstance(last_message, AIMessage):
            return state

        tool_messages: list[ToolMessage] = []
        solved = state["solved"]
        final_response = state.get("final_response")
        platform_progress_complete = state["platform_progress_complete"]
        last_progress_step = state["last_progress_step"]
        consecutive_no_progress_steps = state["consecutive_no_progress_steps"]
        submitted_flags = list(state.get("submitted_flags", []))
        candidate_flags = list(state.get("candidate_flags", []))

        for tool_call in last_message.tool_calls:
            call_id = tool_call.get("id") or "tool_call"
            tool_name = tool_call["name"]
            tool_args = tool_call.get("args") or {}
            result: ToolInvocationResult = self.tool_registry.invoke(tool_name, tool_args, state["steps_taken"])
            tool_messages.append(
                ToolMessage(
                    content=result.content,
                    tool_call_id=call_id,
                    name=tool_name,
                )
            )
            if result.candidate_flags:
                candidate_flags = self._merge_candidate_flags(candidate_flags, result.candidate_flags)
            if result.flag and tool_name == "mcp__challenge__submit_flag":
                submitted_flags = self._merge_flags(submitted_flags, [result.flag])
            if result.progress:
                last_progress_step = state["steps_taken"]
                consecutive_no_progress_steps = 0
            if result.solved:
                solved = True
                platform_progress_complete = True
                final_response = result.flag or result.content

        return {
            "messages": state["messages"] + tool_messages,
            "steps_taken": state["steps_taken"],
            "solved": solved,
            "final_response": final_response,
            "needs_submission_followup": False,
            "needs_campaign_retry": False,
            "challenge_mode": state["challenge_mode"],
            "continue_until_budget_exhausted": state["continue_until_budget_exhausted"],
            "platform_progress_complete": platform_progress_complete,
            "last_progress_step": last_progress_step,
            "consecutive_no_progress_steps": consecutive_no_progress_steps,
            "submitted_flags": submitted_flags,
            "candidate_flags": candidate_flags,
        }

    def _route_after_model(self, state: AgentState) -> str:
        if state["solved"] or state["platform_progress_complete"]:
            return "end"
        if state.get("needs_submission_followup") and state["steps_taken"] < self.max_steps:
            return "retry_model"
        if state.get("needs_campaign_retry") and state["steps_taken"] < self.max_steps:
            return "retry_model"
        if state["steps_taken"] >= self.max_steps:
            return "end"
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return "end"

    def _route_after_tools(self, state: AgentState) -> str:
        if state["solved"] or state["platform_progress_complete"]:
            return "end"
        if state["steps_taken"] >= self.max_steps:
            return "end"
        return "model"

    @staticmethod
    def _has_submit_flag_tool_call(message: AIMessage) -> bool:
        return any(tool_call.get("name") == "mcp__challenge__submit_flag" for tool_call in message.tool_calls)

    @staticmethod
    def _candidate_flag_submission_reminder(flag: str) -> str:
        return (
            "You identified a candidate flag but did not submit it. "
            f"Candidate flag: {flag}. "
            "In hackathon mode, seeing a local flag string is not completion. "
            "If this candidate belongs to the active challenge, immediately call "
            "`mcp__challenge__submit_flag` with the active challenge code and this flag. "
            "Only stop after the platform confirms full progress."
        )

    @staticmethod
    def _stop_reason(message: AIMessage) -> str | None:
        response_metadata = getattr(message, "response_metadata", None) or {}
        return response_metadata.get("finish_reason") or response_metadata.get("stop_reason")

    def _campaign_continue_reminder(
        self,
        *,
        retry_count: int,
        last_progress_step: int,
        latest_text: str,
    ) -> str:
        progress_note = (
            f"The last confirmed platform progress happened at step {last_progress_step}. "
            if last_progress_step > 0
            else "No platform-confirmed progress has been recorded yet. "
        )
        latest_summary = latest_text.strip() or "(no textual summary)"
        return (
            "The active challenge is still not fully solved and the platform progress is incomplete. "
            f"{progress_note}"
            f"This is campaign retry {retry_count}/{self.no_progress_text_retry_limit}. "
            "Do not stop or summarize. Continue the next stage of recon, lateral movement, privilege escalation, "
            "persistence, pivoting, or internal asset expansion, and verify the next step with tool calls. "
            f"Latest text-only response for context: {latest_summary}"
        )

    def _campaign_no_progress_stop_message(self, *, ai_message: AIMessage, retry_count: int) -> str:
        text = self._message_text(ai_message.content)
        latest_text = text or "(no final text produced)"
        return (
            "Stopped campaign attempt because the model produced repeated text-only summaries without new tool-driven "
            f"progress for {retry_count} consecutive retries while the platform progress was still incomplete.\n\n"
            f"Latest model output:\n{latest_text}"
        )

    def _fallback_final_output(self, state: AgentState) -> str:
        last_text = self._latest_text_message(state.get("messages", []))
        if state.get("steps_taken", 0) >= self.max_steps:
            return (
                f"Stopped after reaching max_steps={self.max_steps}.\n\n"
                f"Latest analysis:\n{last_text or '(no final text produced)'}"
            )
        return last_text or "Agent finished without producing a final text response."

    def _step_limit_message(self, ai_message: AIMessage) -> str:
        text = self._message_text(ai_message.content)
        if text:
            return f"Stopped after reaching max_steps={self.max_steps}.\n\nLatest model output:\n{text}"
        return f"Stopped after reaching max_steps={self.max_steps} before the agent produced a final answer."

    def _latest_text_message(self, messages: Iterable[BaseMessage]) -> str:
        for message in reversed(list(messages)):
            text = self._message_text(message.content)
            if text:
                return text
        return ""

    def _extract_flag_from_messages(self, messages: Iterable[BaseMessage]) -> str | None:
        for message in reversed(list(messages)):
            text = self._message_text(message.content)
            flag = extract_flag(text)
            if flag:
                return flag
        return None

    @staticmethod
    def _message_text(content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    if item.get("type") == "text":
                        parts.append(str(item.get("text", "")))
                    else:
                        parts.append(str(item))
                else:
                    text_value = getattr(item, "text", None)
                    if text_value is not None:
                        parts.append(str(text_value))
                    else:
                        parts.append(str(item))
            return "\n".join(part for part in parts if part).strip()
        return str(content)

    @staticmethod
    def _merge_flags(existing: list[str], new_flags: list[str]) -> list[str]:
        merged = list(existing)
        for flag in new_flags:
            text = str(flag).strip()
            if text and text not in merged:
                merged.append(text)
        return merged

    @staticmethod
    def _unique_flags(flags: list[str]) -> list[str]:
        return LocalCTFSolverAgent._merge_flags([], flags)

    @staticmethod
    def _normalize_candidate_flags(flags: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in flags or []:
            candidate = LocalCTFSolverAgent._normalize_candidate_flag(item)
            if candidate is None:
                continue
            key = (
                candidate["value"],
                candidate["source_type"],
                candidate["confidence"],
                candidate["evidence_excerpt"],
            )
            if key in seen:
                continue
            seen.add(key)
            normalized.append(candidate)
        return normalized

    @staticmethod
    def _normalize_candidate_flag(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        value = str(item.get("value", "")).strip()
        if not value:
            return None
        return {
            "value": value,
            "source_type": str(item.get("source_type", "")).strip() or "unknown",
            "confidence": str(item.get("confidence", "")).strip() or "low",
            "observed_in_step": int(item.get("observed_in_step") or 0),
            "evidence_excerpt": str(item.get("evidence_excerpt", "")).strip(),
            "auto_submittable": bool(item.get("auto_submittable")),
        }

    @staticmethod
    def _merge_candidate_flags(
        existing: list[dict[str, Any]],
        new_flags: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        merged = list(existing)
        seen = {
            (
                str(item.get("value", "")).strip(),
                str(item.get("source_type", "")).strip(),
                str(item.get("confidence", "")).strip(),
                str(item.get("evidence_excerpt", "")).strip(),
            )
            for item in merged
            if isinstance(item, dict)
        }
        for item in new_flags:
            candidate = LocalCTFSolverAgent._normalize_candidate_flag(item)
            if candidate is None:
                continue
            key = (
                candidate["value"],
                candidate["source_type"],
                candidate["confidence"],
                candidate["evidence_excerpt"],
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(candidate)
        return merged

    @staticmethod
    def _select_best_candidate_flag(candidate_flags: list[dict[str, Any]]) -> str | None:
        scored: list[tuple[int, int, str]] = []
        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        for item in candidate_flags:
            if not isinstance(item, dict):
                continue
            if not bool(item.get("auto_submittable")):
                continue
            value = str(item.get("value", "")).strip()
            if not value:
                continue
            scored.append(
                (
                    confidence_rank.get(str(item.get("confidence", "")).strip().lower(), 0),
                    int(item.get("observed_in_step") or 0),
                    value,
                )
            )
        if not scored:
            return None
        scored.sort()
        return scored[-1][2]

    @staticmethod
    def _normalize_challenge_mode(challenge_mode: str | None) -> str:
        if challenge_mode == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN:
            return CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN
        return CHALLENGE_MODE_SINGLE_FLAG
