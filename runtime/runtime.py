from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import importlib.util
import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
from uuid import uuid4

from dotenv import dotenv_values

from .agent import AgentResult, LocalCTFSolverAgent
from .challenge_platform import ChallengePlatformClient
from .msf_client import MSFClient
from .prompt_loader import load_prompt
from .skills import SkillManager
from .tools import CompatibleToolRegistry


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = PROJECT_ROOT / "claude_code" / ".claude" / "agents" / "security-ctf-agent.md"
TOOLSET_SRC = PROJECT_ROOT / "meta-tooling" / "toolset" / "src"
SERVICE_DIR = PROJECT_ROOT / "meta-tooling" / "service"
SERVICE_BROWSER = SERVICE_DIR / "browser.py"
PYTHON_EXECUTOR_FILE = SERVICE_DIR / "python_executor_mcp.py"
MSF_SERVICE_FILE = SERVICE_DIR / "msfconsole_mcp.py"
DEFAULT_MSF_VENDOR_DIR = SERVICE_DIR / "vendors" / "msfconsole_mcp"
SKILLS_DIR = PROJECT_ROOT / "skills"
DEFAULT_MAX_STEPS = 96
CHALLENGE_MODE_SINGLE_FLAG = "single_flag"
CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN = "multi_flag_campaign"
CVE_KNOWLEDGE_KEYWORDS: tuple[str, ...] = (
    "thinkphp",
    "spring",
    "struts",
    "fastjson",
    "weblogic",
    "middleware",
    "框架",
    "中间件",
    "oa",
    "致远",
    "泛微",
    "用友",
    "蓝凌",
    "cve",
    "n-day",
)

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RuntimeResult:
    final_output: str
    flag: str | None
    steps_taken: int
    workspace: Path
    log_path: Path
    runtime_id: str | None = None
    agent_id: str | None = None
    flags: list[str] = field(default_factory=list)
    candidate_flags: list[dict[str, Any]] = field(default_factory=list)


class WorkspaceLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, payload: Any) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "payload": payload,
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


class Runtime:
    _port_reservation_lock = threading.Lock()
    _reserved_service_ports: set[int] = set()

    def __init__(
        self,
        *,
        workspace: Path,
        max_steps: int | None = None,
        browser_port: int | None = None,
        challenge_client: ChallengePlatformClient | None = None,
        stop_on_flag_text: bool = True,
        challenge_mode: str = CHALLENGE_MODE_SINGLE_FLAG,
    ) -> None:
        self.workspace = workspace
        self.requested_max_steps = max_steps
        self.max_steps = max_steps if max_steps is not None else DEFAULT_MAX_STEPS
        self.browser_port = browser_port
        self.challenge_client = challenge_client
        self.runtime_id = f"runtime-{uuid4().hex[:12]}"
        self.active_agent_id: str | None = None
        self.stop_on_flag_text = stop_on_flag_text
        self.challenge_mode = _normalize_challenge_mode(challenge_mode)
        self.logs_dir = self.workspace / "logs"
        self.notes_dir = self.workspace / "notes"
        self.sessions_dir = self.workspace / "python_sessions"
        self.log_path = self.logs_dir / "agent.jsonl"
        self.browser_log_path = self.logs_dir / "browser-service.log"
        self.msf_log_path = self.logs_dir / "msfconsole-mcp.log"
        self.todo_path = self.workspace / "todo.md"
        self.state_path = self.workspace / "agent_state.json"
        self.final_path = self.workspace / "final_answer.txt"
        self.logger = WorkspaceLogger(self.log_path)
        self.browser_process: subprocess.Popen[str] | None = None
        self.browser_log_handle = None
        self.msf_process: subprocess.Popen[str] | None = None
        self.msf_log_handle = None
        self.executor = None
        self.msf_client: MSFClient | None = None
        self.base_env: dict[str, str] = {}
        self.env: dict[str, str] | None = None
        self.msf_enabled = False
        self.msf_ready = False
        self.msf_port: int | None = None
        self.msf_status_reason: str | None = None
        self._reserved_local_ports: set[int] = set()
        self.skill_manager = SkillManager(
            skills_root=SKILLS_DIR,
            workspace=self.workspace,
            event_logger=self.logger.log,
        )
        self._setup_done = False

    def run(self, task: str) -> RuntimeResult:
        self.setup()
        assert self.executor is not None
        assert self.env is not None

        prompt = load_prompt(PROMPT_PATH)
        model_config = self._resolve_model_config(self.env)
        model_request_timeout = self._resolve_model_request_timeout(self.env)
        model_hard_timeout = self._resolve_model_hard_timeout(self.env, request_timeout=model_request_timeout)
        tool_registry = CompatibleToolRegistry(
            executor=self.executor,
            workspace=self.workspace,
            event_logger=self.logger.log,
            msf_client=self.msf_client,
            skill_manager=self.skill_manager,
            challenge_client=self.challenge_client,
        )
        agent = LocalCTFSolverAgent(
            system_prompt=self._compose_system_prompt(
                prompt.body,
                msf_tools_enabled=tool_registry.has_msf_tools(),
                skills_enabled=self.skill_manager.has_skills(),
                challenge_tools_enabled=tool_registry.has_challenge_tools(),
            ),
            tool_registry=tool_registry,
            event_logger=self.logger.log,
            max_steps=self.max_steps,
            base_url=model_config["base_url"],
            api_key=model_config["api_key"],
            model_name=model_config["model_name"],
            max_tokens=int(self.env.get("CTF_MAX_TOKENS", "4096")),
            temperature=self._read_temperature(self.env.get("CTF_TEMPERATURE")),
            request_timeout=model_request_timeout,
            hard_timeout_seconds=model_hard_timeout,
            stop_on_flag_text=self.stop_on_flag_text,
            challenge_mode=self.challenge_mode,
            agent_id=f"agent-{uuid4().hex[:12]}",
        )
        self.active_agent_id = getattr(agent, "agent_id", self.active_agent_id or f"agent-{uuid4().hex[:12]}")

        self.logger.log(
            "runtime_start",
            {
                "runtime_id": self.runtime_id,
                "agent_id": self.active_agent_id,
                "workspace": str(self.workspace),
                "max_steps": self.max_steps,
                "prompt_path": str(prompt.path),
                "prompt_metadata": prompt.metadata,
                "task": task,
                "browser_port": self.env["BROWSER_PORT"],
                "msf_enabled": self.msf_enabled,
                "msf_ready": self.msf_ready,
                "msf_port": self.env.get("MSF_MCP_PORT"),
                "msf_vendor_dir": self.env.get("MSFCONSOLE_MCP_DIR"),
                "msf_reason": self.msf_status_reason,
                "model_name": model_config["model_name"],
                "model_base_url": model_config["base_url"],
                "model_request_timeout": model_request_timeout,
                "model_hard_timeout": model_hard_timeout,
                "skills_root": str(self.skill_manager.skills_root),
                "skills_index_path": str(self.skill_manager.index_path),
                "skills_count": self.skill_manager.skill_count(),
                "skills_available_slugs": self.skill_manager.available_slugs(),
                "challenge_tools_enabled": tool_registry.has_challenge_tools(),
                "stop_on_flag_text": self.stop_on_flag_text,
                "challenge_mode": self.challenge_mode,
            },
        )
        self._write_state(
            {
                "status": "running",
                "runtime_id": self.runtime_id,
                "agent_id": self.active_agent_id,
                "workspace": str(self.workspace),
                "prompt_path": str(prompt.path),
                "planning_mode": False,
                "updated_at": self._timestamp(),
            }
        )

        try:
            result: AgentResult = agent.run(task)
            runtime_result = RuntimeResult(
                final_output=result.final_output,
                flag=result.flag,
                flags=result.flags,
                candidate_flags=result.candidate_flags,
                steps_taken=result.steps_taken,
                workspace=self.workspace,
                log_path=self.log_path,
                runtime_id=self.runtime_id,
                agent_id=result.agent_id or self.active_agent_id,
            )
            self.final_path.write_text(result.final_output + "\n", encoding="utf-8")
            self.logger.log(
                "runtime_finish",
                {
                    **asdict(runtime_result),
                    "solved": result.solved,
                },
            )
            self._write_state(
                {
                    **self._read_state(),
                    "status": "finished",
                    "runtime_id": self.runtime_id,
                    "agent_id": runtime_result.agent_id,
                    "solved": result.solved,
                    "flag": result.flag,
                    "flags": result.flags,
                    "candidate_flags": result.candidate_flags,
                    "steps_taken": result.steps_taken,
                    "final_answer_file": str(self.final_path),
                    "updated_at": self._timestamp(),
                }
            )
            return runtime_result
        except Exception as exc:
            self.logger.log(
                "runtime_error",
                {
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
            self._write_state(
                {
                    **self._read_state(),
                    "status": "failed",
                    "runtime_id": self.runtime_id,
                    "agent_id": self.active_agent_id,
                    "error": str(exc),
                    "updated_at": self._timestamp(),
                }
            )
            raise

    def setup(self) -> None:
        if self._setup_done:
            return

        self.base_env = self._load_project_env()
        self._validate_model_env(self.base_env)
        self.max_steps = resolve_runtime_max_steps(self.requested_max_steps, self.base_env)
        self._prepare_workspace()
        self.browser_port = self.browser_port or self._pick_browser_port()
        self.msf_enabled = self._env_flag("ENABLE_MSF_MCP", True, env=self.base_env)
        if self.msf_enabled:
            self.msf_port = self._pick_msf_port()
        self.env = self._build_runtime_env(self.base_env)
        self._apply_pythonpath(self.env)
        self._initialize_files()
        self.skill_manager.refresh_index()
        self.executor = self._load_python_executor_class()(
            path=str(self.sessions_dir),
            kernel_env=self.env,
        )
        self._start_browser_service()
        self._setup_msf_integration()
        self._setup_done = True

    def _load_project_env(self) -> dict[str, str]:
        env = {key: str(value) for key, value in os.environ.items()}
        env_path = PROJECT_ROOT / ".env"
        if env_path.exists():
            env.update({key: str(value) for key, value in dotenv_values(env_path).items() if value is not None})
            env.setdefault("CTF_ENV_FILE", str(env_path))
            self.logger.log(
                "env_loaded",
                {
                    "env_file": str(env_path),
                    "loaded_keys": [
                        key
                        for key in (
                            "LLM_BASE_URL",
                            "LLM_AUTH_TOKEN",
                            "LLM_MODEL",
                        )
                        if env.get(key)
                    ],
                },
            )
        return env

    def cleanup(self) -> None:
        if self.msf_client is not None:
            try:
                self.msf_client.close()
            except Exception as exc:
                self.logger.log("cleanup_error", {"component": "msf_client", "message": str(exc)})
        self.msf_client = None

        if self.executor is not None:
            try:
                self.executor.close_all_sessions()
            except Exception as exc:
                self.logger.log("cleanup_error", {"component": "python_executor", "message": str(exc)})
        self.executor = None

        if self.browser_process is not None:
            try:
                self.browser_process.terminate()
                self.browser_process.wait(timeout=5)
            except Exception:
                try:
                    self.browser_process.kill()
                except Exception:
                    pass
            self.browser_process = None

        if self.browser_log_handle is not None:
            self.browser_log_handle.close()
            self.browser_log_handle = None

        if self.msf_process is not None:
            try:
                self.msf_process.terminate()
                self.msf_process.wait(timeout=5)
            except Exception:
                try:
                    self.msf_process.kill()
                except Exception:
                    pass
            self.msf_process = None

        if self.msf_log_handle is not None:
            self.msf_log_handle.close()
            self.msf_log_handle = None

        self._release_reserved_ports()

    def _prepare_workspace(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.notes_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace / "executions").mkdir(parents=True, exist_ok=True)

    def _initialize_files(self) -> None:
        if not self.todo_path.exists():
            self.todo_path.write_text("", encoding="utf-8")
        if not self.state_path.exists():
            self._write_state(
                {
                    "status": "initialized",
                    "runtime_id": self.runtime_id,
                    "agent_id": self.active_agent_id,
                    "planning_mode": False,
                    "workspace": str(self.workspace),
                    "updated_at": self._timestamp(),
                }
            )

    def _build_runtime_env(self, base_env: dict[str, str]) -> dict[str, str]:
        assert self.browser_port is not None
        env = dict(base_env)
        env["CTF_WORKSPACE"] = str(self.workspace)
        env["CTF_NOTES_DIR"] = str(self.notes_dir)
        env["CTF_STATE_FILE"] = str(self.state_path)
        env["CTF_TODO_FILE"] = str(self.todo_path)
        env["CTF_LOG_DIR"] = str(self.logs_dir)
        env["CTF_SESSION_DIR"] = str(self.sessions_dir)
        env["CTF_MAX_STEPS"] = str(self.max_steps)
        env.setdefault("NO_VISION", "1")
        env["BROWSER_PORT"] = str(self.browser_port)
        env["ENABLE_MSF_MCP"] = "1" if self.msf_enabled else "0"
        env.setdefault("MSF_DEFAULT_WORKSPACE", "default")
        env["MSFCONSOLE_MCP_DIR"] = str(
            Path(base_env.get("MSFCONSOLE_MCP_DIR", str(DEFAULT_MSF_VENDOR_DIR))).expanduser().resolve()
        )
        env["MSF_MCP_HOST"] = base_env.get("MSF_MCP_HOST", "127.0.0.1")
        if self.msf_port is not None:
            env["MSF_MCP_PORT"] = str(self.msf_port)
        for key in ("MSFCONSOLE_PATH", "MSFRPCD_PATH"):
            raw_value = base_env.get(key)
            if raw_value:
                env[key] = raw_value
        env["PYTHONUNBUFFERED"] = "1"
        return env

    def _apply_pythonpath(self, env: dict[str, str]) -> None:
        toolset_src = str(TOOLSET_SRC)
        current_entries = [entry for entry in env.get("PYTHONPATH", "").split(os.pathsep) if entry]
        if toolset_src not in current_entries:
            current_entries.insert(0, toolset_src)
        env["PYTHONPATH"] = os.pathsep.join(current_entries)
        if toolset_src not in sys.path:
            sys.path.insert(0, toolset_src)

    def _start_browser_service(self) -> None:
        assert self.env is not None
        self.browser_log_handle = self.browser_log_path.open("a", encoding="utf-8")
        self.browser_process = subprocess.Popen(
            [sys.executable, str(SERVICE_BROWSER), "--port", str(self.browser_port)],
            cwd=str(PROJECT_ROOT),
            env=self.env,
            stdout=self.browser_log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_port(
            service_name="browser service",
            host="127.0.0.1",
            port=int(self.env["BROWSER_PORT"]),
            timeout=20.0,
            process=self.browser_process,
            log_path=self.browser_log_path,
        )
        self.logger.log(
            "browser_service",
            {
                "port": self.env["BROWSER_PORT"],
                "log_path": str(self.browser_log_path),
            },
        )

    def _setup_msf_integration(self) -> None:
        if not self.msf_enabled:
            self.msf_status_reason = "MSF integration is disabled by ENABLE_MSF_MCP=0."
            self.logger.log("msf_service_disabled", {"reason": self.msf_status_reason})
            return

        assert self.env is not None
        self.msf_client = MSFClient(
            service_status_provider=self._get_msf_service_status,
            vendor_dir=self.env["MSFCONSOLE_MCP_DIR"],
            default_workspace=self.env.get("MSF_DEFAULT_WORKSPACE", "default"),
        )
        environment_report = self.msf_client.inspect_environment()
        self.logger.log("msf_environment_check", environment_report)

        if not environment_report.get("available"):
            self.msf_status_reason = str(environment_report.get("reason") or "MSF environment is unavailable.")
            self.logger.log(
                "msf_service_unavailable",
                {
                    "reason": self.msf_status_reason,
                    "environment": environment_report,
                },
            )
            self.msf_client.close()
            self.msf_client = None
            return

        sidecar_start_error: str | None = None
        try:
            self._start_msf_service()
        except Exception as exc:
            sidecar_start_error = str(exc)
            self.logger.log(
                "msf_service_start_warning",
                {
                    "message": str(exc),
                    "log_path": str(self.msf_log_path),
                    "mode": "local-only-fallback",
                },
            )

        warmup_result = self.msf_client.warmup()
        self.logger.log("msf_warmup", warmup_result)
        if not warmup_result.get("success"):
            self.msf_status_reason = str(warmup_result.get("error") or "MSF warmup failed.")
            self.logger.log(
                "msf_service_unavailable",
                {
                    "reason": self.msf_status_reason,
                    "warmup": warmup_result,
                },
            )
            if self.msf_process is not None:
                try:
                    self.msf_process.terminate()
                    self.msf_process.wait(timeout=5)
                except Exception:
                    try:
                        self.msf_process.kill()
                    except Exception:
                        pass
                self.msf_process = None
            if self.msf_log_handle is not None:
                self.msf_log_handle.close()
                self.msf_log_handle = None
            self.msf_client.close()
            self.msf_client = None
            return

        self.msf_ready = True
        self.msf_status_reason = None if sidecar_start_error is None else f"Running in local-only mode: {sidecar_start_error}"
        self.logger.log(
            "msf_service",
            {
                "port": self.env.get("MSF_MCP_PORT"),
                "log_path": str(self.msf_log_path),
                "vendor_dir": self.env.get("MSFCONSOLE_MCP_DIR"),
                "mode": "local+sidecar" if sidecar_start_error is None else "local-only",
                "sidecar_running": self.msf_process is not None and self.msf_process.poll() is None,
            },
        )

    def _start_msf_service(self) -> None:
        assert self.env is not None
        assert self.msf_port is not None
        self.msf_log_handle = self.msf_log_path.open("a", encoding="utf-8")
        self.msf_process = subprocess.Popen(
            [
                sys.executable,
                str(MSF_SERVICE_FILE),
                "--host",
                self.env.get("MSF_MCP_HOST", "127.0.0.1"),
                "--port",
                str(self.msf_port),
            ],
            cwd=str(PROJECT_ROOT),
            env=self.env,
            stdout=self.msf_log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_port(
            service_name="msf service",
            host=self.env.get("MSF_MCP_HOST", "127.0.0.1"),
            port=self.msf_port,
            timeout=20.0,
            process=self.msf_process,
            log_path=self.msf_log_path,
        )

    def _get_msf_service_status(self) -> dict[str, Any]:
        running = self.msf_process is not None and self.msf_process.poll() is None
        return {
            "enabled": self.msf_enabled,
            "available": self.msf_ready,
            "running": running,
            "local_ready": self.msf_ready,
            "mode": "local+sidecar" if running else ("local-only" if self.msf_ready else "disabled"),
            "port": self.msf_port,
            "log_path": str(self.msf_log_path),
            "reason": self.msf_status_reason,
        }

    def _compose_system_prompt(
        self,
        prompt_body: str,
        *,
        msf_tools_enabled: bool,
        skills_enabled: bool,
        challenge_tools_enabled: bool,
    ) -> str:
        notes: list[str] = []
        if skills_enabled:
            notes.append(
                "Runtime note: You have access to a local SKILLS library. First inspect the available skill "
                "summaries with `ListSkills` or `SearchSkills`. Load only the skills that are relevant to the "
                "current stage and target with `LoadSkill`. Do not load all skills at once. Prefer skill-guided "
                "execution when the task involves multi-step exploitation, CVE analysis, AD/internal movement, "
                "OA environments, or agent-social challenges."
            )
        if msf_tools_enabled:
            notes.append(
                "Runtime note: local Metasploit tools are enabled through the `mcp__msf__*` tool family. "
                "Use them when MSF workflows materially help, but keep the existing PythonExecutor + toolset "
                "workflow unchanged."
            )
        if challenge_tools_enabled:
            notes.append(
                "Runtime note: official hackathon platform tools are enabled through the `mcp__challenge__*` "
                "tool family. When solving official challenges, the authoritative completion signal is the "
                "platform response from `mcp__challenge__submit_flag`, not merely seeing a local flag string."
            )
        if not notes:
            return prompt_body
        return f"{prompt_body}\n\n" + "\n\n".join(notes)

    def _wait_for_port(
        self,
        *,
        service_name: str,
        host: str,
        port: int,
        timeout: float,
        process: subprocess.Popen[str] | None,
        log_path: Path,
    ) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if process is not None and process.poll() is not None:
                raise RuntimeError(
                    f"{service_name.capitalize()} exited early. Check {log_path} for details."
                )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((host, port)) == 0:
                    return
            time.sleep(0.5)
        raise RuntimeError(f"Timed out waiting for {service_name} on {host}:{port}")

    def _load_python_executor_class(self):
        spec = importlib.util.spec_from_file_location("ctf_python_executor_mcp", PYTHON_EXECUTOR_FILE)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load PythonExecutor from {PYTHON_EXECUTOR_FILE}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.PythonExecutor

    def _write_state(self, payload: dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _pick_browser_port(self) -> int:
        preferred = self.base_env.get("BROWSER_PORT") or self.base_env.get("CTF_BROWSER_PORT") or "9222"
        return self._pick_free_port(
            preferred_ports=[int(preferred)],
            fallback_ports=range(9223, 9250),
            reserved_ports=set(),
        )

    def _pick_msf_port(self) -> int:
        preferred = self.base_env.get("MSF_MCP_PORT") or "28765"
        reserved_ports = {self.browser_port} if self.browser_port is not None else set()
        return self._pick_free_port(
            preferred_ports=[int(preferred)],
            fallback_ports=range(28766, 28820),
            reserved_ports=reserved_ports,
        )

    def _pick_free_port(
        self,
        *,
        preferred_ports: list[int],
        fallback_ports: range,
        reserved_ports: set[int],
    ) -> int:
        candidates = preferred_ports + list(fallback_ports)
        with self.__class__._port_reservation_lock:
            for candidate in candidates:
                if candidate in reserved_ports or candidate in self.__class__._reserved_service_ports:
                    continue
                if not self._local_port_is_free(candidate):
                    continue
                self.__class__._reserved_service_ports.add(candidate)
                self._reserved_local_ports.add(candidate)
                return candidate
        raise RuntimeError("Unable to find a free local service port.")

    @staticmethod
    def _local_port_is_free(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return sock.connect_ex(("127.0.0.1", port)) != 0

    def _release_reserved_ports(self) -> None:
        if not self._reserved_local_ports:
            return
        with self.__class__._port_reservation_lock:
            for port in list(self._reserved_local_ports):
                self.__class__._reserved_service_ports.discard(port)
            self._reserved_local_ports.clear()

    @staticmethod
    def _validate_model_env(env: dict[str, str]) -> None:
        config = Runtime._resolve_model_config(env)
        missing: list[str] = []
        if not config["base_url"]:
            missing.append("LLM_BASE_URL or ANTHROPIC_BASE_URL or OPENAI_BASE_URL")
        if not config["api_key"]:
            missing.append("LLM_AUTH_TOKEN or ANTHROPIC_AUTH_TOKEN or DASHSCOPE_API_KEY or OPENAI_API_KEY")
        if not config["model_name"]:
            missing.append("LLM_MODEL or ANTHROPIC_MODEL or OPENAI_MODEL")
        if missing:
            raise RuntimeError(
                "Missing required model environment variables: "
                + ", ".join(missing)
                + ". Please set them before running ctf."
            )

    @staticmethod
    def _resolve_model_config(env: dict[str, str]) -> dict[str, str]:
        return {
            "base_url": env.get("LLM_BASE_URL")
            or env.get("ANTHROPIC_BASE_URL")
            or env.get("OPENAI_BASE_URL")
            or "",
            "api_key": env.get("LLM_AUTH_TOKEN")
            or env.get("ANTHROPIC_AUTH_TOKEN")
            or env.get("DASHSCOPE_API_KEY")
            or env.get("OPENAI_API_KEY")
            or "",
            "model_name": env.get("LLM_MODEL")
            or env.get("ANTHROPIC_MODEL")
            or env.get("OPENAI_MODEL")
            or "",
        }

    @staticmethod
    def _read_temperature(raw_value: str | None) -> float | None:
        if raw_value is None or raw_value == "":
            return None
        return float(raw_value)

    @staticmethod
    def _resolve_model_request_timeout(env: dict[str, str]) -> float | None:
        for name in ("LLM_REQUEST_TIMEOUT", "OPENAI_REQUEST_TIMEOUT", "ANTHROPIC_REQUEST_TIMEOUT"):
            raw_value = env.get(name)
            if raw_value is None or str(raw_value).strip() == "":
                continue
            try:
                resolved = float(str(raw_value).strip())
            except (TypeError, ValueError) as exc:
                raise RuntimeError(f"Invalid model request timeout from {name}: {raw_value!r}") from exc
            if resolved <= 0:
                raise RuntimeError(f"Model request timeout from {name} must be positive, got {resolved}.")
            return resolved
        return 90.0

    @staticmethod
    def _resolve_model_hard_timeout(env: dict[str, str], *, request_timeout: float | None) -> float | None:
        for name in ("LLM_HARD_TIMEOUT", "OPENAI_HARD_TIMEOUT", "ANTHROPIC_HARD_TIMEOUT"):
            raw_value = env.get(name)
            if raw_value is None or str(raw_value).strip() == "":
                continue
            normalized = str(raw_value).strip().lower()
            if normalized in {"0", "false", "no", "off", "none"}:
                return None
            try:
                resolved = float(normalized)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(f"Invalid model hard timeout from {name}: {raw_value!r}") from exc
            if resolved <= 0:
                raise RuntimeError(f"Model hard timeout from {name} must be positive, got {resolved}.")
            return resolved

        if request_timeout is None:
            return None

        # Give the SDK-level timeout room to unwind, but never let a single stuck
        # model request block the whole orchestrator forever.
        return max(request_timeout + 30.0, request_timeout * 1.5)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _env_flag(name: str, default: bool, env: dict[str, str] | None = None) -> bool:
        raw = (env or os.environ).get(name)
        if raw is None:
            return default
        return raw.strip().lower() not in {"0", "false", "no", "off"}


def build_default_task(ctf: str) -> str:
    cve_knowledge_note = ""
    if _should_suggest_local_cve_knowledge(ctf):
        cve_knowledge_note = (
            "\nIf the target appears to be a known framework or middleware (e.g. ThinkPHP, Spring, Struts, "
            "Fastjson, Weblogic, or OA software), search the local CVE knowledge base with "
            "`SearchCVEKnowledge` before crafting exploitation steps. Prefer harmless verification first, then "
            "load only the most relevant entry with `LoadCVEKnowledge`."
        )
    return f"""
Use the security-ctf-agent: Solve the CTF challenge (obtaining the flag completes the task, you can end work immediately, don't need to verify the flag's accuracy.)

Challenge Information:
{ctf}

**You don't need to scan ports or IP segments, all IP and ports needed for solving are already listed**
{cve_knowledge_note}
""".strip()


def resolve_challenge_mode(challenge: dict[str, Any]) -> str:
    """Resolve official challenge mode.

    `single_flag` is intended for the first two zones.
    `multi_flag_campaign` is intended for the third/fourth zones where the
    platform may require multiple flags and multi-stage internal movement.
    """

    if not isinstance(challenge, dict):
        LOGGER.warning("resolve_challenge_mode received non-dict challenge, defaulting to single_flag.")
        return CHALLENGE_MODE_SINGLE_FLAG

    for key in ("stage", "zone", "track", "level"):
        stage_number = _extract_stage_number(challenge.get(key))
        if stage_number in {1, 2}:
            return CHALLENGE_MODE_SINGLE_FLAG
        if stage_number in {3, 4}:
            return CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN

    mode_text = " ".join(_iter_mode_strings(challenge)).strip().lower()
    if mode_text:
        if _matches_mode_patterns(mode_text, _MULTI_FLAG_MODE_PATTERNS):
            return CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN
        if _matches_mode_patterns(mode_text, _SINGLE_FLAG_MODE_PATTERNS):
            return CHALLENGE_MODE_SINGLE_FLAG

    LOGGER.warning(
        "Unable to resolve challenge mode for code=%r title=%r; defaulting to single_flag.",
        challenge.get("code"),
        challenge.get("title"),
    )
    return CHALLENGE_MODE_SINGLE_FLAG


def resolve_runtime_max_steps(requested_max_steps: int | None, env: dict[str, str] | None = None) -> int:
    active_env = env or os.environ

    if requested_max_steps is not None:
        return _validated_max_steps(requested_max_steps, source="argument")

    env_override = active_env.get("CTF_MAX_STEPS")
    if env_override is not None and str(env_override).strip():
        return _validated_max_steps(env_override, source="CTF_MAX_STEPS")

    return DEFAULT_MAX_STEPS


def _validated_max_steps(value: int | str, *, source: str) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Invalid max_steps from {source}: {value!r}") from exc
    if parsed <= 0:
        raise RuntimeError(f"max_steps from {source} must be a positive integer, got {parsed}.")
    return parsed


def build_hackathon_task(
    *,
    challenge_code: str,
    challenge_title: str,
    challenge_description: str | None = None,
    challenge_metadata: dict[str, Any] | None = None,
    challenge_mode: str,
    attempt_index: int,
    entrypoint: Any = None,
    hint_content: str | None = None,
    first_attempt: bool,
    total_steps_used: int | None = None,
    hint_already_used: bool = False,
    known_progress: dict[str, Any] | None = None,
    known_flags: list[str] | None = None,
    evidence_context: dict[str, Any] | None = None,
    recommended_skills: list[str] | None = None,
    attempt_context: dict[str, Any] | None = None,
) -> str:
    """Build the autonomous task prompt for official hackathon mode.

    single_flag: first/second zones, usually one flag, two-attempt flow.
    multi_flag_campaign: third/fourth zones, multiple flags and multi-stage
    internal/campaign movement; one correct flag does not mean completion.
    """

    normalized_mode = _normalize_challenge_mode(challenge_mode)
    metadata = challenge_metadata or {}
    progress_source = known_progress or metadata
    description = (
        challenge_description
        or _first_non_empty(
            metadata.get("description"),
            metadata.get("content"),
            metadata.get("summary"),
        )
        or "No detailed description was provided by the platform. Use the available metadata and the live target."
    )
    difficulty = _first_non_empty(metadata.get("difficulty"), metadata.get("level"), "unknown")
    progress = _format_challenge_progress(progress_source)
    entrypoints = _normalize_entrypoints(entrypoint)
    entrypoint_text = (
        "\n".join(f"- {item}" for item in entrypoints)
        if entrypoints
        else "- (platform did not provide an entrypoint)"
    )
    known_progress_text = json.dumps(known_progress or {}, ensure_ascii=False, indent=2, default=str)
    known_flags_list = _normalize_known_flags(known_flags)
    known_flags_text = (
        "\n".join(f"- {item}" for item in known_flags_list)
        if known_flags_list
        else "- (none yet)"
    )
    evidence = evidence_context or {}
    prior_attempt_context = attempt_context or {}
    known_hosts_services_text = _format_prompt_list(
        evidence.get("known_hosts_services") or evidence.get("known_hosts") or evidence.get("known_services"),
        empty_text="- (none preserved yet)",
    )
    known_credentials_text = _format_prompt_list(
        evidence.get("known_credentials"),
        empty_text="- (none preserved yet)",
    )
    known_pivots_text = _format_prompt_list(
        evidence.get("known_pivots"),
        empty_text="- (none preserved yet)",
    )
    known_urls_text = _format_prompt_list(
        evidence.get("known_urls"),
        empty_text="- (none preserved yet)",
    )
    notable_notes_text = _format_prompt_list(
        evidence.get("notable_notes"),
        empty_text="- (none preserved yet)",
    )
    evidence_summary_text = str(evidence.get("summary", "")).strip() or "No preserved evidence yet."
    dynamic_guidance = _analyze_dynamic_hackathon_signals(
        challenge_code=challenge_code,
        challenge_title=challenge_title,
        challenge_description=description,
        challenge_metadata=metadata,
        evidence_context=evidence,
        attempt_context=prior_attempt_context,
    )
    recommended_skills_list = _merge_unique_texts(recommended_skills, dynamic_guidance.get("recommended_skills"))
    recommended_skills_text = (
        "\n".join(f"- {item}" for item in recommended_skills_list)
        if recommended_skills_list
        else "- (none inferred)"
    )
    metadata_text = json.dumps(metadata, ensure_ascii=False, indent=2, default=str)
    cve_knowledge_note = (
        """
Local CVE Knowledge Hint:
- If the target appears to be a known framework or middleware (e.g. ThinkPHP, Spring, Struts, Fastjson, Weblogic, or OA software), search the local CVE knowledge base with `SearchCVEKnowledge` before crafting exploitation steps.
- Start with harmless verification requests, then use `LoadCVEKnowledge` only for the few entries that closely match the observed fingerprints and versions.
""".strip()
        if _should_suggest_local_cve_knowledge(
            challenge_code,
            challenge_title,
            description,
            metadata_text,
            " ".join(recommended_skills_list),
        )
        else ""
    )
    hint_text = (
        hint_content.strip()
        if hint_content and hint_content.strip()
        else "(The platform returned an empty hint.)"
    )
    evidence_block = f"""
Known Evidence Summary:
- {evidence_summary_text}

Known Hosts/Services:
{known_hosts_services_text}

Known Credentials:
{known_credentials_text}

Known Pivot State:
{known_pivots_text}

Known URLs:
{known_urls_text}

Notable Observations:
{notable_notes_text}

Known Submitted Flags:
{known_flags_text}
""".strip()
    recommended_skills_block = f"""
Recommended Skills To Load First:
{recommended_skills_text}

- Use `ListSkills` or `SearchSkills` to confirm relevance, then `LoadSkill` selectively instead of loading everything.
""".strip()
    dynamic_skill_hint = _build_dynamic_skill_hint_block(dynamic_guidance)
    attempt_inheritance_block = _build_attempt_inheritance_block(prior_attempt_context)
    common_header = f"""
Use the security-ctf-agent to solve this official Tencent Cloud hackathon challenge autonomously.

Competition Constraints:
- This target belongs to the official competition platform.
- The instance is already started for challenge `{challenge_code}`. Do not start or stop other challenge instances.
- You must work autonomously with the available tools. Do not ask a human to perform manual penetration steps for you.
- If you discover a high-confidence candidate flag from the target, hint, platform, or real tool output, submit it with `mcp__challenge__submit_flag`.
- Do not submit low-confidence candidate flags that only appear in your own code, payloads, prompts, execution records, or "Trying: flag{{...}}" style test strings.
- Do not treat a local `flag{{...}}` string as success by itself. The platform response and flag progress are authoritative.
- Do not attack unnecessary external targets. Focus on the provided challenge entrypoint(s) and assets derived from them.

Challenge Metadata:
- Code: {challenge_code}
- Title: {challenge_title}
- Difficulty: {difficulty}
- Challenge Mode: {normalized_mode}
- Attempt Index: {attempt_index}
- Previous Total Steps Used: {total_steps_used if total_steps_used is not None else "unknown"}
- Hint Already Used Earlier: {"yes" if hint_already_used else "no"}
- Platform Progress: {progress}

Challenge Description:
{description}

Challenge Entrypoint:
{entrypoint_text}

{evidence_block}

{recommended_skills_block}

{dynamic_skill_hint}

{attempt_inheritance_block}

{cve_knowledge_note}

Execution Style:
- Follow the existing security workflow: browser first, then source and static assets, then functionality and parameters, then traffic and responses, then small focused automation through Python when it helps.
- Keep notes and verify assumptions with real evidence from the target.

Full Challenge Metadata JSON:
{metadata_text}
""".strip()

    if normalized_mode == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN:
        attempt_text = (
            "This is the first campaign attempt. Do not proactively call `mcp__challenge__view_hint`; "
            "the orchestrator decides when to reveal it."
            if first_attempt
            else "This is a later campaign attempt. The orchestrator may have preserved known progress and hints below."
        )
        hint_block = (
            "\nKnown Hint:\n" + hint_text
            if hint_already_used or hint_content is not None
            else ""
        )
        return f"""
{common_header}

Campaign Mode Guidance:
- This challenge is in `multi_flag_campaign` mode, used for third/fourth-zone style problems with multiple flags and staged progression.
- A single correct flag submission only means partial progress unless the platform shows the challenge is fully solved.
- Seeing a local `flag{{...}}`, a plaintext flag file, or a partial flag trail is not completion by itself.
- `mcp__challenge__submit_flag` success can still be only partial progress.
- Do not end the task while platform progress is incomplete. Keep advancing to the next stage and validate with real tool calls.
- Expect multi-layer networks, OA environments, credential harvesting, lateral movement, pivoting, privilege escalation, persistence, or domain operations.
- Even if no new flag is immediately visible, continue reconnaissance and exploitation for the next host, identity, tunnel, or privilege boundary.
- {attempt_text}

Known Campaign State:
- Current platform progress snapshot:
{known_progress_text}
- Already submitted flags that should not be re-submitted:
{known_flags_text}
{hint_block}

Campaign Priorities:
- Focus first on the provided entrypoint and any reachable service or browser-exposed surface.
- Track new hosts, internal segments, credentials, tokens, cookies, keys, and reusable secrets.
- Establish and maintain any proxy, tunnel, route, foothold, or pivot that expands access into deeper layers.
- Enumerate internal assets, trust paths, OA systems, and domain information once footholds appear.
- Look for persistence, privilege maintenance, session reuse, and high-value identity paths when the network opens up.
- Preserve and reuse footholds, proxies, tunnels, sessions, and valid credentials across later stages instead of redoing earlier access.
- If `mcp__challenge__submit_flag` reports partial completion, immediately continue to the next stage instead of writing a final summary.
""".strip()

    attempt_text = (
        "This is the first attempt. Do not proactively call `mcp__challenge__view_hint` in this round. "
        "The orchestrator will decide whether to reveal a hint after this runtime ends."
        if first_attempt
        else "This is the hint-assisted attempt. The orchestrator has already retrieved the official hint and included it below."
    )
    hint_block = (
        ""
        if first_attempt and hint_content is None
        else "\nKnown Hint:\n" + hint_text
    )
    return f"""
{common_header}

Single-Flag Guidance:
- This challenge is in `single_flag` mode, used for first/second-zone style problems where one accepted flag usually completes the task.
- Once `mcp__challenge__submit_flag` and the platform progress indicate the challenge is fully solved, you can stop.
- {attempt_text}
- If the platform ever reports only partial progress, continue until the platform progress is complete or the current runtime hits its step budget.
- If a candidate flag is low confidence, record it as pending verification instead of submitting it immediately.
{hint_block}

Known State:
- Current platform progress snapshot:
{known_progress_text}
- Already accepted flags:
{known_flags_text}
""".strip()


def _format_prompt_list(values: Any, *, empty_text: str) -> str:
    if values is None:
        return empty_text
    if isinstance(values, str):
        cleaned = values.strip()
        return f"- {cleaned}" if cleaned else empty_text

    rendered: list[str] = []
    if isinstance(values, (list, tuple, set)):
        for item in values:
            item_text = str(item).strip()
            if item_text and item_text not in rendered:
                rendered.append(item_text)
    if not rendered:
        return empty_text
    return "\n".join(f"- {item}" for item in rendered)


def _merge_unique_texts(*value_groups: Any) -> list[str]:
    merged: list[str] = []
    for group in value_groups:
        if group is None:
            continue
        if isinstance(group, str):
            candidates = [group]
        elif isinstance(group, (list, tuple, set)):
            candidates = [str(item) for item in group]
        else:
            candidates = [str(group)]
        for candidate in candidates:
            text = str(candidate).strip()
            if text and text not in merged:
                merged.append(text)
    return merged


def _flatten_signal_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for nested in value.values():
            values.extend(_flatten_signal_strings(nested))
        return values
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for nested in value:
            values.extend(_flatten_signal_strings(nested))
        return values
    text = str(value).strip()
    return [text] if text else []


def _analyze_dynamic_hackathon_signals(
    *,
    challenge_code: str,
    challenge_title: str,
    challenge_description: str,
    challenge_metadata: dict[str, Any],
    evidence_context: dict[str, Any],
    attempt_context: dict[str, Any],
) -> dict[str, Any]:
    combined_values = _merge_unique_texts(
        challenge_code,
        challenge_title,
        challenge_description,
        _flatten_signal_strings(challenge_metadata),
        _flatten_signal_strings(evidence_context),
        _flatten_signal_strings(attempt_context),
    )
    combined_text = "\n".join(combined_values)
    lowered = combined_text.lower()
    difficulty_text = str(
        _first_non_empty(challenge_metadata.get("difficulty"), challenge_metadata.get("level"), "")
        or ""
    ).lower()
    flag_count = _int_text(challenge_metadata.get("flag_count"))
    known_urls = [item.lower() for item in _flatten_signal_strings(evidence_context.get("known_urls"))]
    notable_notes = [item.lower() for item in _flatten_signal_strings(evidence_context.get("notable_notes"))]
    strong_markers = {
        "admin": "admin",
        "private": "private",
        "login": "login",
        "api": "api",
        "docs": "docs",
        "swagger": "swagger",
        "fastapi": "fastapi",
        "openapi": "openapi",
        "redoc": "redoc",
        "demo": "demo",
        "filter": "filter",
        "job": "job",
        "unauthorized": "unauthorized",
        "forbidden": "forbidden",
        "not allowed": "not allowed",
        "admin only": "admin only",
        "only admins can see private jobs": "only admins can see private jobs",
        "uvicorn": "uvicorn",
    }
    observed_signals = [label for token, label in strong_markers.items() if token in lowered]
    for url in known_urls:
        if any(marker in url for marker in ("/openapi.json", "/docs", "/redoc", "/api", "/admin", "/login")):
            observed_signals.append(url)
    for note in notable_notes:
        if any(marker in note for marker in ("fastapi", "swagger", "redoc", "openapi", "admin", "private", "unauthorized", "forbidden")):
            observed_signals.append(note)
    observed_signals = _merge_unique_texts(observed_signals)

    recommended_skills: list[str] = []
    if observed_signals:
        recommended_skills.extend(["src-web-recon", "web-vuln-hunting"])

    easy_markers = ("easy", "very easy", "level 0", "level 1", "简单", "入门", "初级")
    looks_easy = any(marker in difficulty_text for marker in easy_markers)
    if not looks_easy and flag_count == 1 and any(
        marker in lowered for marker in ("demo", "api", "admin", "private", "swagger", "fastapi", "job")
    ):
        looks_easy = True

    openapi_path_count = sum(
        1 for item in known_urls if any(marker in item for marker in ("/openapi.json", "/docs", "/redoc", "/api"))
    )
    fast_path_enabled = flag_count in {None, 1} and looks_easy and bool(observed_signals)
    if fast_path_enabled and openapi_path_count > 8:
        fast_path_enabled = False

    return {
        "recommended_skills": _merge_unique_texts(recommended_skills),
        "observed_signals": observed_signals[:10],
        "fast_path_enabled": fast_path_enabled,
        "looks_easy_single_flag": looks_easy and flag_count in {None, 1},
    }


def _build_dynamic_skill_hint_block(dynamic_guidance: dict[str, Any]) -> str:
    signals = _merge_unique_texts(dynamic_guidance.get("observed_signals"))
    recommended_skills = _merge_unique_texts(dynamic_guidance.get("recommended_skills"))
    if not signals and not recommended_skills:
        return ""

    lines = [
        "Dynamic Skill Hint:",
        "- Observed signals suggest this target is likely a lightweight Web/API or business-logic challenge.",
    ]
    if signals:
        lines.append("- High-signal markers: " + ", ".join(signals[:8]))
    if recommended_skills:
        lines.append("- Prioritize these skill playbooks first: " + ", ".join(recommended_skills))
    if dynamic_guidance.get("fast_path_enabled"):
        lines.extend(
            [
                "- For the first 10-15 steps, avoid heavy tools such as ffuf, nuclei, deep katana crawling, sqlmap, or msf unless the lightweight path clearly stalls.",
                "- First inspect the homepage, JS behavior, `/openapi.json`, `/docs`, `/redoc`, request schemas, headers, content-type handling, auth checks, and small structured parameter mutations.",
                "- If several focused probes stop producing new endpoints, parameters, or response differences, explicitly switch strategies instead of spending the whole budget on broad scans.",
            ]
        )
    lines.extend(
        [
            "- Never treat flags that appear only inside your own code, prompts, execution records, or test strings as observed target evidence.",
            "- Low-confidence candidate flags can be recorded, but do not submit them until a real target/platform/tool response shows them.",
        ]
    )
    return "\n".join(lines)


def _build_attempt_inheritance_block(attempt_context: dict[str, Any]) -> str:
    if not isinstance(attempt_context, dict) or not attempt_context:
        return ""

    high_value_evidence = _format_prompt_list(
        attempt_context.get("high_value_evidence"),
        empty_text="- (none recorded yet)",
    )
    disproven_hypotheses = _format_prompt_list(
        attempt_context.get("disproven_hypotheses"),
        empty_text="- (none recorded yet)",
    )
    failed_submissions = _format_prompt_list(
        attempt_context.get("failed_submitted_flags"),
        empty_text="- (none recorded yet)",
    )
    low_confidence_flags = _format_prompt_list(
        attempt_context.get("low_confidence_flags"),
        empty_text="- (none recorded yet)",
    )
    key_response_diffs = _format_prompt_list(
        attempt_context.get("key_response_diffs"),
        empty_text="- (none recorded yet)",
    )
    return f"""
Attempt Inheritance:
- Reuse the strongest evidence from earlier attempts instead of restarting from scratch.

High-Value Evidence:
{high_value_evidence}

Disproven Hypotheses:
{disproven_hypotheses}

Failed Submitted Flags:
{failed_submissions}

Pending Low-Confidence Flags:
{low_confidence_flags}

Key Response Differences:
{key_response_diffs}
""".strip()


def _normalize_entrypoints(entrypoint: Any) -> list[str]:
    if entrypoint is None:
        return []
    if isinstance(entrypoint, str):
        text = entrypoint.strip()
        return [text] if text else []
    if isinstance(entrypoint, (list, tuple, set)):
        values: list[str] = []
        for item in entrypoint:
            values.extend(_normalize_entrypoints(item))
        return values
    if isinstance(entrypoint, dict):
        values: list[str] = []
        for key in ("url", "entrypoint", "value", "host"):
            values.extend(_normalize_entrypoints(entrypoint.get(key)))
        return values
    return [str(entrypoint)]


def _format_challenge_progress(metadata: dict[str, Any]) -> str:
    flag_got_count = _int_text(metadata.get("flag_got_count"))
    flag_count = _int_text(metadata.get("flag_count"))
    score_got = _int_text(metadata.get("total_got_score"))
    total_score = _int_text(metadata.get("total_score"))

    progress_parts: list[str] = []
    if flag_got_count is not None and flag_count is not None:
        progress_parts.append(f"flags {flag_got_count}/{flag_count}")
    if score_got is not None and total_score is not None:
        progress_parts.append(f"score {score_got}/{total_score}")
    return ", ".join(progress_parts) if progress_parts else "unknown"


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _should_suggest_local_cve_knowledge(*values: Any) -> bool:
    combined = " ".join(str(value) for value in values if value is not None).lower()
    return any(keyword in combined for keyword in CVE_KNOWLEDGE_KEYWORDS)


def _int_text(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalize_challenge_mode(challenge_mode: str | None) -> str:
    if challenge_mode == CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN:
        return CHALLENGE_MODE_MULTI_FLAG_CAMPAIGN
    return CHALLENGE_MODE_SINGLE_FLAG


def _normalize_known_flags(flags: list[str] | None) -> list[str]:
    unique_flags: list[str] = []
    for flag in flags or []:
        text = str(flag).strip()
        if text and text not in unique_flags:
            unique_flags.append(text)
    return unique_flags


def _iter_mode_strings(challenge: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("stage", "zone", "track", "level", "mode", "summary", "content", "category", "tags", "title", "description"):
        values.extend(_flatten_mode_value(challenge.get(key)))
    return values


def _flatten_mode_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for nested_value in value.values():
            values.extend(_flatten_mode_value(nested_value))
        return values
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for nested_value in value:
            values.extend(_flatten_mode_value(nested_value))
        return values
    text = str(value).strip()
    return [text] if text else []


def _extract_stage_number(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        parsed = int(value)
        return parsed if parsed in {1, 2, 3, 4} else None

    text = str(value).strip().lower()
    if text in {"1", "2", "3", "4"}:
        return int(text)

    demo_match = re.search(r"\bdemo\s*([1-4])\b|\bdemo([1-4])\b", text)
    if demo_match is not None:
        token = demo_match.group(1) or demo_match.group(2)
        if token is not None:
            return int(token)

    for stage_number, markers in _NAMED_STAGE_MARKERS.items():
        if any(marker in text for marker in markers):
            return stage_number

    regexes = (
        r"(?:zone|stage|track|level)\s*[-_ ]?\s*([1-4])",
        r"第\s*([一二三四1234])\s*(?:赛区|阶段|关卡)",
        r"(?:赛区|阶段|关卡)\s*([一二三四1234])",
    )
    for pattern in regexes:
        match = re.search(pattern, text)
        if match is None:
            continue
        token = match.group(1)
        return _stage_token_to_int(token)
    return None


def _stage_token_to_int(token: str) -> int | None:
    normalized = str(token).strip()
    chinese_digits = {"一": 1, "二": 2, "三": 3, "四": 4}
    if normalized in chinese_digits:
        return chinese_digits[normalized]
    if normalized in {"1", "2", "3", "4"}:
        return int(normalized)
    return None


def _matches_mode_patterns(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


_NAMED_STAGE_MARKERS: dict[int, tuple[str, ...]] = {
    1: ("第一赛区", "识器·明理"),
    2: ("第二赛区", "洞见·虚实"),
    3: ("第三赛区", "执刃·循迹"),
    4: ("第四赛区", "铸剑·止戈"),
}

_SINGLE_FLAG_MODE_PATTERNS: tuple[str, ...] = (
    r"第一赛区",
    r"第二赛区",
    r"\bdemo\s*1\b",
    r"\bdemo\s*2\b",
    r"\bdemo1\b",
    r"\bdemo2\b",
    r"\bzone\s*[-_ ]?1\b",
    r"\bzone\s*[-_ ]?2\b",
    r"\bstage\s*[-_ ]?1\b",
    r"\bstage\s*[-_ ]?2\b",
    r"\btrack\s*[-_ ]?1\b",
    r"\btrack\s*[-_ ]?2\b",
    r"识器·明理",
    r"洞见·虚实",
)

_MULTI_FLAG_MODE_PATTERNS: tuple[str, ...] = (
    r"第三赛区",
    r"第四赛区",
    r"\bdemo\s*3\b",
    r"\bdemo\s*4\b",
    r"\bdemo3\b",
    r"\bdemo4\b",
    r"\bzone\s*[-_ ]?3\b",
    r"\bzone\s*[-_ ]?4\b",
    r"\bstage\s*[-_ ]?3\b",
    r"\bstage\s*[-_ ]?4\b",
    r"\btrack\s*[-_ ]?3\b",
    r"\btrack\s*[-_ ]?4\b",
    r"执刃·循迹",
    r"铸剑·止戈",
    r"\boa\b",
    r"\bactive directory\b",
    r"\bad\b",
    r"\bdomain\b",
    r"\binternal\b",
    r"\bpivot\b",
    r"\blateral\b",
    r"\bcampaign\b",
    r"多层网络",
    r"多 flag",
    r"多flag",
    r"multiple flags",
    r"multi[- ]flag",
    r"内网",
    r"横向",
    r"域渗透",
    r"域控",
    r"凭证",
    r"隧道",
    r"持久化",
)
