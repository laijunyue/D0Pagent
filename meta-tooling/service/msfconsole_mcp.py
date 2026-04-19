from __future__ import annotations

import argparse
import asyncio
import atexit
import importlib.util
import json
import logging
import os
import shutil
import sys
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Annotated, Any, Mapping

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover - optional until HTTP mode is used
    FastMCP = None


LOGGER = logging.getLogger("ctf.msfconsole_mcp")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VENDOR_DIR = PROJECT_ROOT / "meta-tooling" / "service" / "vendors" / "msfconsole_mcp"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 28765
DEFAULT_WORKSPACE = "default"
_VENDOR_MODULE_NAME = "ctf_vendored_msf_stable_integration"


@dataclass(slots=True)
class MSFEnvironmentReport:
    enabled: bool
    available: bool
    vendor_dir: str
    vendor_dir_exists: bool
    fastmcp_available: bool
    msfconsole_path: str | None
    msfconsole_found: bool
    msfrpcd_path: str | None
    msfrpcd_found: bool
    import_error: str | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)


class AsyncTaskRunner:
    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ctf-msf-async",
            daemon=True,
        )
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def close(self) -> None:
        if self._loop.is_closed():
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2.0)
        if not self._loop.is_closed():
            self._loop.close()


def resolve_vendor_dir(configured_dir: str | os.PathLike[str] | None = None) -> Path:
    raw_dir = configured_dir or os.getenv("MSFCONSOLE_MCP_DIR") or DEFAULT_VENDOR_DIR
    return Path(raw_dir).expanduser().resolve()


def _resolve_binary_path(env_name: str, command_name: str) -> tuple[str | None, bool]:
    configured = os.getenv(env_name)
    if configured:
        path = Path(configured).expanduser()
        return (str(path.resolve()) if path.exists() else str(path), path.exists())
    discovered = shutil.which(command_name)
    return discovered, discovered is not None


def _prepend_binary_dir(path: str | None) -> None:
    if not path:
        return
    binary_dir = str(Path(path).expanduser().resolve().parent)
    current_entries = [entry for entry in os.environ.get("PATH", "").split(os.pathsep) if entry]
    if binary_dir not in current_entries:
        os.environ["PATH"] = os.pathsep.join([binary_dir, *current_entries])


def load_vendor_module(vendor_dir: str | os.PathLike[str] | None = None):
    resolved_vendor_dir = resolve_vendor_dir(vendor_dir)
    module_path = resolved_vendor_dir / "msf_stable_integration.py"
    if not module_path.exists():
        raise FileNotFoundError(f"Vendored msf_stable_integration.py not found: {module_path}")
    spec = importlib.util.spec_from_file_location(_VENDOR_MODULE_NAME, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load vendored msf module from {module_path}")
    module = sys.modules.get(_VENDOR_MODULE_NAME)
    if module is not None:
        return module
    module = importlib.util.module_from_spec(spec)
    sys.modules[_VENDOR_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def inspect_msf_environment(vendor_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    resolved_vendor_dir = resolve_vendor_dir(vendor_dir)
    msfconsole_path, msfconsole_found = _resolve_binary_path("MSFCONSOLE_PATH", "msfconsole")
    msfrpcd_path, msfrpcd_found = _resolve_binary_path("MSFRPCD_PATH", "msfrpcd")

    report = MSFEnvironmentReport(
        enabled=_env_flag("ENABLE_MSF_MCP", True),
        available=False,
        vendor_dir=str(resolved_vendor_dir),
        vendor_dir_exists=resolved_vendor_dir.exists(),
        fastmcp_available=FastMCP is not None,
        msfconsole_path=msfconsole_path,
        msfconsole_found=msfconsole_found,
        msfrpcd_path=msfrpcd_path,
        msfrpcd_found=msfrpcd_found,
    )

    if not report.vendor_dir_exists:
        report.reason = f"Vendored msfconsole-mcp directory not found: {resolved_vendor_dir}"
        report.warnings.append("MSF integration is disabled because the vendored repository is missing.")
        return asdict(report)

    if FastMCP is None:
        report.reason = "fastmcp is not installed."
        report.warnings.append("Install the project dependencies before enabling ENABLE_MSF_MCP.")
        return asdict(report)

    if not msfconsole_found:
        report.reason = (
            "msfconsole is not installed or not discoverable. "
            "Set MSFCONSOLE_PATH or add msfconsole to PATH."
        )
        report.warnings.append("MSFRPCD is optional for this adapter and is not required for basic console mode.")
        return asdict(report)

    try:
        load_vendor_module(resolved_vendor_dir)
    except Exception as exc:  # pragma: no cover - depends on local environment
        report.import_error = str(exc)
        report.reason = f"Failed to import vendored msfconsole-mcp code: {exc}"
        return asdict(report)

    if not msfrpcd_found:
        report.warnings.append("msfrpcd was not found. RPC-specific workflows stay unavailable, but console mode can still run.")

    report.available = True
    return asdict(report)


class MSFConsoleLocalService:
    def __init__(
        self,
        *,
        vendor_dir: str | os.PathLike[str] | None = None,
        default_workspace: str | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.vendor_dir = resolve_vendor_dir(vendor_dir)
        self.default_workspace = (default_workspace or os.getenv("MSF_DEFAULT_WORKSPACE") or DEFAULT_WORKSPACE).strip()
        self.logger = logger or LOGGER
        self._runner = AsyncTaskRunner()
        self._lock = threading.Lock()
        self._wrapper: Any | None = None
        self._module: Any | None = None
        self._init_error: str | None = None
        self._warmup_result: dict[str, Any] | None = None

    def inspect_environment(self) -> dict[str, Any]:
        return inspect_msf_environment(self.vendor_dir)

    def warmup(self) -> dict[str, Any]:
        success, error = self._ensure_initialized()
        payload = {
            "success": success,
            "error": error,
            "vendor_dir": str(self.vendor_dir),
            "default_workspace": self.default_workspace,
        }
        self._warmup_result = payload
        return payload

    def get_msf_status(self) -> dict[str, Any]:
        environment = self.inspect_environment()
        status = {
            "service_name": "MSF Console",
            "enabled": environment["enabled"],
            "available": False,
            "environment": environment,
            "initialized": self._wrapper is not None,
            "default_workspace": self.default_workspace,
            "warmup": self._warmup_result,
        }
        if self._wrapper is None:
            status["error"] = self._init_error
            return status
        try:
            wrapper_status = self._wrapper.get_status()
            status["available"] = True
            status["wrapper_status"] = wrapper_status
        except Exception as exc:  # pragma: no cover - depends on external tooling
            status["error"] = str(exc)
        return status

    def execute_msf_command(
        self,
        *,
        command: str,
        workspace: str | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        try:
            effective_command = self._sanitize_command(command)
            if workspace and not effective_command.lstrip().startswith("workspace"):
                workspace_name = self._sanitize_segment(workspace, field_name="workspace")
                effective_command = f"workspace {workspace_name}; {effective_command}"
            result = self._call_wrapper("execute_command", effective_command, timeout=timeout)
            if result["success"]:
                result["command"] = effective_command
                result["workspace"] = workspace or self.default_workspace
            return result
        except Exception as exc:
            return self._error_payload("execute_msf_command", str(exc))

    def search_msf_modules(
        self,
        *,
        query: str,
        limit: int = 10,
        page: int = 1,
    ) -> dict[str, Any]:
        try:
            query_text = self._sanitize_command(query).strip()
            return self._call_wrapper("search_modules", query_text, limit=max(1, limit), page=max(1, page))
        except Exception as exc:
            return self._error_payload("search_msf_modules", str(exc))

    def manage_msf_workspace(
        self,
        *,
        action: str,
        workspace_name: str | None = None,
        new_name: str | None = None,
    ) -> dict[str, Any]:
        try:
            normalized_action = action.strip().lower()
            command: str
            if normalized_action in {"list", "current"}:
                command = "workspace"
            elif normalized_action == "create" and workspace_name:
                command = f"workspace -a {self._sanitize_segment(workspace_name, field_name='workspace_name')}"
            elif normalized_action == "delete" and workspace_name:
                command = f"workspace -d {self._sanitize_segment(workspace_name, field_name='workspace_name')}"
            elif normalized_action == "switch" and workspace_name:
                command = f"workspace {self._sanitize_segment(workspace_name, field_name='workspace_name')}"
            elif normalized_action == "rename" and new_name:
                if workspace_name:
                    current_name = self._sanitize_segment(workspace_name, field_name="workspace_name")
                    target_name = self._sanitize_segment(new_name, field_name="new_name")
                    command = f"workspace {current_name}; workspace -r {target_name}"
                else:
                    command = f"workspace -r {self._sanitize_segment(new_name, field_name='new_name')}"
            else:
                return self._error_payload(
                    "manage_msf_workspace",
                    "Invalid workspace action or missing required arguments.",
                    valid_actions=["list", "current", "create", "delete", "switch", "rename"],
                )

            result = self.execute_msf_command(command=command)
            if result["success"]:
                stdout = self._extract_stdout(result)
                workspaces = self._parse_workspace_list(stdout)
                result["workspaces"] = workspaces
                result["current_workspace"] = next((item["name"] for item in workspaces if item["current"]), None)
                result["action"] = normalized_action
            return result
        except Exception as exc:
            return self._error_payload("manage_msf_workspace", str(exc))

    def query_msf_db(
        self,
        *,
        operation: str,
        filters: str | None = None,
        workspace: str | None = None,
    ) -> dict[str, Any]:
        try:
            normalized_operation = operation.strip().lower()
            command_map = {
                "status": "db_status",
                "hosts": "hosts",
                "services": "services",
                "vulns": "vulns",
                "creds": "creds",
                "loot": "loot",
                "notes": "notes",
                "sessions": "sessions -l",
            }
            command = command_map.get(normalized_operation)
            if command is None:
                return self._error_payload(
                    "query_msf_db",
                    f"Unsupported DB operation: {operation}",
                    valid_operations=sorted(command_map),
                )
            if filters:
                command = f"{command} {self._sanitize_command(filters)}"
            result = self.execute_msf_command(command=command, workspace=workspace)
            if result["success"]:
                stdout = self._extract_stdout(result)
                parser_map = {
                    "hosts": self._parse_table_like_rows,
                    "services": self._parse_table_like_rows,
                    "vulns": self._parse_table_like_rows,
                    "sessions": self._parse_sessions,
                }
                parser = parser_map.get(normalized_operation)
                if parser is not None:
                    result["parsed"] = parser(stdout)
                result["operation"] = normalized_operation
            return result
        except Exception as exc:
            return self._error_payload("query_msf_db", str(exc))

    def manage_msf_sessions(
        self,
        *,
        action: str,
        session_id: str | None = None,
        command: str | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        try:
            normalized_action = action.strip().lower()
            command_string: str
            if normalized_action == "list":
                command_string = "sessions -l"
            elif normalized_action == "interact" and session_id:
                command_string = f"sessions -i {self._sanitize_segment(session_id, field_name='session_id')}"
            elif normalized_action == "execute" and session_id and command:
                safe_session = self._sanitize_segment(session_id, field_name="session_id")
                command_string = f"sessions -c {self._quote_argument(command)} {safe_session}"
            elif normalized_action == "kill" and session_id:
                command_string = f"sessions -k {self._sanitize_segment(session_id, field_name='session_id')}"
            elif normalized_action == "upgrade" and session_id:
                command_string = f"sessions -u {self._sanitize_segment(session_id, field_name='session_id')}"
            else:
                return self._error_payload(
                    "manage_msf_sessions",
                    "Invalid session action or missing required arguments.",
                    valid_actions=["list", "interact", "execute", "kill", "upgrade"],
                )

            result = self.execute_msf_command(command=command_string, timeout=timeout)
            if result["success"]:
                stdout = self._extract_stdout(result)
                if normalized_action == "list":
                    result["sessions"] = self._parse_sessions(stdout)
                result["action"] = normalized_action
                result["session_id"] = session_id
            return result
        except Exception as exc:
            return self._error_payload("manage_msf_sessions", str(exc))

    def manage_msf_module(
        self,
        *,
        action: str,
        module_path: str,
        options: Mapping[str, Any] | None = None,
        run_action: str | None = None,
        workspace: str | None = None,
    ) -> dict[str, Any]:
        try:
            safe_module = self._sanitize_segment(module_path, field_name="module_path")
            normalized_action = action.strip().lower()
            option_commands = self._build_option_commands(options or {})

            if normalized_action == "info":
                command = f"info {safe_module}"
            elif normalized_action in {"use", "options"}:
                command = "; ".join([f"use {safe_module}", *option_commands, "show options"])
            elif normalized_action == "set":
                if not option_commands:
                    return self._error_payload("manage_msf_module", "The 'set' action requires at least one option.")
                command = "; ".join([f"use {safe_module}", *option_commands, "show options"])
            elif normalized_action in {"execute", "run", "check"}:
                final_run_action = (run_action or normalized_action).strip().lower()
                if final_run_action not in {"run", "exploit", "check"}:
                    return self._error_payload(
                        "manage_msf_module",
                        f"Unsupported run_action: {run_action}",
                        valid_run_actions=["run", "exploit", "check"],
                    )
                command = "; ".join([f"use {safe_module}", *option_commands, final_run_action])
            elif normalized_action == "search_payloads":
                command = "; ".join([f"use {safe_module}", "show payloads"])
            else:
                return self._error_payload(
                    "manage_msf_module",
                    "Invalid module action.",
                    valid_actions=["info", "use", "options", "set", "execute", "run", "check", "search_payloads"],
                )

            result = self.execute_msf_command(command=command, workspace=workspace)
            if result["success"]:
                result["action"] = normalized_action
                result["module_path"] = safe_module
                if options:
                    result["options"] = dict(options)
            return result
        except Exception as exc:
            return self._error_payload("manage_msf_module", str(exc))

    def close(self) -> None:
        with self._lock:
            wrapper = self._wrapper
            self._wrapper = None
        if wrapper is not None:
            try:
                self._runner.run(wrapper.cleanup())
            except Exception:  # pragma: no cover - best effort cleanup
                pass
        self._runner.close()

    def _ensure_initialized(self) -> tuple[bool, str | None]:
        with self._lock:
            if self._wrapper is not None:
                return True, None
            environment = self.inspect_environment()
            if not environment.get("available"):
                self._init_error = str(environment.get("reason") or "MSF environment is unavailable.")
                return False, self._init_error

            try:
                _prepend_binary_dir(environment.get("msfconsole_path"))
                self._module = load_vendor_module(self.vendor_dir)
                wrapper_class = getattr(self._module, "MSFConsoleStableWrapper")
                self._wrapper = wrapper_class()
                result = self._runner.run(self._wrapper.initialize())
                success_status = getattr(self._module, "OperationStatus").SUCCESS
                if result.status != success_status:
                    self._init_error = result.error or "MSF initialization failed."
                    self._wrapper = None
                    return False, self._init_error
                self._init_error = None
                return True, None
            except Exception as exc:  # pragma: no cover - depends on local MSF installation
                self._init_error = str(exc)
                self._wrapper = None
                return False, self._init_error

    def _call_wrapper(self, method_name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        success, error = self._ensure_initialized()
        if not success:
            return self._error_payload(method_name, error or "MSF integration is unavailable.")
        assert self._wrapper is not None
        try:
            method = getattr(self._wrapper, method_name)
            result = self._runner.run(method(*args, **kwargs))
            payload = self._normalize_result(result)
            payload["success"] = payload["status"] == "success"
            return payload
        except Exception as exc:  # pragma: no cover - depends on local MSF installation
            return self._error_payload(method_name, f"MSF operation failed: {exc}")

    @staticmethod
    def _normalize_result(result: Any) -> dict[str, Any]:
        return {
            "status": getattr(getattr(result, "status", None), "value", str(getattr(result, "status", "unknown"))),
            "data": getattr(result, "data", None),
            "execution_time": getattr(result, "execution_time", None),
            "error": getattr(result, "error", None),
            "warnings": getattr(result, "warnings", None) or [],
        }

    @staticmethod
    def _error_payload(operation: str, error: str, **extra: Any) -> dict[str, Any]:
        return {
            "success": False,
            "status": "error",
            "operation": operation,
            "error": error,
            **extra,
        }

    @staticmethod
    def _sanitize_command(command: str) -> str:
        cleaned = str(command or "").replace("\x00", "").replace("\r", "").strip()
        if not cleaned:
            raise ValueError("MSF command must not be empty.")
        return cleaned

    @staticmethod
    def _sanitize_segment(value: str, *, field_name: str) -> str:
        cleaned = str(value or "").replace("\x00", "").replace("\r", "").replace("\n", " ").strip()
        if not cleaned:
            raise ValueError(f"{field_name} must not be empty.")
        if ";" in cleaned:
            raise ValueError(f"{field_name} must not contain ';'.")
        return cleaned

    @classmethod
    def _quote_argument(cls, value: str) -> str:
        cleaned = cls._sanitize_command(value)
        return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'

    @classmethod
    def _build_option_commands(cls, options: Mapping[str, Any]) -> list[str]:
        commands: list[str] = []
        for key, value in options.items():
            if value is None:
                continue
            option_name = cls._sanitize_segment(str(key), field_name="option_name")
            option_value = cls._sanitize_segment(str(value), field_name=f"option[{option_name}]")
            commands.append(f"set {option_name} {option_value}")
        return commands

    @staticmethod
    def _extract_stdout(result: Mapping[str, Any]) -> str:
        data = result.get("data")
        if isinstance(data, Mapping):
            stdout = data.get("stdout")
            if isinstance(stdout, str):
                return stdout
        return ""

    @staticmethod
    def _parse_workspace_list(output: str) -> list[dict[str, Any]]:
        workspaces: list[dict[str, Any]] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line == "Workspaces" or line.startswith("="):
                continue
            current = line.startswith("*")
            name = line.lstrip("* ").strip()
            if name:
                workspaces.append({"name": name, "current": current})
        return workspaces

    @staticmethod
    def _parse_sessions(output: str) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        lines = output.splitlines()
        header_index = -1
        for index, raw_line in enumerate(lines):
            line = raw_line.strip().lower()
            if "id" in line and "type" in line:
                header_index = index
                break
        if header_index == -1:
            return sessions
        for raw_line in lines[header_index + 2 :]:
            line = raw_line.strip()
            if not line or line.startswith("-") or line.startswith("="):
                continue
            parts = line.split(None, 4)
            if len(parts) >= 3:
                sessions.append(
                    {
                        "id": parts[0],
                        "name": parts[1],
                        "type": parts[2],
                        "information": parts[3] if len(parts) > 3 else "",
                        "connection": parts[4] if len(parts) > 4 else "",
                    }
                )
        return sessions

    @staticmethod
    def _parse_table_like_rows(output: str) -> list[str]:
        rows: list[str] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("="):
                continue
            rows.append(line)
        return rows


_SERVICE_LOCK = threading.Lock()
_DEFAULT_SERVICE: MSFConsoleLocalService | None = None


def get_service() -> MSFConsoleLocalService:
    global _DEFAULT_SERVICE
    with _SERVICE_LOCK:
        if _DEFAULT_SERVICE is None:
            _DEFAULT_SERVICE = MSFConsoleLocalService()
        return _DEFAULT_SERVICE


def close_service() -> None:
    global _DEFAULT_SERVICE
    with _SERVICE_LOCK:
        service = _DEFAULT_SERVICE
        _DEFAULT_SERVICE = None
    if service is not None:
        service.close()


atexit.register(close_service)


def get_msf_status() -> dict[str, Any]:
    """Return MSF availability, warmup state, and runtime diagnostics."""
    return get_service().get_msf_status()


def execute_msf_command(
    command: Annotated[str, "Raw Metasploit console command to execute."],
    workspace: Annotated[str | None, "Optional Metasploit workspace to switch into first."] = None,
    timeout: Annotated[int | None, "Optional timeout in seconds."] = None,
) -> dict[str, Any]:
    """
    Execute a single focused msfconsole batch command.

    Returns a structured payload containing stdout, stderr, status, warnings, and timing information.
    """
    return get_service().execute_msf_command(command=command, workspace=workspace, timeout=timeout)


def search_msf_modules(
    query: Annotated[str, "Metasploit module search query, for example 'platform:windows smb'."],
    limit: Annotated[int, "Maximum number of modules to return on the requested page."] = 10,
    page: Annotated[int, "1-based page number for paginated search results."] = 1,
) -> dict[str, Any]:
    """
    Search Metasploit modules using the vendored stable wrapper.

    Results are paginated and already structured for agent consumption.
    """
    return get_service().search_msf_modules(query=query, limit=limit, page=page)


def manage_msf_workspace(
    action: Annotated[str, "One of: list, current, create, delete, switch, rename."],
    workspace_name: Annotated[str | None, "Workspace name used by create, delete, switch, or rename."] = None,
    new_name: Annotated[str | None, "New name used by the rename action."] = None,
) -> dict[str, Any]:
    """
    Manage Metasploit workspaces.

    The adapter keeps the interface stable even when the upstream project changes.
    """
    return get_service().manage_msf_workspace(action=action, workspace_name=workspace_name, new_name=new_name)


def query_msf_db(
    operation: Annotated[str, "One of: status, hosts, services, vulns, creds, loot, notes, sessions."],
    filters: Annotated[str | None, "Optional extra arguments appended to the DB command."] = None,
    workspace: Annotated[str | None, "Optional workspace to activate before running the query."] = None,
) -> dict[str, Any]:
    """
    Query common Metasploit database-backed views.

    When Metasploit DB support is unavailable the payload contains a readable error instead of crashing.
    """
    return get_service().query_msf_db(operation=operation, filters=filters, workspace=workspace)


def manage_msf_sessions(
    action: Annotated[str, "One of: list, interact, execute, kill, upgrade."],
    session_id: Annotated[str | None, "Session identifier required by non-list actions."] = None,
    command: Annotated[str | None, "Command executed inside the session when action=execute."] = None,
    timeout: Annotated[int | None, "Optional timeout override in seconds."] = None,
) -> dict[str, Any]:
    """
    List or manage active Metasploit sessions through a stable wrapper.

    The return payload always stays JSON-serializable for runtime compatibility.
    """
    return get_service().manage_msf_sessions(action=action, session_id=session_id, command=command, timeout=timeout)


def manage_msf_module(
    action: Annotated[str, "One of: info, use, options, set, execute, run, check, search_payloads."],
    module_path: Annotated[str, "Metasploit module path such as exploit/windows/smb/ms17_010_eternalblue."],
    options: Annotated[dict[str, Any] | None, "Optional module options passed as key/value pairs."] = None,
    run_action: Annotated[str | None, "Optional run verb override for execute actions: run, exploit, or check."] = None,
    workspace: Annotated[str | None, "Optional workspace to activate first."] = None,
) -> dict[str, Any]:
    """
    Inspect, configure, or execute a single Metasploit module.

    This intentionally exposes a smaller stable subset instead of forwarding every upstream tool directly.
    """
    return get_service().manage_msf_module(
        action=action,
        module_path=module_path,
        options=options,
        run_action=run_action,
        workspace=workspace,
    )


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def create_fastmcp_server(name: str):
    if FastMCP is None:
        return None
    try:
        return FastMCP(name, include_fastmcp_meta=False)
    except TypeError:
        return FastMCP(name)


mcp = create_fastmcp_server("MSF Console")


if mcp is not None:
    get_msf_status = mcp.tool(output_schema=None)(get_msf_status)
    execute_msf_command = mcp.tool(output_schema=None)(execute_msf_command)
    search_msf_modules = mcp.tool(output_schema=None)(search_msf_modules)
    manage_msf_workspace = mcp.tool(output_schema=None)(manage_msf_workspace)
    query_msf_db = mcp.tool(output_schema=None)(query_msf_db)
    manage_msf_sessions = mcp.tool(output_schema=None)(manage_msf_sessions)
    manage_msf_module = mcp.tool(output_schema=None)(manage_msf_module)


if __name__ == "__main__":
    if mcp is None:
        raise RuntimeError("fastmcp is required only when running msfconsole_mcp.py as an HTTP MCP service.")

    parser = argparse.ArgumentParser(description="ctf MSF Console FastMCP adapter")
    parser.add_argument("--host", type=str, default=os.getenv("MSF_MCP_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.getenv("MSF_MCP_PORT", str(DEFAULT_PORT))))
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("CTF_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    LOGGER.info(json.dumps({"event": "msf_mcp_server_start", "host": args.host, "port": args.port}))
    mcp.run(transport="streamable-http", host=args.host, port=args.port)
