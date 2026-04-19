from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from typing import Any, Callable


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVICE_FILE = PROJECT_ROOT / "meta-tooling" / "service" / "msfconsole_mcp.py"
_SERVICE_MODULE_NAME = "ctf_msfconsole_service_adapter"
_SERVICE_MODULE_LOCK = threading.Lock()

ServiceStatusProvider = Callable[[], dict[str, Any]]


class MSFClient:
    def __init__(
        self,
        *,
        service_status_provider: ServiceStatusProvider | None = None,
        vendor_dir: str | Path | None = None,
        default_workspace: str = "default",
        service_file: str | Path = SERVICE_FILE,
    ) -> None:
        self.service_status_provider = service_status_provider
        self.vendor_dir = Path(vendor_dir).expanduser().resolve() if vendor_dir is not None else None
        self.default_workspace = default_workspace
        self.service_file = Path(service_file).expanduser().resolve()
        self.module = None
        self.service = None
        self.import_error: str | None = None
        self.warmup_result: dict[str, Any] | None = None
        self._load_service_module()

    def inspect_environment(self) -> dict[str, Any]:
        if self.module is None:
            return self._unavailable_payload("inspect_environment", self.import_error or "MSF service module is unavailable.")
        try:
            return self.module.inspect_msf_environment(self.vendor_dir)
        except Exception as exc:
            return self._unavailable_payload("inspect_environment", f"Failed to inspect MSF environment: {exc}")

    def warmup(self) -> dict[str, Any]:
        if self.service is None:
            self.warmup_result = self._unavailable_payload("warmup", self.import_error or "MSF service module is unavailable.")
            return self.warmup_result
        try:
            self.warmup_result = self.service.warmup()
            return self.warmup_result
        except Exception as exc:
            self.warmup_result = self._unavailable_payload("warmup", f"MSF warmup failed: {exc}")
            return self.warmup_result

    def is_available(self) -> bool:
        if self.service is None:
            return False
        if not (self.warmup_result or {}).get("success", False):
            self.warmup()
        return bool((self.warmup_result or {}).get("success", False))

    def get_service_status(self) -> dict[str, Any]:
        if self.service_status_provider is None:
            return {"enabled": False, "running": False, "available": False}
        try:
            return self.service_status_provider()
        except Exception as exc:
            return {"enabled": True, "running": False, "available": False, "error": str(exc)}

    def get_status(self) -> dict[str, Any]:
        if self.service is None:
            return self._unavailable_payload("get_status", self.import_error or "MSF service module is unavailable.")
        try:
            payload = self.service.get_msf_status()
            payload["service_process"] = self.get_service_status()
            payload["client_available"] = self.is_available()
            payload["local_warmup_success"] = bool((self.warmup_result or {}).get("success", False))
            payload["warmup"] = self.warmup_result
            return payload
        except Exception as exc:
            return self._unavailable_payload("get_status", f"Failed to gather MSF status: {exc}")

    def execute_command(self, **kwargs: Any) -> dict[str, Any]:
        return self._invoke("execute_command", lambda: self.service.execute_msf_command(**kwargs))

    def search_modules(self, **kwargs: Any) -> dict[str, Any]:
        return self._invoke("search_modules", lambda: self.service.search_msf_modules(**kwargs))

    def workspace(self, **kwargs: Any) -> dict[str, Any]:
        return self._invoke("workspace", lambda: self.service.manage_msf_workspace(**kwargs))

    def db_query(self, **kwargs: Any) -> dict[str, Any]:
        return self._invoke("db_query", lambda: self.service.query_msf_db(**kwargs))

    def session(self, **kwargs: Any) -> dict[str, Any]:
        return self._invoke("session", lambda: self.service.manage_msf_sessions(**kwargs))

    def module_action(self, **kwargs: Any) -> dict[str, Any]:
        return self._invoke("module", lambda: self.service.manage_msf_module(**kwargs))

    def close(self) -> None:
        if self.service is None:
            return
        try:
            self.service.close()
        finally:
            self.service = None

    def _invoke(self, operation: str, callback: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        if self.service is None:
            return self._unavailable_payload(operation, self.import_error or "MSF service module is unavailable.")
        if not (self.warmup_result or {}).get("success", False):
            self.warmup()
        if not (self.warmup_result or {}).get("success", False):
            service_status = self.get_service_status()
            error = "MSF local service warmup failed."
            if self.warmup_result and self.warmup_result.get("error"):
                error = str(self.warmup_result["error"])
            payload = self._unavailable_payload(operation, error)
            payload["service_process"] = service_status
            return payload
        try:
            payload = callback()
            payload["service_process"] = self.get_service_status()
            return payload
        except Exception as exc:
            return self._unavailable_payload(operation, f"MSF client invocation failed: {exc}")

    def _load_service_module(self) -> None:
        if not self.service_file.exists():
            self.import_error = f"MSF service adapter file not found: {self.service_file}"
            return

        try:
            with _SERVICE_MODULE_LOCK:
                module = sys.modules.get(_SERVICE_MODULE_NAME)
                if module is None or not hasattr(module, "MSFConsoleLocalService"):
                    spec = importlib.util.spec_from_file_location(_SERVICE_MODULE_NAME, self.service_file)
                    if spec is None or spec.loader is None:
                        raise RuntimeError(f"Unable to load service module from {self.service_file}")
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[_SERVICE_MODULE_NAME] = module
                    spec.loader.exec_module(module)
            self.module = module
            self.service = module.MSFConsoleLocalService(
                vendor_dir=self.vendor_dir,
                default_workspace=self.default_workspace,
            )
        except Exception as exc:
            self.import_error = str(exc)
            self.module = None
            self.service = None

    def _unavailable_payload(self, operation: str, error: str) -> dict[str, Any]:
        return {
            "success": False,
            "status": "unavailable",
            "operation": operation,
            "error": error,
            "service_process": self.get_service_status(),
            "warmup": self.warmup_result,
        }
