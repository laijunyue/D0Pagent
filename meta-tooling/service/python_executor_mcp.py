from __future__ import annotations

import argparse
import os
import re
import time
from queue import Empty
from typing import Annotated, Optional

import nbformat
from jupyter_client import KernelManager
from nbformat import v4 as nbf

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover - optional in local runtime mode
    FastMCP = None


class PythonExecutor:
    def __init__(self, path: str | None = None, kernel_env: dict[str, str] | None = None):
        workspace = os.getenv("CTF_WORKSPACE", os.getcwd())
        default_path = os.path.join(workspace, "python_sessions")
        self.path = os.path.abspath(path or os.getenv("CTF_SESSION_DIR", default_path))
        self.kernel_env = os.environ.copy()
        if kernel_env:
            self.kernel_env.update({key: str(value) for key, value in kernel_env.items()})
        os.makedirs(self.path, exist_ok=True)
        self.sessions: dict[str, dict[str, object]] = {}

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        return re.sub(r"[^\w\-.]", "_", name)

    def _get_unique_filepath(self, session_name: str) -> str:
        sanitized_name = self._sanitize_filename(session_name)
        base_path = os.path.join(self.path, f"{sanitized_name}.ipynb")
        if not os.path.exists(base_path):
            return base_path
        index = 1
        while True:
            new_path = os.path.join(self.path, f"{sanitized_name}_{index}.ipynb")
            if not os.path.exists(new_path):
                return new_path
            index += 1

    def _create_session(self, session_name: str) -> dict[str, object]:
        km = KernelManager(kernel_name="python3")
        km.start_kernel(env=self.kernel_env)
        client = km.client()
        client.start_channels()
        try:
            client.wait_for_ready(timeout=3)
        except RuntimeError:
            client.stop_channels()
            km.shutdown_kernel(now=True)
            raise RuntimeError("Kernel did not start in time.")

        filepath = self._get_unique_filepath(session_name)
        notebook = nbf.new_notebook()
        self.sessions[session_name] = {
            "km": km,
            "client": client,
            "notebook": notebook,
            "filepath": filepath,
            "execution_count": 1,
        }
        return self.sessions[session_name]

    @staticmethod
    def _format_output(output_objects) -> list[dict]:
        formatted_outputs: list[dict] = []
        for out in output_objects:
            output_type = out.output_type
            if output_type == "stream":
                formatted_outputs.append({"type": "stream", "name": out.name, "text": out.text})
            elif output_type == "execute_result":
                formatted_outputs.append(
                    {
                        "type": "execute_result",
                        "data": dict(out.data),
                        "execution_count": out.execution_count,
                    }
                )
            elif output_type == "display_data":
                formatted_outputs.append({"type": "display_data", "data": dict(out.data)})
            elif output_type == "error":
                formatted_outputs.append(
                    {
                        "type": "error",
                        "ename": out.ename,
                        "evalue": out.evalue,
                        "traceback": out.traceback,
                    }
                )
        return formatted_outputs

    def list_sessions(self) -> list[str]:
        return list(self.sessions.keys())

    def execute_code(self, session_name: str, code: str, timeout: int = 10) -> list[dict]:
        if session_name not in self.sessions:
            self._create_session(session_name)

        session = self.sessions[session_name]
        client = session["client"]
        km = session["km"]
        notebook = session["notebook"]
        filepath = session["filepath"]
        exec_count = session["execution_count"]

        cell = nbf.new_code_cell(code, execution_count=exec_count)
        cell.outputs = []
        notebook.cells.append(cell)
        with open(filepath, "w", encoding="utf-8") as handle:
            nbformat.write(notebook, handle)

        msg_id = client.execute(code)
        output_objects = []
        start_time = time.time()

        try:
            shell_reply_received = False
            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    timeout_message = f"Execution timeout after {timeout} seconds. Attempting to interrupt..."
                    output_objects.append(nbf.new_output("display_data", data={"text/plain": f"[SYSTEM] {timeout_message}"}))
                    try:
                        km.interrupt_kernel()
                        time.sleep(1)
                        try:
                            while True:
                                msg = client.get_iopub_msg(timeout=0.1)
                                if msg["parent_header"].get("msg_id") == msg_id:
                                    msg_type = msg["header"]["msg_type"]
                                    if msg_type == "status" and msg["content"]["execution_state"] == "idle":
                                        break
                        except Empty:
                            pass
                        output_objects.append(
                            nbf.new_output(
                                "display_data",
                                data={"text/plain": "[SYSTEM] Kernel interrupted. Session state preserved."},
                            )
                        )
                    except Exception as exc:
                        output_objects.append(
                            nbf.new_output(
                                "display_data",
                                data={"text/plain": f"[SYSTEM] Failed to interrupt kernel: {repr(exc)}"},
                            )
                        )
                    break

                try:
                    msg = client.get_iopub_msg(timeout=0.1)
                    if msg["parent_header"].get("msg_id") != msg_id:
                        continue

                    msg_type = msg["header"]["msg_type"]
                    content = msg["content"]
                    if msg_type == "status" and content["execution_state"] == "idle":
                        break
                    if msg_type == "stream":
                        output_objects.append(
                            nbf.new_output("stream", name=content.get("name", "stdout"), text=content.get("text", ""))
                        )
                    elif msg_type == "execute_result":
                        output_objects.append(
                            nbf.new_output(
                                "execute_result",
                                data=content.get("data", {}),
                                execution_count=exec_count,
                            )
                        )
                    elif msg_type == "display_data":
                        output_objects.append(nbf.new_output("display_data", data=content.get("data", {})))
                    elif msg_type == "error":
                        output_objects.append(
                            nbf.new_output(
                                "error",
                                ename=content.get("ename", ""),
                                evalue=content.get("evalue", ""),
                                traceback=content.get("traceback", []),
                            )
                        )
                except Empty:
                    if not shell_reply_received:
                        try:
                            client.get_shell_msg(timeout=0.1)
                            shell_reply_received = True
                        except Empty:
                            pass
                    continue
        except Exception as exc:
            output_objects.append(
                nbf.new_output(
                    "display_data",
                    data={"text/plain": f"[SYSTEM] Failed to execute code or retrieve output: {repr(exc)}"},
                )
            )

        cell.outputs = output_objects if output_objects else []
        with open(filepath, "w", encoding="utf-8") as handle:
            nbformat.write(notebook, handle)

        session["execution_count"] = exec_count + 1
        return self._format_output(output_objects)

    def close_session(self, session_name: str) -> bool:
        if session_name not in self.sessions:
            return False
        session = self.sessions.pop(session_name)
        session["client"].stop_channels()
        session["km"].shutdown_kernel(now=True)
        return True

    def close_all_sessions(self) -> None:
        for session_name in list(self.sessions.keys()):
            self.close_session(session_name)


def create_fastmcp_server(name: str):
    if FastMCP is None:
        return None
    try:
        return FastMCP(name, include_fastmcp_meta=False)
    except TypeError:
        return FastMCP(name)


python_executer = PythonExecutor()
mcp = create_fastmcp_server("Python Executor")


def execute_code(
    session_name: Annotated[str, "Unique session ID. Same name shares state (vars, imports)."],
    code: Annotated[str, "Python code (multi-line OK). Runs in Jupyter kernel. Supports `%pip install pkg` and `!shell_cmd`."],
    timeout: Annotated[Optional[int], "Max seconds (default: 10). Timeout interrupts but keeps session alive."],
) -> list[dict]:
    """
    Run Python code in a stateful Jupyter kernel.

    - Preserves variables/functions across calls.
    - Supports magic `%pip` and shell `!cmd`.
    - Built-in toolset library allows you to control the browser, command-line terminal, proxy analysis tools, etc. in the local runtime. Execute the following code to view help:
    ```
    import toolset
    help(toolset)
    ```
    """
    return python_executer.execute_code(
        session_name=session_name,
        code=code,
        timeout=timeout or 10,
    )


def list_sessions() -> list[str]:
    """Return list of active session names."""
    return python_executer.list_sessions()


def close_session(session_name: Annotated[str, "Session to close."]) -> bool:
    """Close a session."""
    return python_executer.close_session(session_name)


if mcp is not None:
    execute_code = mcp.tool(output_schema=None)(execute_code)
    list_sessions = mcp.tool(output_schema=None)(list_sessions)
    close_session = mcp.tool(output_schema=None)(close_session)


if __name__ == "__main__":
    if mcp is None:
        raise RuntimeError("fastmcp is required only when running python_executor_mcp.py as an HTTP MCP service.")
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()
    mcp.run(transport="streamable-http", host=args.host, port=args.port)
