from __future__ import annotations

import os
import subprocess
import time
from typing import Annotated, Optional

import libtmux
import psutil

from core import namespace, tool, toolset


namespace()


def env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def resolve_workspace() -> str:
    workspace = os.getenv("CTF_WORKSPACE")
    if workspace:
        return os.path.abspath(workspace)
    return os.path.abspath(os.getcwd())


@toolset()
class Terminal:
    def __init__(self):
        self.server = libtmux.Server()

    @tool()
    def list_sessions(self) -> list:
        """List terminal sessions."""
        return [session.session_id.replace("$", "") for session in self.server.sessions]

    @tool()
    def kill_session(self, session_id: int):
        """kill a session"""
        session_ids = [session.session_id.replace("$", "") for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        sessions[0].kill()

    @tool()
    def new_session(self) -> int:
        """Open a new terminal window as a new session."""
        start_directory = resolve_workspace()
        os.makedirs(start_directory, exist_ok=True)
        session = self.server.new_session(attach=False, start_directory=start_directory)
        session.set_option("status", "off")
        session_id = session.session_id.replace("$", "")

        if not env_flag("NO_VISION", True):
            xfce4_terminal_running = any("xfce4-terminal" in process.name() for process in psutil.process_iter())
            try:
                proc = subprocess.Popen(
                    [
                        "xfce4-terminal",
                        "--title",
                        f"AI-Terminal-{session_id}",
                        "--command",
                        f"tmux attach-session -t {session_id}",
                        "--hide-scrollbar",
                    ]
                )
                if xfce4_terminal_running:
                    proc.wait()
                else:
                    time.sleep(0.5)
                session.set_option("destroy-unattached", "on")
            except FileNotFoundError:
                pass
        return int(session_id)

    @tool()
    def get_output(
        self,
        session_id: int,
        start: Annotated[
            Optional[str],
            "Specify the starting line number. Zero is the first line of the visible pane. Positive numbers are lines in the visible pane. Negative numbers are lines in the history. - is the start of the history. Default: None",
        ] = "",
        end: Annotated[
            Optional[str],
            "Specify the ending line number. Zero is the first line of the visible pane. Positive numbers are lines in the visible pane. Negative numbers are lines in the history. - is the end of the visible pane Default: None",
        ] = "",
    ) -> str:
        """Get the output of a terminal session by session id."""
        session_ids = [session.session_id.replace("$", "") for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        return "\n".join(session.windows[0].panes[0].capture_pane(start, end))

    @tool()
    def send_keys(
        self,
        session_id: int,
        keys: Annotated[str, "Text or input into terminal window"],
        enter: Annotated[bool, "Send enter after sending the input."],
    ) -> str:
        """
        Send keys to a terminal session by session id.

        Examaple:
            To execute 'whoami' command:
            ```
            import toolset

            toolset.terminal.send_keys(session_id=0, keys="whoami", enter=True)
            ```

            To press Ctrl+c:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-c", enter=False)
            ```

            To press Esc:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-[", enter=False)
            ```

            To press up arrow:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-Up", enter=False)
            ```

            To press tab:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-i", enter=False)
            ```

            After execution, it will wait for 1 second before returning the result. If the command is not completed at this time, you need to call the relevant function again to view the pane output
        """
        session_ids = [session.session_id.replace("$", "") for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        session.windows[0].panes[0].send_keys(keys, enter=enter)
        time.sleep(1)
        return "\n".join(session.windows[0].panes[0].capture_pane())
