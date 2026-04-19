from __future__ import annotations

import argparse
import io
import os
import sys
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, TextIO

from dotenv import load_dotenv

from runtime.hackathon import HackathonOrchestrator
from runtime.runtime import Runtime, build_default_task


class _TimestampedConsoleStream(io.TextIOBase):
    def __init__(self, *, terminal: TextIO, log_handle: TextIO, write_lock: threading.RLock) -> None:
        self._terminal = terminal
        self._log_handle = log_handle
        self._write_lock = write_lock
        self._buffer = ""

    @property
    def encoding(self) -> str:
        return getattr(self._terminal, "encoding", "utf-8")

    @property
    def errors(self) -> str | None:
        return getattr(self._terminal, "errors", None)

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        isatty = getattr(self._terminal, "isatty", None)
        return bool(isatty()) if callable(isatty) else False

    def fileno(self) -> int:
        return self._terminal.fileno()

    def write(self, data: str) -> int:
        if not data:
            return 0
        text = str(data)
        with self._write_lock:
            written = self._terminal.write(text)
            self._terminal.flush()
            self._buffer += text
            self._drain_complete_lines()
        return written if isinstance(written, int) else len(text)

    def flush(self) -> None:
        with self._write_lock:
            self._terminal.flush()
            self._flush_pending_line()
            self._log_handle.flush()

    def _drain_complete_lines(self) -> None:
        while True:
            newline_index = self._buffer.find("\n")
            if newline_index < 0:
                return
            line = self._buffer[:newline_index]
            self._buffer = self._buffer[newline_index + 1 :]
            self._write_log_line(line)

    def _flush_pending_line(self) -> None:
        if not self._buffer:
            return
        line = self._buffer
        self._buffer = ""
        self._write_log_line(line)

    def _write_log_line(self, line: str) -> None:
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        normalized_line = line.rstrip("\r")
        self._log_handle.write(f"[{timestamp}] {normalized_line}\n")
        self._log_handle.flush()


@contextmanager
def _capture_console_output(project_root: Path) -> Iterator[Path]:
    start_time = datetime.now().astimezone()
    log_dir = project_root / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{start_time.strftime('%Y%m%d_%H%M%S_%f')}.log"

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    previous_console_log_path = os.environ.get("CTF_CONSOLE_LOG_PATH")
    os.environ["CTF_CONSOLE_LOG_PATH"] = str(log_path)

    with log_path.open("a", encoding="utf-8") as log_handle:
        write_lock = threading.RLock()
        stdout_tee = _TimestampedConsoleStream(
            terminal=original_stdout,
            log_handle=log_handle,
            write_lock=write_lock,
        )
        stderr_tee = _TimestampedConsoleStream(
            terminal=original_stderr,
            log_handle=log_handle,
            write_lock=write_lock,
        )
        sys.stdout = stdout_tee
        sys.stderr = stderr_tee
        try:
            yield log_path
        finally:
            stdout_tee.flush()
            stderr_tee.flush()
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            if previous_console_log_path is None:
                os.environ.pop("CTF_CONSOLE_LOG_PATH", None)
            else:
                os.environ["CTF_CONSOLE_LOG_PATH"] = previous_console_log_path


def main() -> int:
    project_root = Path(__file__).resolve().parent
    load_dotenv(project_root / ".env", override=True)
    load_dotenv(override=False)

    parser = argparse.ArgumentParser(description="ctf local LangGraph runtime")
    parser.add_argument("--ctf", type=str, help="CTF challenge URL or description")
    parser.add_argument(
        "--workspace",
        type=str,
        default="workspace",
        help="Workspace directory for logs, notes, notebooks, and artifacts",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="Maximum LangGraph reasoning steps before stopping. If omitted, use CTF_MAX_STEPS when set; otherwise default to 96.",
    )
    parser.add_argument(
        "--auto-hackathon",
        action="store_true",
        help="Run the official hackathon orchestrator mode instead of the legacy single-task mode",
    )
    parser.add_argument(
        "--only-codes",
        type=str,
        default="",
        help="Comma-separated challenge codes to include in auto-hackathon mode",
    )
    parser.add_argument(
        "--skip-codes",
        type=str,
        default="",
        help="Comma-separated challenge codes to skip in auto-hackathon mode",
    )
    parser.add_argument(
        "--hint-policy-mode",
        type=str,
        default="default",
        help="Hint policy mode for auto-hackathon mode. Defaults to 'default'.",
    )
    parser.add_argument(
        "--max-concurrent-challenges",
        type=int,
        default=3,
        help="Maximum number of challenges to solve concurrently in auto-hackathon mode; official limit is 3.",
    )
    args = parser.parse_args()
    workspace = Path(args.workspace).expanduser().resolve()

    if not args.auto_hackathon and not args.ctf:
        parser.error("--ctf is required unless --auto-hackathon is enabled")

    with _capture_console_output(project_root):
        if args.auto_hackathon:
            orchestrator = HackathonOrchestrator(
                workspace=workspace,
                max_steps=args.max_steps,
                only_codes=_split_codes(args.only_codes),
                skip_codes=_split_codes(args.skip_codes),
                hint_policy_mode=args.hint_policy_mode,
                max_concurrent_challenges=args.max_concurrent_challenges,
            )
            try:
                print(f"[+] Workspace: {workspace}")
                print("[+] 启动自动化闯关编排器...")
                summary = orchestrator.run()
                print("[+] 自动化闯关结束")
                print(
                    "[+] 汇总: "
                    f"visible={summary['total_visible']}, "
                    f"attempted={summary['total_attempted']}, "
                    f"solved={summary['total_solved']}, "
                    f"give_up={summary['total_give_up']}"
                )
                print(f"[+] 结果汇总: {summary['summary_path']}")
                print(f"[+] 编排器日志: {summary['orchestrator_log_path']}")
                return 0
            except Exception as exc:
                print(f"[-] 自动化闯关失败: {exc}", file=sys.stderr)
                print(f"[-] 编排器日志: {workspace / 'hackathon' / 'orchestrator.jsonl'}", file=sys.stderr)
                return 1

        runtime = Runtime(workspace=workspace, max_steps=args.max_steps)
        task = build_default_task(args.ctf or "")

        try:
            print(f"[+] Workspace: {workspace}")
            print("[+] 启动本地 LangGraph runtime...")
            result = runtime.run(task)
            print("[+] 结束运行")
            print(result.final_output)
            if result.flag:
                print(f"[+] flag: {result.flag}")
            print(f"[+] 详细日志: {result.log_path}")
            return 0
        except Exception as exc:
            print(f"[-] 运行失败: {exc}", file=sys.stderr)
            if runtime.log_path is not None:
                print(f"[-] 详细日志: {runtime.log_path}", file=sys.stderr)
            return 1
        finally:
            runtime.cleanup()


def _split_codes(raw_value: str) -> list[str]:
    return [part.strip() for part in raw_value.split(",") if part.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
