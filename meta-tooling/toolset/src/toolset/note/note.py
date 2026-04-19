from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, List

from core import namespace, tool, toolset


namespace()


def resolve_note_dir() -> Path:
    configured = os.getenv("CTF_NOTES_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    workspace = os.getenv("CTF_WORKSPACE")
    if workspace:
        return Path(workspace).expanduser().resolve() / "notes"
    return Path.cwd() / "notes"


@toolset()
class Note:
    """
    A toolset for AI Agent to manage persistent notes for state tracking,
    information gathering, and long-term memory across different execution steps.
    """

    def __init__(self):
        self.note_dir = resolve_note_dir()
        self.note_dir.mkdir(parents=True, exist_ok=True)

    def _get_filepath(self, title: str) -> Path:
        safe_title = "".join(c if c.isalnum() or c in (" ", "-") else "_" for c in title).strip()
        if not safe_title:
            safe_title = "untitled_note"
        return self.note_dir / f"{safe_title}.md"

    @tool()
    def save_note(
        self,
        title: Annotated[str, "A concise, unique title for the note."],
        content: Annotated[str, "The content of the note (Markdown format is recommended)."],
    ) -> str:
        """
        Saves a new note or overwrites an existing note with the given title.
        The note is saved to a persistent file for later retrieval.
        """
        filepath = self._get_filepath(title)
        try:
            filepath.write_text(content, encoding="utf-8")
            return f"Note '{title}' successfully saved to {filepath}"
        except Exception as exc:
            return f"Error saving note '{title}': {exc}"

    @tool()
    def read_note(
        self,
        title: Annotated[str, "The title of the note to read."],
    ) -> str:
        """
        Reads and returns the content of the note with the given title.
        Returns an error message if the note is not found.
        """
        filepath = self._get_filepath(title)
        if not filepath.exists():
            return f"Error: Note '{title}' not found. Use list_notes() to see available titles."
        try:
            return filepath.read_text(encoding="utf-8")
        except Exception as exc:
            return f"Error reading note '{title}': {exc}"

    @tool()
    def list_notes(self) -> List[str]:
        """
        Lists all available note titles.
        """
        try:
            return [file.stem for file in sorted(self.note_dir.glob("*.md"))]
        except Exception as exc:
            return [f"Error listing notes: {exc}"]
