from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re

import yaml


FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)


@dataclass(frozen=True)
class PromptSpec:
    path: Path
    metadata: dict[str, Any]
    body: str


def load_prompt(prompt_path: str | Path) -> PromptSpec:
    path = Path(prompt_path).expanduser().resolve()
    text = path.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(text)
    if not match:
        return PromptSpec(path=path, metadata={}, body=text.strip())

    frontmatter, body = match.groups()
    metadata = yaml.safe_load(frontmatter) or {}
    return PromptSpec(path=path, metadata=metadata, body=body.strip())
