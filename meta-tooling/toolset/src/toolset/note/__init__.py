"""
Manage persistent notes for state tracking, information gathering, and long-term memory across different execution steps.
"""
from core import namespace

namespace()

from .note import Note

note = Note()

__all__ = ['note']