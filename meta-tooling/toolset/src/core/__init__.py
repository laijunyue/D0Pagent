"""POM Core - Decorators for namespace, tool, and toolset."""

import builtins
from .docstring import namespace, tool, toolset, registry, DocModel

# Monkeypatch help to use man()
_original_help = builtins.help

def help(obj=None):
    """Enhanced help that uses man() if available."""
    if obj is None:
        return _original_help()

    if hasattr(obj, 'man') and callable(obj.man):
        print(obj.man())
    else:
        _original_help(obj)

builtins.help = help

__all__ = ["namespace", "tool", "toolset", "registry", "DocModel"]
