""""""
from core import namespace

namespace()

from .proxy import proxy
from .terminal import terminal
from .browser import browser
from .note import note

__all__ = ['proxy','terminal','browser', 'note']