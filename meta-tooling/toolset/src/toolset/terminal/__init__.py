"""
The terminal is used to manage command-line terminal sessions and can also execute system commands within the terminal to view their output.
You have access to common Linux commands and security tools such as httpx, katana, nuclei, ffuf, sqlmap, dirsearch, nmap, and masscan.
You can view the usage instructions by running help(toolset.terminal).
"""
from core import namespace

namespace()

from .terminal import Terminal

terminal = Terminal()

__all__ = ['terminal']
