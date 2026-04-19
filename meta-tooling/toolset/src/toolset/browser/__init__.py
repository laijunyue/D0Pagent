"""
The browser is used to control the web browser, including operations such as opening web pages, clicking, and uploading files.
You can view the usage instructions by running help(toolset.browser).
"""
from core import namespace

namespace()

import os

from .browser import Browser

browser = Browser(f"http://localhost:{os.getenv('BROWSER_PORT', '9222')}")

__all__ = ["browser"]
