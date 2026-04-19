"""
The proxy is used to view HTTP traffic from the browser.
You can check the usage by running help(toolset.proxy).
"""
from core import namespace

namespace()

import os

from .proxy import Proxy

caido_port = os.getenv("CAIDO_PORT")
proxy = Proxy(
    f"http://localhost:{caido_port}/graphql" if caido_port else None,
    os.getenv("CAIDO_TOKEN"),
)

__all__ = ["proxy"]
