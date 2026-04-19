from __future__ import annotations

import argparse
import os
import time

from playwright.sync_api import sync_playwright


def env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def build_proxy_settings() -> dict[str, str] | None:
    caido_port = os.getenv("CAIDO_PORT")
    if not caido_port:
        return None
    return {
        "server": f"http://localhost:{caido_port}",
        "bypass": (
            "localhost,127.0.0.1,.google.com,.google.com.hk,"
            ".googleapis.com,.gvt1.com,.gvt1-cn.com,.gstatic.com,.ggpht.com"
        ),
    }


def start_browser_service(port: int) -> None:
    headless = env_flag("NO_VISION", True)
    launch_args = [
        f"--remote-debugging-port={port}",
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ]
    proxy_settings = build_proxy_settings()

    with sync_playwright() as playwright:
        launch_kwargs = {
            "headless": headless,
            "args": launch_args,
        }
        if proxy_settings is not None:
            launch_kwargs["proxy"] = proxy_settings

        browser = playwright.chromium.launch(**launch_kwargs)
        print(f"Browser service started on port {port} (headless={headless})", flush=True)
        contexts = browser.contexts
        if contexts:
            contexts[0].new_page()
        else:
            browser.new_context().new_page()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping browser service...", flush=True)
        finally:
            browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9222)
    args = parser.parse_args()
    start_browser_service(port=args.port)
