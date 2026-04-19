import os
from typing import Annotated
from playwright.async_api import async_playwright, BrowserContext

from core import tool, toolset, namespace

namespace()

@toolset()
class Browser:
    def __init__(self, url):
        self.url = url
        self.browser_instance = None
    
    @tool()
    async def get_context(self) -> Annotated[BrowserContext, "BrowserContext in Playwright"]:
        """
        Returns the BrowserContext object from Playwright-Python.

        Examaple:
            You can use it to see which pages are available, open a new page to view its content, and then click on its elements:
            ```
            import toolset

            context = await toolset.browser.get_context()
            print(context.pages)
            page = await context.new_page()
            await page.goto("http://example.com")
            print(await page.locator("html").aria_snapshot())
            await page.get_by_role("link", name="Learn more").click()
            ```

            When testing a website for XSS vulnerabilities, do not use functions like alert and prompt; instead, use console.log:
            ```
            import toolset

            context = await toolset.browser.get_context()
            msgs = []
            async def handle_console(msg):
                msgs.append(msg)
            page = await context.new_page()
            page.on("console", handle_console)
            await page.goto("http://example.com")
            await page.evaluate("console.log(1);")
            print(msgs)
            ```

            Attention: Prioritize using existing page objects (context. pages) and avoid creating too many pages
        """

        if not self.browser_instance:
            p = await async_playwright().start()
            self.browser_instance = await p.chromium.connect_over_cdp(self.url)

        contexts = self.browser_instance.contexts
        if contexts:
            return contexts[0]
        else:
            return await self.browser_instance.new_context()

   

   
