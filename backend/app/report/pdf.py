"""PDF 导出：用 Playwright 驱动 Chromium 内核浏览器打印报告 HTML（D-007）。

优先使用 Playwright 自带的 Chromium；没有执行过 `playwright install chromium` 时依次改用本机的 Edge、Chrome。
打印时禁用页面脚本并拦截全部网络请求，图表以 data URI 内嵌，不需要联网。
"""

from __future__ import annotations

import asyncio

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

# None 表示 Playwright 自带的 Chromium
CHANNELS: tuple[str | None, ...] = (None, "msedge", "chrome")
TIMEOUT_MS = 60_000
FOOTER = (
    '<div style="width:100%;font-size:9px;color:#86909c;text-align:center;">'
    '<span class="pageNumber"></span> / <span class="totalPages"></span></div>'
)


class PdfUnavailable(RuntimeError):
    """本机没有可用的浏览器，或打印失败。"""


def html_to_pdf(html: str) -> bytes:
    with sync_playwright() as playwright:
        browser = None
        for channel in CHANNELS:
            try:
                browser = playwright.chromium.launch(channel=channel) if channel else playwright.chromium.launch()
                break
            except PlaywrightError:
                continue
        if browser is None:
            raise PdfUnavailable(
                "没有可用的 Chromium 内核浏览器，请在 backend 目录执行 uv run playwright install chromium，"
                "或安装 Edge / Chrome"
            )
        try:
            context = browser.new_context(java_script_enabled=False)
            context.route("**/*", lambda route: route.abort())
            page = context.new_page()
            page.set_content(html, wait_until="load", timeout=TIMEOUT_MS)
            return page.pdf(
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template="<div></div>",
                footer_template=FOOTER,
                margin={"top": "16mm", "bottom": "18mm", "left": "14mm", "right": "14mm"},
            )
        except PlaywrightError as exc:
            raise PdfUnavailable(f"PDF 打印失败：{str(exc).splitlines()[0]}") from exc
        finally:
            browser.close()


async def render_pdf(html: str) -> bytes:
    """Playwright 同步接口放到线程里执行，不依赖服务进程的事件循环类型。"""
    return await asyncio.to_thread(html_to_pdf, html)
