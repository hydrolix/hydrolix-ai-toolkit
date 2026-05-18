"""Optional PDF export for print-ready HTML reports."""

from __future__ import annotations

from pathlib import Path


class PrintExportError(RuntimeError):
    """Raised when PDF export cannot run in the current environment."""


def render_pdf_from_html(
    html: str,
    output_path: Path,
    *,
    title: str | None = None,
    paper_format: str = "Letter",
) -> None:
    """Render ``html`` to a PDF file using Playwright when available."""

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise PrintExportError(
            "PDF export requires optional Playwright support. Install it with "
            "`uv pip install playwright` and then run `uv run playwright install "
            "chromium`, or render `--format html --profile print` and print from "
            "a browser."
        ) from exc

    output_path = Path(output_path)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page()
                page.set_content(html, wait_until="networkidle")
                if title:
                    page.evaluate(
                        "(value) => { document.title = value; }",
                        title,
                    )
                page.pdf(
                    path=str(output_path),
                    format=paper_format,
                    print_background=True,
                    margin={
                        "top": "0.6in",
                        "right": "0.5in",
                        "bottom": "0.6in",
                        "left": "0.5in",
                    },
                )
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise PrintExportError(
            "PDF export requires a working Playwright Chromium runtime. Run "
            "`uv run playwright install chromium`, or render "
            "`--format html --profile print` and print from a browser."
        ) from exc
