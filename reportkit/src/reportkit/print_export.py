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
    full_bleed: bool = False,
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
                pdf_options = {
                    "path": str(output_path),
                    "format": paper_format,
                    "prefer_css_page_size": True,
                    "print_background": True,
                }
                if full_bleed:
                    pdf_options.update(
                        {
                            "display_header_footer": False,
                            "margin": {
                                "top": "0",
                                "right": "0",
                                "bottom": "0",
                                "left": "0",
                            },
                        }
                    )
                else:
                    pdf_options.update(
                        {
                            "display_header_footer": True,
                            "header_template": "<span></span>",
                            "footer_template": (
                                "<div style=\"width:100%; font-size:7px; color:#777; "
                                "padding:0 0.38in; text-align:right; "
                                "font-family:Arial, sans-serif;\">"
                                "<span class=\"pageNumber\"></span>/<span class=\"totalPages\"></span>"
                                "</div>"
                            ),
                            "margin": {
                                "top": "0.48in",
                                "right": "0.42in",
                                "bottom": "0.54in",
                                "left": "0.42in",
                            },
                        }
                    )
                page.pdf(**pdf_options)
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise PrintExportError(
            "PDF export requires a working Playwright Chromium runtime. Run "
            "`uv run playwright install chromium`, or render "
            "`--format html --profile print` and print from a browser."
        ) from exc
