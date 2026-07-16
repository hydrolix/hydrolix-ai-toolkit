#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate the embedded-font CSS partial for the editorial incident brief.

Fetches Public Sans (300..800, italic) and Inconsolata (400..700) woff2
files from Google Fonts, base64-encodes them, and writes a
`@font-face` partial at
``report_engine/templates/_styles_editorial_fonts.css``. The main
``_styles.css`` ``{% include %}``s that partial so the rendered HTML
is fully self-contained (no external font requests).

Run on demand (network required); commit the generated partial so
report rendering stays offline-deterministic.
"""

from __future__ import annotations

import base64
import re
import sys
import urllib.request
from pathlib import Path


# Modern browser UA — Google Fonts serves woff2 only to UAs that
# advertise it. Without this the API returns ttf/woff/woff2 candidates
# in a different shape.
_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Safari/605.1.15"
)

# Weights confirmed used by the editorial layout (briefing.html audit):
# 400/500/600/700/800 roman + italic 400 (for the .attack-note and
# .ioc-meta .label italic body copy).  300 and italic 600/700 are not
# referenced — dropping them keeps the embedded payload small.
PUBLIC_SANS_CSS = (
    "https://fonts.googleapis.com/css2?"
    "family=Public+Sans:ital,wght@0,400;0,500;0,600;0,700;0,800;1,400"
    "&display=swap"
)
INCONSOLATA_CSS = (
    "https://fonts.googleapis.com/css2?"
    "family=Inconsolata:wght@400;500;600;700&display=swap"
)

# Google Fonts splits each weight into multiple @font-face blocks keyed
# by Unicode range (Latin, Latin-Ext, Vietnamese, Cyrillic, etc.).
# Reports are English-only and the editorial copy uses ASCII + a handful
# of typographic punctuation (em-dash, curly quotes, middle dot) that
# all live inside Latin. Keep Latin + Latin-Ext, drop the rest — the
# unused ranges add ~700 KB per render for zero visible benefit.
KEEP_SUBSETS = ("latin",)

OUTPUT_PATH = (
    Path(__file__).resolve().parent
    / "report_engine"
    / "templates"
    / "_styles_editorial_fonts.css"
)


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return resp.read()


_URL_RE = re.compile(r"url\((https://[^)]+\.woff2)\)")


def _inline_woff2(css_text: str) -> str:
    """Replace every ``url(https://....woff2)`` with a base64 data URI."""

    def _replace(match: re.Match[str]) -> str:
        font_url = match.group(1)
        blob = _fetch(font_url)
        b64 = base64.b64encode(blob).decode("ascii")
        return f"url(data:font/woff2;base64,{b64}) format('woff2')"

    return _URL_RE.sub(_replace, css_text)


def _strip_format(css_text: str) -> str:
    """Drop any pre-existing ``format('woff2')`` so our inliner can add one.

    Google Fonts emits ``url(...) format('woff2')`` — our replacement
    builds the ``format('woff2')`` clause itself, so we strip the
    original to avoid a double clause.
    """
    return re.sub(r"\)\s*format\(['\"]woff2['\"]\)", ")", css_text)


_BLOCK_RE = re.compile(
    r"/\*\s*(?P<subset>[\w\-]+)\s*\*/\s*"
    r"(?P<face>@font-face\s*\{[^}]*\})",
    re.MULTILINE,
)


def _filter_subsets(css_text: str) -> str:
    """Keep only the @font-face blocks whose preceding /* subset */
    comment matches :data:`KEEP_SUBSETS`."""
    kept: list[str] = []
    for match in _BLOCK_RE.finditer(css_text):
        subset = match.group("subset").strip()
        if subset in KEEP_SUBSETS:
            kept.append(f"/* {subset} */\n{match.group('face')}")
    return "\n\n".join(kept)


def _build(label: str, css_url: str) -> str:
    print(f"fetching {label} CSS …", file=sys.stderr)
    css = _fetch(css_url).decode("utf-8")
    css = _strip_format(css)
    css = _filter_subsets(css)
    print(f"inlining {label} woff2 files (Latin + Latin-Ext only) …", file=sys.stderr)
    return _inline_woff2(css)


def main() -> None:
    public_sans_css = _build("Public Sans", PUBLIC_SANS_CSS)
    inconsolata_css = _build("Inconsolata", INCONSOLATA_CSS)

    header = (
        "/* GENERATED FILE — do not edit by hand.\n"
        "   Regenerate with: uv run skills/bot-insights/scripts/"
        "build_editorial_fonts.py\n"
        "   Sources: Google Fonts CSS API. woff2 payloads inlined as\n"
        "   base64 data URIs so rendered reports stay standalone (no\n"
        "   external font requests). */\n\n"
        "/* ──── Public Sans (300..800, italic 400/600) ───────────── */\n"
    )
    body = (
        header
        + public_sans_css.strip()
        + "\n\n/* ──── Inconsolata (400..700) ───────────────────────────── */\n"
        + inconsolata_css.strip()
        + "\n"
    )
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(body)
    print(f"wrote {OUTPUT_PATH} ({len(body):,} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
