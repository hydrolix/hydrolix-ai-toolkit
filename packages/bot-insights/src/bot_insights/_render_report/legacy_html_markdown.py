"""Legacy Markdown-to-HTML conversion helpers."""

from __future__ import annotations

from .formatters import (
    _demd,
    _find_unescaped,
    h_escape,
)

__all__ = [
    'markdown_to_simple_html',
    'inline_html',
    '_split_table_row',
    'table_to_html',
]


def markdown_to_simple_html(markdown: str) -> str:
    lines = markdown.splitlines()
    output: list[str] = []
    table_lines: list[str] = []
    list_open = False

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        output.append(table_to_html(table_lines))
        table_lines = []

    def close_list() -> None:
        nonlocal list_open
        if list_open:
            output.append("</ul>")
            list_open = False

    for line in lines:
        if line.startswith("|"):
            close_list()
            table_lines.append(line)
            continue
        flush_table()
        rendered = _simple_html_line(line)
        if rendered is None:
            close_list()
            continue
        if rendered[0] == "li":
            if not list_open:
                output.append("<ul>")
                list_open = True
            output.append(rendered[1])
        else:
            close_list()
            output.append(rendered[1])
    flush_table()
    close_list()
    return "".join(output)


def _simple_html_line(line: str) -> tuple[str, str] | None:
    if not line.strip():
        return None
    for marker, tag in (("# ", "h1"), ("## ", "h2"), ("### ", "h3")):
        if line.startswith(marker):
            return tag, f"<{tag}>{h_escape(_demd(line[len(marker):]))}</{tag}>"
    if line.startswith("- "):
        return "li", f"<li>{inline_html(line[2:])}</li>"
    return "p", f"<p>{inline_html(line)}</p>"


def inline_html(text: str) -> str:
    parts: list[str] = []

    def append_text(segment: str) -> None:
        cursor = 0
        while cursor < len(segment):
            start = _find_unescaped(segment, "_", cursor)
            if start == -1:
                parts.append(h_escape(_demd(segment[cursor:])))
                return
            end = _find_unescaped(segment, "_", start + 1)
            if end == -1:
                parts.append(h_escape(_demd(segment[cursor:])))
                return
            parts.append(h_escape(_demd(segment[cursor:start])))
            parts.append(f"<em>{h_escape(_demd(segment[start + 1 : end]))}</em>")
            cursor = end + 1

    cursor = 0
    while cursor < len(text):
        start = _find_unescaped(text, "`", cursor)
        if start == -1:
            append_text(text[cursor:])
            break
        end = _find_unescaped(text, "`", start + 1)
        if end == -1:
            append_text(text[cursor:])
            break
        append_text(text[cursor:start])
        parts.append(f"<code>{h_escape(_demd(text[start + 1 : end]))}</code>")
        cursor = end + 1
    return "".join(parts)


def _split_table_row(line: str) -> list[str]:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    cells: list[str] = []
    buffer: list[str] = []
    index = 0
    while index < len(body):
        ch = body[index]
        if ch == "\\" and index + 1 < len(body):
            buffer.append(body[index])
            buffer.append(body[index + 1])
            index += 2
            continue
        if ch == "|":
            cells.append("".join(buffer).strip())
            buffer = []
            index += 1
            continue
        buffer.append(ch)
        index += 1
    cells.append("".join(buffer).strip())
    return cells


def table_to_html(lines: list[str]) -> str:
    rows = []
    for line in lines:
        cells = _split_table_row(line)
        if cells and all(set(cell) <= {"-"} for cell in cells):
            continue
        rows.append(cells)
    if not rows:
        return ""
    header = rows[0]
    body = rows[1:]
    output = ["<table><thead><tr>"]
    output.extend(f"<th>{h_escape(_demd(cell))}</th>" for cell in header)
    output.append("</tr></thead><tbody>")
    for row in body:
        output.append("<tr>")
        output.extend(f"<td>{inline_html(cell)}</td>" for cell in row)
        output.append("</tr>")
    output.append("</tbody></table>")
    return "".join(output)
