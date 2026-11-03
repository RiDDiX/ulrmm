# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
import secrets

import markdown

MARKDOWN_EXTENSIONS = (
    "ocxsect",
    "tables",
    "sane_lists",
    "def_list",
    "nl2br",
    "fenced_code",
    "attr_list",
)


def convert_markdown(text: str) -> str:
    """Markdown to HTML with Jinja block tags kept for the Jinja step.

    On each line the span from the first {% to the last %} is swapped for a
    plain word while Markdown runs, so the tags sit in the surrounding text:
    a tag line next to text stays in that paragraph or table, a tag line on
    its own comes out without a paragraph around it.
    """
    token = f"ulrmmjinja{secrets.token_hex(6)}n"
    spans = []

    def protect(line: str) -> str:
        start = line.find("{%")
        end = line.rfind("%}")
        if start == -1 or end < start:
            return line
        end += 2
        spans.append(line[start:end])
        return f"{line[:start]}{token}{len(spans) - 1}x{line[end:]}"

    protected = "\n".join(protect(line) for line in text.split("\n"))
    # a new converter per call: Markdown instances keep state between runs
    html = markdown.markdown(protected, extensions=list(MARKDOWN_EXTENSIONS))
    if not spans:
        return html
    marker = re.compile(rf"<p>{token}(\d+)x</p>|{token}(\d+)x")
    return marker.sub(lambda m: spans[int(m.group(1) or m.group(2))], html)
