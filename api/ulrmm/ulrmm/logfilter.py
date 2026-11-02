# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Masks credentials in log records before any handler writes them."""

import logging
import re

MASK = "********"
# the rules run on this much of a message; the rest is cut, not written unmasked
SCAN_LIMIT = 64 * 1024

_RULES = (
    # PEM blocks: keys, certificates, CSRs
    (
        re.compile(r"(-----BEGIN ([A-Z0-9 ]+)-----).*?(-----END \2-----)", re.S),
        rf"\1{MASK}\3",
    ),
    # header values: Authorization: Token <key>, Bearer <jwt>, Enroll <jws>
    (
        re.compile(r"\b(Token|Bearer|Enroll|Basic)(\s+)[A-Za-z0-9._~+/=-]{16,}"),
        rf"\1\2{MASK}",
    ),
    # query strings and form bodies: password=, token=, access_token=, secret=
    (
        re.compile(
            r"((?<![\w-])[\w-]{0,40}(?:password|passwd|token|secret|api_?key)=)"
            r"[^&\s'\"]+",
            re.I,
        ),
        rf"\1{MASK}",
    ),
)


def redact(text: str) -> str:
    if len(text) > SCAN_LIMIT:
        head = text[:SCAN_LIMIT]
        begin = head.rfind("-----BEGIN ")
        if begin > head.rfind("-----END "):
            # a block cut in half has no END line to be masked by
            head = head[:begin]
        text = f"{head} [{len(text) - len(head)} characters cut]"
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    return text


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg, record.args = redact(message), None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True
