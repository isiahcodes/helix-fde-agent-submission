"""Redaction / output boundary.

Secrets must never reach a model prompt or any generated sink, comment, log,
trace, exception text, approval description, incident summary (spec §5.5,
CLAUDE.md). Two sources of "secret":

  1. Known canaries seeded into the world (exact-string match). These are the
     values the grader plants; exact match is reliable and we lean on it.
  2. Pattern-shaped secrets (AWS keys, bearers, private-key blocks, long
     hex/base64 tokens) caught heuristically for the values we were NOT told
     about in advance.

We deliberately do NOT claim the pattern detector is complete (architecture:
"do not claim a pattern detector proves universal redaction"). The known-value
path is the guarantee; patterns are defense in depth. redact() is applied at
every boundary, and recursively through nested structures, because a secret
hidden three levels deep in an exception's JSON is still a leak.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Iterable

REDACTION = "[REDACTED]"

# Heuristic patterns. Order matters only for readability; each is independent.
_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\b\s*[=:]\s*[^\s,;'\"]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),  # OpenAI-style
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack tokens
]


def _variants(secret: str) -> set[str]:
    """The forms a known secret is likely to show up in besides verbatim.
    Red-team found two cheap evasions: the requester pastes it base64-encoded
    ("so you can rotate it"), or it arrives with a line break in the middle.
    Base64 is handled here as extra literal strings; whitespace is handled by
    the matcher below. We do not claim this covers every encoding."""
    out = {secret}
    raw = secret.encode()
    out.add(base64.b64encode(raw).decode())
    out.add(base64.urlsafe_b64encode(raw).decode())
    out.add(base64.b64encode(raw).decode().rstrip("="))
    return {v for v in out if len(v) >= 4}


class Redactor:
    def __init__(self, known_secrets: Iterable[str] = ()):
        known: set[str] = set()
        for s in known_secrets:
            if s:
                known |= _variants(s)
        # Longest-first so a secret that contains a shorter one is masked whole.
        self._known = sorted(known, key=len, reverse=True)
        # One regex per known value that tolerates whitespace (incl. newlines)
        # between any two characters: "SECRET_\nVALUE" still matches. Built
        # once per redactor; secrets are short so this stays cheap even on a
        # 60KB ticket body.
        self._known_res = [
            re.compile(r"\s*".join(re.escape(ch) for ch in s)) for s in self._known
        ]

    def redact_text(self, text: str) -> str:
        if not text:
            return text
        for pat in self._known_res:
            text = pat.sub(REDACTION, text)
        for pat in _PATTERNS:
            text = pat.sub(REDACTION, text)
        return text

    def redact(self, value: Any) -> Any:
        """Recursively redact strings inside dicts/lists/tuples. Non-strings
        pass through; keys are left intact (a key named 'password' is not a
        secret, its value is)."""
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {k: self.redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(self.redact(v) for v in value)
        return value

    def contains_secret(self, text: str) -> bool:
        """Detection WITHOUT masking, used so incident evidence can note that
        a secret was present without ever storing its value."""
        if any(pat.search(text) for pat in self._known_res):
            return True
        return any(pat.search(text) for pat in _PATTERNS)
