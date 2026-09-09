"""Sanitized decision/action evidence trail.

Every ActionEvent and every Decision is written here AFTER redaction. The audit
log is the evaluator's primary evidence (it reads events, not the guard's
return value, D-32), and it is also the human-readable decision log the
spec asks for (one line per ticket).

Nothing reaches this log un-redacted: append_event and record_decision both run
their inputs through the active Redactor first. dump_text() is what the
redaction tests grep, so if a secret ever appeared in a comment or an error, it
would show up here and fail the canary test, which is exactly the tripwire we
want.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from helix.models import ActionEvent, Decision
from helix.privacy import Redactor


class AuditLog:
    def __init__(self, out_dir: Path | str, redactor: Optional[Redactor] = None):
        self.dir = Path(out_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.dir / "events.jsonl"
        self.decisions_path = self.dir / "decisions.jsonl"
        self.redactor = redactor or Redactor()
        self._seq = 0
        self._events: list[dict] = []

    def set_redactor(self, redactor: Redactor) -> None:
        # The worker installs a per-ticket redactor once it knows the ticket's
        # known secrets; do it before any event for that ticket is written.
        self.redactor = redactor

    def append_event(self, event: ActionEvent) -> None:
        self._seq += 1
        event.seq = self._seq
        clean = self.redactor.redact(json.loads(event.model_dump_json()))
        self._events.append(clean)
        with self.events_path.open("a") as fh:
            fh.write(json.dumps(clean) + "\n")

    def record_decision(self, decision: Decision) -> None:
        clean = self.redactor.redact(json.loads(decision.model_dump_json()))
        with self.decisions_path.open("a") as fh:
            fh.write(json.dumps(clean) + "\n")

    def events(self) -> list[dict]:
        return list(self._events)

    def dump_text(self) -> str:
        chunks: list[str] = [json.dumps(e) for e in self._events]
        if self.decisions_path.exists():
            chunks.append(self.decisions_path.read_text())
        return "\n".join(chunks)

    def model_input_note(self, text: str) -> None:
        """Record (redacted) what was sent to the planner, so outputs() covers
        model input too, the canary must be absent there as well."""
        self._events.append({"phase": "model_input", "text": self.redactor.redact_text(text)})
        with self.events_path.open("a") as fh:
            fh.write(json.dumps(self._events[-1]) + "\n")


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
