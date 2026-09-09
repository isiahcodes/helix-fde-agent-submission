"""Shared test harness (implementation plan, 'Shared harness contract').

The harness is test-only plumbing: it can seed worlds, inject planner
proposals, dispatch through the REAL guarded executor, flip approval records
out-of-band, and observe events/mutations/outputs. None of these capabilities
are model-visible tools. They exist so the tests can prove what the agent
did, not to give the agent shortcuts.

Imports of helix internals happen lazily inside the fixture so early-task
tests (models, policies) collect and run before later modules exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

REPO = Path(__file__).resolve().parents[1]


class Harness:
    def __init__(self, tmp_path: Path):
        # Late imports: the whole stack only has to exist once a test actually
        # asks for the harness.
        from helix.audit import AuditLog
        from helix.mock import MockWorld
        from helix.planner import FakePlanner
        from helix.workflow import Agent

        self.db_path = tmp_path / "world.sqlite3"
        self.world = MockWorld(self.db_path)
        self.audit = AuditLog(tmp_path / "audit")
        self.planner = FakePlanner()
        self.agent = Agent(self.world, self.planner, self.audit)
        self._before_dispatch: Callable[[], None] | None = None
        # Executor hook so a test can mutate the world between the decision
        # and the action (withdrawal race, approval revocation).
        self.agent.executor.before_dispatch_hook = self._fire_before_dispatch

    # -- contract methods ---------------------------------------------------

    def seed(self, name: str) -> None:
        """Reset to a named fixture scenario. Only isolated tests call this;
        multi-stage flows (pending -> approved) must NOT reseed mid-flow."""
        from helix.mock import load_scenario

        load_scenario(self.world, name)

    def process(self, ticket_id: str, proposal: dict | None = None) -> dict:
        """Run the full pipeline. A supplied proposal replaces only the model
        (it is validated through the same strict ProposedIntent schema and
        the same guards), nothing else is bypassed."""
        return self.agent.process(ticket_id, injected_proposal=proposal)

    def dispatch(self, tool: str, ticket_id: str, args: dict) -> dict:
        """Direct hostile call into the guarded executor, simulates an
        attacker or a buggy caller skipping the workflow. Guards must hold
        here too (D-01)."""
        return self.agent.hostile_dispatch(tool, ticket_id, args)

    def set_approval(self, approval_id: str, status: str) -> None:
        """Out-of-band approver decision (D-10): the human/demo admin path.
        Keeps required-approver decisions consistent with the status."""
        self.world.admin_set_approval(approval_id, status)

    def inspect(self, path: str) -> Any:
        """Narrow read into mock state, dotted path e.g. 'accounts.u-alice'."""
        return self.world.inspect(path)

    def events(self) -> list[dict]:
        return self.audit.events()

    def mutations(self, tool: str) -> int:
        """Count of ACTUAL state changes by tool, not attempts, not no-ops."""
        return self.world.mutation_count(tool)

    def outputs(self) -> str:
        """Every generated sink concatenated: model inputs, comments, traces,
        errors, approval and SOC descriptions. The redaction tests grep this."""
        parts: list[str] = [self.audit.dump_text()]
        parts.append(self.world.generated_text())
        return "\n".join(parts)

    def before_next_dispatch(self, callback: Callable[[], None]) -> None:
        self._before_dispatch = callback

    def _fire_before_dispatch(self) -> None:
        cb, self._before_dispatch = self._before_dispatch, None
        if cb:
            cb()


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    h = Harness(tmp_path)
    h.seed("baseline")
    return h


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
