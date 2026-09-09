"""A proposal that names an action but no tool must defer, never raise.

Found by running the evaluation against a live model rather than the fake
planner: the model returned PROPOSE_FOR_APPROVAL with `tool: null`, which
reached `Executor.execute(None, ...)` and raised a validation error out of
`Agent.process`. A crash is worse than a wrong answer here, the ticket is
left mid-flight with no decision recorded, which is the one outcome the
six-disposition contract is supposed to make impossible.

`_auto_action` already had this guard; `_propose_for_approval` did not.
"""

from __future__ import annotations

import pytest

from helix.models import Disposition, ProposedIntent
from helix.workflow import Agent


class ToollessPlanner:
    """Proposes an action-shaped disposition with no tool named."""

    def __init__(self, disposition: Disposition):
        self.disposition = disposition

    def propose(self, ticket, spans, retriever, redactor=None) -> ProposedIntent:
        return ProposedIntent(
            disposition=self.disposition,
            tool=None,
            target_ref="self",
            params={},
            span_ids=[],
            rationale="model named a disposition but no tool",
        )


@pytest.mark.parametrize(
    "disposition",
    [Disposition.AUTO_ACTION, Disposition.PROPOSE_FOR_APPROVAL],
)
def test_action_without_a_tool_defers_and_mutates_nothing(harness, disposition):
    harness.seed("pending_access")
    agent = Agent(harness.world, ToollessPlanner(disposition), harness.audit)

    decision = agent.process("T-ACCESS")

    assert decision["disposition"] == Disposition.DEFER_HUMAN.value
    assert "without a tool" in decision["reason_code"]
    # Nothing in the estate moved: no unlock, no grant, no approval filed.
    for tool in ("okta.unlock_account", "iam.grant_access", "iam.create_approval",
                 "endpoint.grant_admin", "okta.force_password_reset"):
        assert harness.mutations(tool) == 0, tool
