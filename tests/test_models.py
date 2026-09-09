"""Task 1 contract tests: the six dispositions are exact, and the model-facing
schema cannot carry authority. These run first because everything downstream
leans on these guarantees."""

import pytest
from pydantic import ValidationError

from helix.models import (
    Disposition,
    ExecutionStatus,
    ProposedIntent,
    RiskClass,
)


def test_exact_dispositions():
    assert {d.value for d in Disposition} == {
        "ANSWER_ONLY",
        "AUTO_ACTION",
        "PROPOSE_FOR_APPROVAL",
        "ESCALATE_INCIDENT",
        "ASK_CLARIFICATION",
        "DEFER_HUMAN",
    }


def test_execution_status_is_separate_axis():
    # Lifecycle facts must not leak into the disposition enum (D-04/D-05).
    assert "DUPLICATE_LINKED" not in {d.value for d in Disposition}
    assert ExecutionStatus.DUPLICATE_LINKED.value == "DUPLICATE_LINKED"
    assert ExecutionStatus.PENDING_APPROVAL.value == "PENDING_APPROVAL"


def test_risk_classes():
    assert {r.value for r in RiskClass} == {"GREEN", "AMBER", "RED"}


def test_proposal_rejects_trusted_identity_fields():
    # A planner (or an injection reaching the planner) must not be able to
    # assert who is asking or which tenant it is.
    with pytest.raises(ValidationError):
        ProposedIntent(
            disposition=Disposition.AUTO_ACTION,
            tool="okta.unlock_account",
            requester_id="u-mallory",  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        ProposedIntent(
            disposition=Disposition.AUTO_ACTION,
            tool="okta.unlock_account",
            tenant_id="helix",  # type: ignore[call-arg]
        )


def test_proposal_rejects_authority_smuggled_in_params():
    for bad in ("canonical_hash", "idempotency_key", "approved", "approval_status", "approval_id"):
        with pytest.raises(ValidationError):
            ProposedIntent(
                disposition=Disposition.PROPOSE_FOR_APPROVAL,
                tool="iam.grant_access",
                params={bad: "x"},
            )


def test_proposal_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ProposedIntent(disposition=Disposition.ANSWER_ONLY, definitely_not_a_field=True)  # type: ignore[call-arg]


def test_non_integer_admin_duration_is_rejected_at_guard_not_schema():
    # params is free-form at the schema layer; the strict 1..60 integer rule
    # is a guard concern (test_guards). Here we only pin that params carries
    # values through untouched so the guard sees the original type.
    p = ProposedIntent(
        disposition=Disposition.AUTO_ACTION,
        tool="endpoint.grant_admin",
        params={"minutes": "60"},
    )
    assert p.params["minutes"] == "60"  # still a string; guard must reject it


def test_authority_fields_rejected_when_nested():
    # Security-review finding: the validator only looked at top-level params.
    # Nesting under "fields" (which create_request/create_case legitimately
    # use) must be caught too.
    with pytest.raises(ValidationError):
        ProposedIntent(
            disposition=Disposition.AUTO_ACTION,
            tool="servicenow.create_request",
            params={"item": "software", "fields": {"approved": True}},
        )
    with pytest.raises(ValidationError):
        ProposedIntent(
            disposition=Disposition.AUTO_ACTION,
            tool="assetmgmt.create_case",
            params={"type": "lost_stolen", "fields": [{"approval_id": "APR-1"}]},
        )


def test_extra_tools_side_door_is_gone():
    # A planner-supplied list of additional tool calls bypassed the params
    # validator entirely. The field no longer exists; supplying it is an
    # unknown-field error like any other.
    with pytest.raises(ValidationError):
        ProposedIntent(
            disposition=Disposition.ESCALATE_INCIDENT,
            extra_tools=[{"tool": "iam.grant_access", "params": {"approved": True}}],  # type: ignore[call-arg]
        )
