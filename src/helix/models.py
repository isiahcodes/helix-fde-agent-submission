"""Typed contracts for the Helix agent.

This module is the trust boundary in data form. The core rule (CLAUDE.md
invariants, D-01/D-09/D-11): the model may propose, but only trusted code may
assert. So the records here come in two families:

- Model-facing schemas (ProposedIntent) are strict and deliberately small.
  They reject extra fields so a proposal cannot smuggle in a requester id,
  tenant, canonical hash, idempotency key or an "approved" flag, those are
  claims, and claims are not evidence.
- Trusted records (Ticket, User, BoundAction, ApprovalRecord,
  ExecutionContext, ActionEvent) are built by our own code from adapter reads,
  never parsed out of model output.

Everything forbids unknown fields. We would rather fail loudly on a schema
drift than silently accept a field that later reads as authority.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """Base for every record: unknown fields are an error, not a shrug."""

    model_config = ConfigDict(extra="forbid", strict=False)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Disposition(str, enum.Enum):
    """The six dispositions (spec §4). Exactly these, no more.

    Lifecycle facts (duplicate, withdrawn, blocked...) are NOT dispositions.
    They live in ExecutionStatus (D-04/D-05). An approved AMBER execution keeps
    PROPOSE_FOR_APPROVAL as its disposition; only its execution_status moves.
    """

    ANSWER_ONLY = "ANSWER_ONLY"
    AUTO_ACTION = "AUTO_ACTION"
    PROPOSE_FOR_APPROVAL = "PROPOSE_FOR_APPROVAL"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"
    ASK_CLARIFICATION = "ASK_CLARIFICATION"
    DEFER_HUMAN = "DEFER_HUMAN"


class ExecutionStatus(str, enum.Enum):
    """Separate execution axis (D-04). Documented local conventions.

    NONE           no state-changing action was attempted (pure answer/defer).
    PENDING_APPROVAL  drafted and routed; awaiting an out-of-band decision.
    VERIFIED       action dispatched AND its effect independently confirmed.
    BLOCKED        a guard refused the action (policy, authz, approval, config).
    FAILED         dispatched but the API failed and nothing useful stands.
    INCOMPLETE     multi-step action partially succeeded; remainder flagged
                   (successful containment is preserved and never rolled
                   back, D-18).
    DUPLICATE_LINKED  exact in-flight duplicate; linked instead of re-acting.
    WITHDRAWN      requester withdrew before dispatch; nothing executed (D-05).
    """

    NONE = "NONE"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"
    DUPLICATE_LINKED = "DUPLICATE_LINKED"
    WITHDRAWN = "WITHDRAWN"


class RiskClass(str, enum.Enum):
    """Spec §3 risk classes. GREEN* (conditional unlock) is GREEN here with
    ToolSpec.risk_conditional=True, the promotion-to-RED logic is a guard,
    not a fourth class."""

    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"


class TicketStatus(str, enum.Enum):
    """Mock JIRA workflow states. The permitted-transition table lives in the
    ticket adapter; these are just the vocabulary."""

    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    WAITING_FOR_CUSTOMER = "Waiting for Customer"
    PENDING_APPROVAL = "Pending Approval"
    ESCALATED = "Escalated"
    DONE = "Done"
    WITHDRAWN = "Withdrawn"


# ---------------------------------------------------------------------------
# Trusted world records (built from adapapter reads, never from model output)
# ---------------------------------------------------------------------------


class User(StrictModel):
    user_id: str
    tenant_id: str
    email: str
    display_name: str
    manager_id: Optional[str] = None
    department: str = "unknown"
    privileged: bool = False
    contractor: bool = False
    active: bool = True
    # Asset id of the laptop assigned to this user. grant_admin may only ever
    # target this device (POL-04 4.6 as bounded by D-01 guard contracts).
    assigned_laptop: Optional[str] = None
    mobile_eligible: bool = False


class Ticket(StrictModel):
    ticket_id: str
    tenant_id: str
    # Reporter identity is established by the ticket adapter at ingestion
    # (login), NOT by names in the body text (D-11). Body claims of identity
    # are just text.
    reporter_id: str
    summary: str
    body: str
    revision: int = 1
    status: TicketStatus = TicketStatus.OPEN
    withdrawn: bool = False
    labels: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    # Set by our own workflow when an approval was routed for this ticket.
    approval_ref: Optional[str] = None
    asset_refs: list[str] = Field(default_factory=list)
    # Comments the agent itself wrote get authored_by="agent" so the worker
    # never re-enqueues a ticket because of its own output (Task 8).
    created_at: str = "1970-01-01T00:00:00Z"


class PolicySpan(StrictModel):
    """One numbered policy section, the only grantable knowledge unit."""

    policy_id: str  # "POL-01"
    section: str  # "1.4"
    title: str  # policy title, e.g. "Password & Authentication Policy"
    text: str
    owner: str
    effective: str
    source_sha256: str

    @property
    def span_id(self) -> str:
        return f"{self.policy_id} {self.section}"


# ---------------------------------------------------------------------------
# Model-facing proposal schema (strict, minimal, no authority fields)
# ---------------------------------------------------------------------------


class ProposedIntent(StrictModel):
    """What the planner (LLM or fake) is allowed to say.

    Deliberately absent, and rejected via extra='forbid' if supplied:
    requester_id, tenant_id, canonical_hash, idempotency_key, approval status
    of any kind, and permission booleans. Trusted code derives all of those.
    """

    disposition: Disposition
    # Tool name from the catalog; None for ANSWER_ONLY / ASK / DEFER.
    tool: Optional[str] = None
    # A *reference* the guards resolve against the directory ("self",
    # "user:u-bob", an email). Never treated as an authenticated identity.
    target_ref: Optional[str] = None
    params: dict[str, Any] = Field(default_factory=dict)
    span_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    clarification_question: Optional[str] = None
    # There is deliberately NO free-form "extra_tools" list. The escalation
    # workflow decides containment steps itself from trusted state; a planner-
    # supplied list of additional tool calls was an unvalidated side door the
    # security review caught (the params validator did not reach into it).
    # One tool per proposal, or none.

    @field_validator("params")
    @classmethod
    def _no_authority_smuggling(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Belt and braces: even inside the free-form params dict, the fields
        # trusted code derives must not be accepted from the model. A planner
        # that emits them is either confused or being injected. Checked
        # recursively, nesting them under "fields" is the obvious dodge.
        forbidden = {
            "requester_id",
            "tenant_id",
            "canonical_hash",
            "idempotency_key",
            "logical_key",
            "approved",
            "approval_status",
            "approval_id",
            # RED evidence is a trusted-context fact set by the escalation
            # handler, never a parameter a proposal can assert (red-team:
            # a planner "AUTO_ACTION soc.open_incident" with this flag would
            # otherwise fabricate an incident).
            "incident_evidence",
        }

        def walk(obj: Any, path: str = "params") -> None:
            if isinstance(obj, dict):
                hit = forbidden.intersection(obj.keys())
                if hit:
                    raise ValueError(
                        f"model-supplied authority fields rejected at {path}: {sorted(hit)}"
                    )
                for k, val in obj.items():
                    walk(val, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, val in enumerate(obj):
                    walk(val, f"{path}[{i}]")

        walk(v)
        return v


# ---------------------------------------------------------------------------
# Trusted execution records
# ---------------------------------------------------------------------------


class BoundAction(StrictModel):
    """A proposal after trusted binding: identities resolved via the
    directory, params normalized, hash and logical key derived by us.
    Kept as a separate type from ProposedIntent on purpose, passing one
    where the other is expected should be a type error, not a subtle bug."""

    tenant_id: str
    requester_id: str
    target_id: str
    tool: str
    params: dict[str, Any]
    canonical_hash: str
    logical_key: str


class ApprovalRecord(StrictModel):
    approval_id: str
    tenant_id: str
    requester_id: str
    target_id: str
    tool: str
    params: dict[str, Any]
    canonical_hash: str
    status: ApprovalStatus
    required_approvers: list[str]
    decisions: dict[str, str] = Field(default_factory=dict)
    version: int = 1


class ExecutionContext(StrictModel):
    """Created by trusted code per processing run. The model never sees or
    supplies one."""

    ticket_id: str
    revision: int
    tenant_id: str
    requester_id: str
    run_id: str
    dispatch_id: str = ""
    # True only on the context the ESCALATE_INCIDENT handler builds. The RED
    # guard reads this, not a params flag, so neither a hostile direct call
    # nor a model proposal can supply the evidence that opens an incident.
    incident_evidence: bool = False


class ToolSpec(StrictModel):
    """Catalog row: risk class plus the three enforcement hooks. The callables
    live in registry.py; specs are data so the eval can enumerate coverage."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    name: str
    risk: RiskClass
    risk_conditional: bool = False  # GREEN*, unlock's promote-to-RED context
    mutating: bool = True
    documented_key: str = ""
    # permission(world, ctx, target_id, params) -> None | str (refusal reason)
    permission: Optional[Callable[..., Optional[str]]] = None
    # key_recipe(world, ctx, target_id, params) -> str logical key
    key_recipe: Optional[Callable[..., str]] = None
    # inspector(world, target_id, params, result) -> bool actual effect stands
    inspector: Optional[Callable[..., bool]] = None


class ActionEvent(StrictModel):
    """Trusted evidence line for the ledger/evaluator. Args are sanitized
    before storage, secrets never reach this record (Task 4)."""

    seq: int = 0
    run_id: str
    dispatch_id: str
    ticket_id: str
    tenant_id: str
    tool: str
    phase: str  # attempted | blocked | dispatched | verified | failed
    args: dict[str, Any] = Field(default_factory=dict)
    logical_key: Optional[str] = None
    api_ok: Optional[bool] = None
    effect: Optional[bool] = None
    error: Optional[str] = None
    at: str = ""


class Decision(StrictModel):
    """Public per-ticket result (implementation plan: disposition,
    execution_status, ticket_status, citations, approval_id, reason_code)."""

    ticket_id: str
    disposition: Disposition
    execution_status: ExecutionStatus
    ticket_status: TicketStatus
    citations: list[str] = Field(default_factory=list)
    approval_id: Optional[str] = None
    reason_code: str = ""
    comment: str = ""


def utcnow_iso() -> str:
    """Single time formatting choice (UTC, D-14). The mock world injects a
    fixture clock; this helper is only for real wall-clock audit stamps."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
