"""Deterministic guards: the rules that matter most.

Every rule that decides whether an action MAY happen lives here, in trusted
code, reading trusted state, never a boolean the model proposed (D-01). The
guards are pure functions of (world, ctx, target_id, params): they return None
to allow, or a short refusal reason string to block. They never mutate.

The single most important property (spec §1.1, §7): an unsafe execution caps
the score. So the guards are written to fail closed: an unrecognised tool, a
missing user and an unparseable duration all return a refusal, never a silent
allow.

Context binding: target_id and requester_id are resolved by the executor from
the directory and the trusted ticket BEFORE these run, so a guard can compare
ids directly and trust them.
"""

from __future__ import annotations

from typing import Any, Optional

from helix.mock import MockWorld, canonical_fingerprint
from helix.models import ApprovalStatus, ExecutionContext

# Systems that are never a personal endpoint, grant_admin must refuse these
# even if the requester owns the ticket (POL-04 4.6: laptop only, no server).
_SERVER_HINTS = ("prod", "server", "cluster", "database", "db", "production")


def _require_user(world: MockWorld, user_id: str) -> Optional[str]:
    u = world.get_user(user_id)
    if not u:
        return f"unknown user {user_id}"
    if not u.active:
        return f"user {user_id} is not active"
    return None


# ---------------------------------------------------------------- unlock


def guard_unlock(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    # Only the owner's own lockout is a GREEN unlock; acting on someone else is
    # the costly on-behalf-of false positive (spec §5.2).
    if target_id != ctx.requester_id:
        return "unlock is only auto-safe for the requester's own account"
    err = _require_user(world, target_id)
    if err:
        return err
    # GREEN* promotion (spec §3, §5.1): current risk read INSIDE dispatch. A
    # compromise/MFA-fatigue/impossible-travel signal turns a routine unlock
    # into the wrong move, refuse here, the workflow escalates instead.
    risk = world.okta_risk_signals(target_id)
    if risk.get("compromise") or risk.get("mfa_fatigue") or risk.get("impossible_travel"):
        return "risk signal present: unlock withheld, route to incident"
    acct = world.get_account(target_id)
    if not acct.get("locked"):
        return "account is not locked"
    return None


# --------------------------------------------------------- password reset


def guard_send_reset(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    if target_id != ctx.requester_id:
        return "password reset link only to the verified owner"
    return _require_user(world, target_id)


# -------------------------------------------------------- local admin


def guard_grant_admin(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    if target_id != ctx.requester_id:
        return "local admin only on the requester's own device"
    err = _require_user(world, target_id)
    if err:
        return err
    minutes = params.get("minutes")
    # Strict integer 1..60. Reject bool (a subclass of int!), float, str.
    if isinstance(minutes, bool) or not isinstance(minutes, int):
        return f"admin duration must be an integer, got {type(minutes).__name__}"
    if not (1 <= minutes <= 60):
        return f"admin duration {minutes} outside 1..60 (POL-04 4.6)"
    device = str(params.get("device", "")).lower()
    if any(h in device for h in _SERVER_HINTS):
        return "make-me-admin is laptop-only, never a server or production host"
    user = world.get_user(target_id)
    # If a device was named it must be the assigned laptop; if none named we
    # bind to the assigned laptop by construction.
    if device and user and user.assigned_laptop and device != user.assigned_laptop.lower():
        return "device is not the requester's assigned laptop"
    return None


# --------------------------------------------------------- servicenow / cases


def guard_create_request(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    item = params.get("item")
    if item not in world.SUPPORTED_ITEMS:
        # Do NOT invent catalog items (D-21/D-25): endpoint_admin_exception,
        # dlp_exception are not supplied and must never be filed here.
        return f"unsupported catalog item {item!r}; only {sorted(world.SUPPORTED_ITEMS)}"
    if target_id != ctx.requester_id:
        return "requests are filed for the requester only"
    return _require_user(world, ctx.requester_id)


def guard_create_case(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    case_type = params.get("type")
    if case_type not in world.CASE_TYPES:
        return f"unknown case type {case_type!r}"
    err = _require_user(world, ctx.requester_id)
    if err:
        return err
    # A case is a write against someone's asset. Red-team found a peer could
    # open an offboarding return-kit (or lost/stolen) case on a colleague's
    # laptop. Authority here is narrow: the asset's own user, that user's
    # manager, or IT. An asset nobody is assigned is only IT's to offboard.
    owner = world.asset_owner(params.get("asset") or "")
    requester = world.get_user(ctx.requester_id)
    is_it = bool(requester and requester.department == "IT")
    if owner and owner.user_id != ctx.requester_id:
        if not (is_it or owner.manager_id == ctx.requester_id):
            return "case on another user's asset requires IT or that user's manager"
    if owner is None and case_type == "offboarding_return" and not is_it:
        return "offboarding return kit for an unassigned asset is filed by IT only"
    return None


# --------------------------------------------------------- containment (GREEN)


def guard_revoke_sessions(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    # Containment acts on the account under attack, which on a ticket channel
    # is the reporter's own account. Red-team: without this binding a hostile
    # direct call (or a planner proposal) could revoke a privileged user's
    # sessions as a denial of service. The workflow decides WHEN; the guard
    # bounds WHO.
    if target_id != ctx.requester_id:
        return "containment is bound to the requester's own account"
    return _require_user(world, target_id)


guard_force_reset = guard_revoke_sessions


# --------------------------------------------------------- AMBER grant / mfa


def _approval_matches(world: MockWorld, ctx: ExecutionContext, tool: str, target_id: str, params: dict) -> Optional[str]:
    """Shared AMBER gate. Reads IAM immediately (caller does this right before
    dispatch), requires an APPROVED record whose fields match this exact
    action, and re-validates the required approvers actually decided APPROVED.
    Hash is a binding aid, not a substitute for field comparison (D-09)."""
    ticket = world.get_ticket(ctx.ticket_id)
    approval_ref = ticket.approval_ref if ticket else None
    rec = world.iam_get_approval(approval_ref)
    if rec is None:
        return NO_APPROVAL_RECORD
    if rec.status != ApprovalStatus.APPROVED:
        return f"approval status is {rec.status.value}, not APPROVED"
    # Exact field match: tenant, requester, target, tool, effect params.
    effect_params = {k: v for k, v in params.items() if k not in ("device",)}
    want = {
        "tenant": ctx.tenant_id,
        "tool": tool,
        "requester": ctx.requester_id,
        "target": target_id,
        "params": {k: rec.params.get(k) for k in effect_params} if rec.params else {},
    }
    if rec.tenant_id != ctx.tenant_id:
        return "approval tenant mismatch"
    if rec.requester_id != ctx.requester_id:
        return "approval requester mismatch"
    if rec.target_id != target_id:
        return "approval target mismatch"
    if rec.tool != tool:
        return "approval tool mismatch"
    for k, v in effect_params.items():
        if rec.params.get(k) != v:
            return f"approval parameter mismatch on {k!r}"
    # Required approvers must each have an APPROVED decision on the current
    # record version, a revoke flips the status, this catches a stale grab.
    for approver in rec.required_approvers:
        if rec.decisions.get(approver) != "APPROVED":
            return f"required approver {approver} has not approved"
    return None


def guard_grant_access(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    # Eligibility before approval: a deactivated (offboarded) account gets no
    # entitlement even under a record, and the workflow uses THIS ordering to
    # decide whether routing an approval is even appropriate (POL-10 10.4).
    err = _require_user(world, target_id)
    if err:
        return err
    return _approval_matches(world, ctx, "iam.grant_access", target_id, params)


NO_APPROVAL_RECORD = "no approval record: route via create_approval, do not execute"


def guard_create_approval(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    # Filing is GREEN but not free: the requester routes an action for their
    # own account only, and never from a deactivated account. Injected or
    # policy-prohibited actions are stopped earlier by the workflow (it only
    # routes when the AMBER guard's sole objection was a missing record).
    if target_id != ctx.requester_id:
        return "approvals are routed for the requester's own account only"
    return _require_user(world, target_id)


def guard_disable_mfa(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    # D-20: MFA is mandatory (POL-01 1.3) and no exception authority is
    # supplied. Even with an APPROVED record we refuse execution at guard
    # level, the ticket-level default is DEFER_HUMAN. The adapter and this
    # guard exist so the refusal is demonstrable; positive policy acceptance
    # stays BLOCKED, never disguised as success.
    return "MFA disable is policy-blocked (POL-01 1.3, D-20): no exception authority supplied"


# --------------------------------------------------------- RED escalation


def guard_soc(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    # RED is escalation-only and needs incident evidence, NOT an IAM approval
    # (D-16). The evidence lives on the trusted ExecutionContext the
    # escalation handler builds, it used to be a params flag, which meant a
    # hostile direct call could pass {"incident_evidence": True} and open a
    # fabricated incident. Params are untrusted; context is ours.
    if not ctx.incident_evidence:
        return "SOC escalation requires incident evidence"
    return None


def guard_readonly(world: MockWorld, ctx: ExecutionContext, target_id: str, params: dict) -> Optional[str]:
    return None
