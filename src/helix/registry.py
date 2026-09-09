"""The 21-operation catalog as data.

Each ToolSpec ties a catalog operation to its risk class, its permission
guard, its idempotency-key recipe, and its postcondition inspector. The
executor is generic: it looks a tool up here and runs guard -> key -> dispatch
-> inspect. Keeping the catalog as a table (not a switch statement) is what
lets the evaluator enumerate coverage over exactly these 21 names (D-31).

Key recipes implement the documented logical keys from the tool catalog
(tool-catalog.json). "n/a (workflow)" and "n/a (read-only)" operations carry
no idempotency key; only the mutating, keyed ones go through the ledger.
"""

from __future__ import annotations

from helix.guards import (
    guard_create_approval,
    guard_create_case,
    guard_create_request,
    guard_disable_mfa,
    guard_force_reset,
    guard_grant_access,
    guard_grant_admin,
    guard_readonly,
    guard_revoke_sessions,
    guard_send_reset,
    guard_soc,
    guard_unlock,
)
from helix.mock import MockWorld
from helix.models import ExecutionContext, RiskClass, ToolSpec

# ---- key recipes (world, ctx, target_id, params) -> str --------------------


def k_unlock(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    # account + lock epoch: a fresh lockout is a new key, a retry of the same
    # lockout replays (D-13).
    acct = world.get_account(target)
    return f"{target}:{acct.get('lock_epoch', 'none')}"


def k_reset_day(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    return f"{target}:{world.day}"


def k_user_incident(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    # containment keyed by user + incident/ticket, so both containment verbs
    # under one incident are namespaced and each acts at most once.
    return f"{target}:{ctx.ticket_id}"


def k_request(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    return f"{ctx.requester_id}:{p.get('item')}:{world.day}"


def k_admin_session(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    # user + session: the persisted session key must be stable across process
    # restarts so a resumed worker does not re-grant (Task 8).
    return f"{target}:{ctx.ticket_id}"


def k_case(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    return f"{p.get('asset', target)}:{p.get('type')}"


def k_approval_id(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    # AMBER grant uses the approval id as its idempotency key (spec §3).
    ticket = world.get_ticket(ctx.ticket_id)
    return ticket.approval_ref if ticket and ticket.approval_ref else f"noapproval:{ctx.ticket_id}"


def k_ticket(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    return ctx.ticket_id


def k_request_hash(world: MockWorld, ctx: ExecutionContext, target: str, p: dict) -> str:
    from helix.mock import canonical_fingerprint

    return canonical_fingerprint(
        {"requester": ctx.requester_id, "target": target, "tool": p.get("tool"), "params": p.get("params", {})}
    )


# ---- inspectors (world, target, params, result) -> bool effect stands ------


def insp_unlock(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return world.get_account(target).get("locked") is False


def insp_reset(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return world.get_account(target).get("reset_link_sent_day") == world.day


def insp_revoke(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return world.get_account(target).get("sessions", 1) == 0


def insp_force_reset(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return world.get_account(target).get("force_reset") is True


def insp_grant_admin(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return world.inspect(f"admin_grants.{target}") is not None


def insp_request(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return bool(r.get("request_id"))


def insp_case(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return bool(r.get("case_id"))


def insp_grant_access(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    ents = world.inspect(f"entitlements.{target}")
    return any(e["system"] == p.get("system") and e["role"] == p.get("role") for e in ents)


def insp_disable_mfa(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return world.get_account(target).get("mfa_enabled") is False


def insp_incident(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return bool(r.get("incident_id"))


def insp_page(world: MockWorld, target: str, p: dict, r: dict) -> bool:
    return bool(r.get("page_id"))


def _spec(name, risk, **kw) -> ToolSpec:
    return ToolSpec(name=name, risk=risk, **kw)


# The full catalog. Workflow + read-only ops are non-mutating and keyless;
# only the state-changing rows carry a key recipe + inspector and route
# through the ledger.
CATALOG: dict[str, ToolSpec] = {s.name: s for s in [
    # workflow (GREEN, non-mutating from the ledger's perspective)
    _spec("jira.get", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("jira.comment", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("jira.transition", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("jira.add_label", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("jira.link_issues", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    # directory (read-only)
    _spec("directory.lookup_user", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("directory.verify_manager", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    # okta
    _spec("okta.unlock_account", RiskClass.GREEN, risk_conditional=True, documented_key="account + lock epoch",
          permission=guard_unlock, key_recipe=k_unlock, inspector=insp_unlock),
    _spec("okta.risk_signals", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("okta.send_password_reset", RiskClass.GREEN, documented_key="user + calendar day",
          permission=guard_send_reset, key_recipe=k_reset_day, inspector=insp_reset),
    _spec("okta.revoke_sessions", RiskClass.GREEN, documented_key="user + incident",
          permission=guard_revoke_sessions, key_recipe=k_user_incident, inspector=insp_revoke),
    _spec("okta.force_password_reset", RiskClass.GREEN, documented_key="user + incident",
          permission=guard_force_reset, key_recipe=k_user_incident, inspector=insp_force_reset),
    # servicenow
    _spec("servicenow.create_request", RiskClass.GREEN, documented_key="user + item + day",
          permission=guard_create_request, key_recipe=k_request, inspector=insp_request),
    # endpoint
    _spec("endpoint.grant_admin", RiskClass.GREEN, documented_key="user + session",
          permission=guard_grant_admin, key_recipe=k_admin_session, inspector=insp_grant_admin),
    # asset management
    _spec("assetmgmt.create_case", RiskClass.GREEN, documented_key="asset + type",
          permission=guard_create_case, key_recipe=k_case, inspector=insp_case),
    # iam
    _spec("iam.create_approval", RiskClass.GREEN, documented_key="request hash",
          permission=guard_create_approval, key_recipe=k_request_hash, inspector=lambda w, t, p, r: bool(r.get("approval_id"))),
    _spec("iam.get_approval", RiskClass.GREEN, mutating=False, permission=guard_readonly),
    _spec("iam.grant_access", RiskClass.AMBER, documented_key="approval id",
          permission=guard_grant_access, key_recipe=k_approval_id, inspector=insp_grant_access),
    _spec("okta.disable_mfa", RiskClass.AMBER, documented_key="approval id",
          permission=guard_disable_mfa, key_recipe=k_approval_id, inspector=insp_disable_mfa),
    # soc (RED)
    _spec("soc.open_incident", RiskClass.RED, documented_key="ticket id",
          permission=guard_soc, key_recipe=k_ticket, inspector=insp_incident),
    _spec("soc.page_oncall", RiskClass.RED, documented_key="ticket id",
          permission=guard_soc, key_recipe=k_ticket, inspector=insp_page),
]}

ALL_OPERATIONS = tuple(CATALOG.keys())
assert len(ALL_OPERATIONS) == 21, f"catalog must have 21 operations, has {len(ALL_OPERATIONS)}"
