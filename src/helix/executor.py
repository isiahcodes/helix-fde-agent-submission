"""Guarded dispatch and postcondition verification.

This is the only door to any state-changing operation. Every path, the normal
workflow, a requester reply, a retry, and a hostile direct call from the test
harness, comes through execute(). Nothing mutates the world except by going
through here, so the guards in guards.py cannot be bypassed (D-01,
CLAUDE.md invariant: "All mutating adapters are reachable only through guarded
dispatch. Direct hostile executor calls must be refused too.").

The sequence for a mutating op:
    1. re-read the current ticket; stop on withdrawal / terminal / revision
       drift (state can change between decision and action, spec §5.3).
    2. bind trusted context: resolve the target via the directory, derive the
       canonical fingerprint and the documented idempotency key ourselves.
    3. run the tool's guard. A refusal returns BLOCKED with zero mutation.
    4. fire before_dispatch_hook (test seam for withdrawal/revocation races),
       then re-read one more time.
    5. dispatch through the ledger adapter (idempotent, may silent-noop).
    6. verify the actual effect with the tool's inspector. API ok is NOT proof
       (spec §5.4). Unverified => not VERIFIED, ticket not closed.

Return shape is uniform: execution_status plus evidence, and an ActionEvent is
appended at each phase so the independent evaluator can reconstruct what
happened without trusting this module's own verdict.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from helix.config import Settings, load_settings
from helix.mock import MockWorld, canonical_fingerprint
from helix.models import (
    ActionEvent,
    ExecutionContext,
    ExecutionStatus,
    RiskClass,
    utcnow_iso,
)
from helix.registry import CATALOG
from helix.privacy import Redactor


class AdapterTimeout(RuntimeError):
    """One adapter attempt blew its wall-clock budget. Treated exactly like any
    other transient adapter error: a `retry` event under the same key, then the
    next attempt. Distinct type so the audit line can say *why*."""


@dataclass(frozen=True)
class RetryPolicy:
    """The retry schedule for mutating adapter calls (R-59).

    Attempt n (1-based) is followed by a sleep of base * 2**(n-1) + U(0, jitter)
    seconds, except the last attempt, which is followed by nothing because there
    is no attempt after it to wait for. adapter_timeout_seconds is the budget
    for ONE attempt; 0 disables the watchdog entirely (see config.py for why
    that is the default with the in-process mock).

    Frozen because the executor reads it on every dispatch and a test swaps the
    whole object rather than poking fields; a mutable policy shared across
    dispatches would be a race waiting to happen.
    """

    max_attempts: int = 3
    base_seconds: float = 0.0
    jitter_seconds: float = 0.0
    adapter_timeout_seconds: float = 0.0

    def __post_init__(self) -> None:
        # Fail loudly on nonsense config instead of silently retrying zero
        # times or sleeping a negative duration (time.sleep raises anyway).
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_seconds < 0 or self.jitter_seconds < 0 or self.adapter_timeout_seconds < 0:
            raise ValueError("backoff/jitter/timeout seconds must be >= 0")

    @classmethod
    def from_settings(cls, settings: Settings) -> RetryPolicy:
        return cls(
            base_seconds=settings.backoff_base_seconds,
            jitter_seconds=settings.backoff_jitter_seconds,
            adapter_timeout_seconds=settings.adapter_timeout_seconds,
        )

    def delay_for(self, attempt: int) -> float:
        """Seconds to wait after the given (1-based) attempt failed."""
        delay = self.base_seconds * (2 ** (attempt - 1))
        if self.jitter_seconds:
            delay += random.uniform(0.0, self.jitter_seconds)
        return delay


class Executor:
    def __init__(self, world: MockWorld, audit, redactor: Optional[Redactor] = None,
                 retry: Optional[RetryPolicy] = None):
        self.world = world
        self.audit = audit
        self.redactor = redactor or Redactor()
        self.before_dispatch_hook: Optional[Callable[[], None]] = None
        # Agent builds us without a policy, so the default has to come from
        # the HELIX_ environment here or the CLI path would never be
        # config-driven. Tests replace this attribute per case.
        self.retry: RetryPolicy = retry or RetryPolicy.from_settings(load_settings())

    def set_redactor(self, redactor: Redactor) -> None:
        self.redactor = redactor

    # -- adapter dispatch table: tool name -> the mock method it drives -------

    def _adapter_call(self, tool: str, ctx: ExecutionContext, target: str, params: dict, key: str) -> dict:
        w, t = self.world, ctx.tenant_id
        if tool == "okta.unlock_account":
            return w.okta_unlock(t, target, key)
        if tool == "okta.send_password_reset":
            return w.okta_send_reset(t, target, key)
        if tool == "okta.revoke_sessions":
            return w.okta_revoke_sessions(t, target, key)
        if tool == "okta.force_password_reset":
            return w.okta_force_reset(t, target, key)
        if tool == "okta.disable_mfa":
            return w.okta_disable_mfa(t, target, key)
        if tool == "servicenow.create_request":
            return w.servicenow_create_request(t, ctx.requester_id, params["item"], params.get("fields", {}), key)
        if tool == "endpoint.grant_admin":
            return w.endpoint_grant_admin(t, target, params["minutes"], key)
        if tool == "assetmgmt.create_case":
            return w.assetmgmt_create_case(t, params["type"], params.get("asset", target), params.get("fields", {}), key)
        if tool == "iam.grant_access":
            return w.iam_grant_access(t, target, params["system"], params["role"], key)
        if tool == "iam.create_approval":
            # Routing goes through the same door as everything else so the
            # event stream (and therefore the evaluator) sees every approval
            # filed. The description is generated text: redact it here too.
            return w.iam_create_approval(
                t, ctx.requester_id, target, params["tool"], params.get("params", {}),
                list(params.get("approvers", [])), key,
                description=self.redactor.redact_text(params.get("description", "")),
            )
        if tool == "soc.open_incident":
            summary = self.redactor.redact_text(params.get("summary", ""))
            return w.soc_open_incident(t, params.get("sev", "SEV-2"), summary, ctx.ticket_id, key)
        if tool == "soc.page_oncall":
            return w.soc_page_oncall(t, params.get("team", "SOC"), ctx.ticket_id, key)
        raise KeyError(f"no adapter wired for {tool}")

    # -- the one guarded entry point -----------------------------------------

    def execute(self, tool: str, ctx: ExecutionContext, target_ref: str, params: dict) -> dict:
        spec = CATALOG.get(tool)
        if spec is None:
            self._event(ctx, tool, "blocked", error="unknown tool")
            return {"execution_status": ExecutionStatus.BLOCKED.value, "reason": "unknown tool"}

        # Non-mutating workflow/read ops don't go through the ledger, but they
        # still must not fire on a withdrawn or wrong-tenant ticket.
        ticket = self.world.get_ticket(ctx.ticket_id)
        if ticket is None or ticket.tenant_id != ctx.tenant_id:
            self._event(ctx, tool, "blocked", error="ticket missing or tenant mismatch")
            return {"execution_status": ExecutionStatus.BLOCKED.value, "reason": "tenant/ticket"}
        if ticket.withdrawn:
            self._event(ctx, tool, "blocked", error="ticket withdrawn")
            return {"execution_status": ExecutionStatus.WITHDRAWN.value, "reason": "withdrawn"}

        # Resolve target: "self"/None -> requester; else directory lookup
        # WITHIN the tenant (a cross-tenant ref resolves to nothing).
        target_id = self._resolve_target(ctx, target_ref)
        if target_id is None:
            self._event(ctx, tool, "blocked", error="target unresolved")
            return {"execution_status": ExecutionStatus.BLOCKED.value, "reason": "target unresolved"}

        # Params are the one place ticket text can still flow into a sink
        # (a request's free-text fields, a case summary). Redact them before
        # any adapter sees them; ints and other non-strings pass through, so
        # the strict duration check downstream is unaffected.
        params = self.redactor.redact(params)

        self._event(ctx, tool, "attempted", args=params)

        # Guard. Fail closed on any refusal.
        guard = spec.permission
        reason = guard(self.world, ctx, target_id, params) if guard else None
        if reason:
            self._event(ctx, tool, "blocked", args=params, error=reason)
            return {"execution_status": ExecutionStatus.BLOCKED.value, "reason": reason}

        if not spec.mutating:
            # Workflow/read op: run it directly (transitions are validated by
            # the mock's own transition table) and return.
            result = self._workflow_call(tool, ctx, target_id, params)
            ok = result.get("ok", False)
            self._event(ctx, tool, "dispatched" if ok else "failed", args=params,
                        api_ok=ok, effect=ok, error=None if ok else result.get("error"))
            return {
                "execution_status": ExecutionStatus.VERIFIED.value if ok else ExecutionStatus.FAILED.value,
                "result": result,
            }

        # Mutating op: derive key + fingerprint ourselves, then race-recheck.
        key = spec.key_recipe(self.world, ctx, target_id, params) if spec.key_recipe else ctx.ticket_id

        if self.before_dispatch_hook:
            self.before_dispatch_hook()
        # Re-read AFTER the hook: withdrawal or approval revocation may have
        # landed in the gap. For AMBER, re-run the guard so a just-revoked
        # approval is caught immediately before the write.
        ticket = self.world.get_ticket(ctx.ticket_id)
        if ticket is None or ticket.withdrawn:
            self._event(ctx, tool, "blocked", error="withdrawn before dispatch")
            return {"execution_status": ExecutionStatus.WITHDRAWN.value, "reason": "withdrawn"}
        if spec.risk == RiskClass.AMBER:
            reason = guard(self.world, ctx, target_id, params)
            if reason:
                self._event(ctx, tool, "blocked", args=params, error=reason)
                return {"execution_status": ExecutionStatus.BLOCKED.value, "reason": reason}

        try:
            result = self._call_with_retry(
                lambda: self._adapter_call(tool, ctx, target_id, params, key), ctx, tool, key
            )
        except Exception as exc:  # exhausted retries (e.g. second-step failure)
            self._event(ctx, tool, "failed", args=params, logical_key=key,
                        error=self.redactor.redact_text(str(exc)))
            return {"execution_status": ExecutionStatus.FAILED.value, "reason": str(exc)}

        api_ok = result.get("ok", False)
        # Postcondition: read state back. This is what catches the silent
        # no-op, the ledger said ok, the inspector says nothing changed.
        effect = False
        if api_ok and spec.inspector:
            effect = bool(spec.inspector(self.world, target_id, params, result))
        elif api_ok and not spec.inspector:
            effect = api_ok

        phase = "verified" if effect else ("dispatched" if api_ok else "failed")
        self._event(ctx, tool, phase, args=params, logical_key=key, api_ok=api_ok, effect=effect,
                    error=None if api_ok else result.get("error"))

        if effect:
            status = ExecutionStatus.VERIFIED
        else:
            # Dispatched but no verified effect (the silent no-op), or the API
            # itself failed. Either way it is NOT a success, never a "done"
            # receipt, never a close.
            status = ExecutionStatus.FAILED
        return {"execution_status": status.value, "result": result, "logical_key": key, "effect": effect}

    # -- helpers --------------------------------------------------------------

    # Bounded retry for transient adapter errors. Safe ONLY because every
    # mutating call carries the same logical key on each attempt, so a retry
    # that lands after a "failed" first attempt replays through the ledger
    # instead of acting twice. We never retry a guard refusal (those return,
    # they don't raise) and never mint a new key. The schedule (attempts,
    # backoff, jitter, per-attempt timeout) lives in self.retry, fed from the
    # HELIX_ environment; tests pin it in tests/test_recovery.py.
    def _call_with_retry(self, fn, ctx: ExecutionContext, tool: str, key: str):
        policy = self.retry
        last: Optional[Exception] = None
        for attempt in range(1, policy.max_attempts + 1):
            try:
                return self._call_with_timeout(fn, policy.adapter_timeout_seconds)
            except Exception as exc:
                last = exc
                # The key is on every retry event so an audit reader (or the
                # test) can prove no attempt ever used a different key.
                self._event(ctx, tool, "retry", logical_key=key,
                            error=f"attempt {attempt}: {self.redactor.redact_text(str(exc))}")
                if attempt < policy.max_attempts:
                    delay = policy.delay_for(attempt)
                    if delay:
                        time.sleep(delay)
        assert last is not None
        raise last

    @staticmethod
    def _call_with_timeout(fn, timeout: float):
        """Run one adapter attempt under a wall-clock budget.

        timeout <= 0 means no watchdog: call inline. Otherwise the call runs on
        a daemon thread and we wait at most `timeout` seconds. Python cannot
        kill a thread, so a genuinely hung adapter keeps its thread parked; the
        daemon flag means it will not block interpreter exit, and we
        deliberately avoid concurrent.futures because its atexit hook joins
        workers and WOULD hang shutdown on exactly the case we are guarding.

        A late-landing attempt is not a double-act risk: every attempt carries
        the same logical key, so if the "hung" call eventually reaches the
        ledger it replays instead of acting twice (ADR-0003).

        Watch out: sqlite connections are bound to their creating thread, so
        this path is for network adapters; the in-process mock runs with
        timeout 0 (config.py explains the default).
        """
        if timeout <= 0:
            return fn()

        box: dict[str, Any] = {}

        def run() -> None:
            try:
                box["value"] = fn()
            except BaseException as exc:  # surfaced to the caller below
                box["error"] = exc

        worker = threading.Thread(target=run, name="helix-adapter-call", daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            raise AdapterTimeout(f"adapter call timed out after {timeout:g}s")
        if "error" in box:
            raise box["error"]
        return box["value"]

    def _resolve_target(self, ctx: ExecutionContext, target_ref: Optional[str]) -> Optional[str]:
        if target_ref in (None, "", "self", "me"):
            return ctx.requester_id
        # Explicit id or email, resolved within tenant only.
        u = self.world.directory_lookup(target_ref, ctx.tenant_id)
        return u.user_id if u else None

    def _workflow_call(self, tool: str, ctx: ExecutionContext, target_id: str, params: dict) -> dict:
        w = self.world
        if tool == "jira.comment":
            return w.jira_comment(ctx.ticket_id, self.redactor.redact_text(params.get("body", "")))
        if tool == "jira.transition":
            return w.jira_transition(ctx.ticket_id, params["to_status"])
        if tool == "jira.add_label":
            return w.jira_add_label(ctx.ticket_id, params["label"])
        if tool == "jira.link_issues":
            return w.jira_link_issues(ctx.ticket_id, params["other_id"])
        if tool == "jira.get":
            t = w.get_ticket(ctx.ticket_id)
            return {"ok": bool(t)}
        if tool in ("directory.lookup_user", "directory.verify_manager",
                    "okta.risk_signals", "iam.get_approval"):
            return {"ok": True}
        return {"ok": False, "error": f"unhandled workflow tool {tool}"}

    def _event(self, ctx: ExecutionContext, tool: str, phase: str, *, args: dict | None = None,
               logical_key: str | None = None, api_ok: bool | None = None,
               effect: bool | None = None, error: str | None = None) -> None:
        self.audit.append_event(ActionEvent(
            run_id=ctx.run_id, dispatch_id=ctx.dispatch_id, ticket_id=ctx.ticket_id,
            tenant_id=ctx.tenant_id, tool=tool, phase=phase,
            args=self.redactor.redact(args or {}), logical_key=logical_key,
            api_ok=api_ok, effect=effect,
            error=self.redactor.redact_text(error) if error else None, at=utcnow_iso(),
        ))
