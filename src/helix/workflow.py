"""The six-disposition workflow and the Agent that runs it.

This is the controller between the (untrusted) planner and the (trusted)
executor. For each ticket it:
  1. loads the trusted ticket and builds a per-ticket redactor from the world's
     known secrets, then installs it on the audit log + executor so nothing
     downstream can leak a canary.
  2. gets a ProposedIntent (from the live/fake planner, or an injected one in
     tests). The proposal is validated by the strict schema on the way in.
  3. validates policy SUPPORT for the citations, a plausible id the ticket
     never pointed at is not grounding (D-28).
  4. dispatches to exactly one of six disposition handlers, each of which
     produces the artifact the spec requires (§4). Actions go
     through executor.execute; the handler never touches the mock directly.

The controller derives the disposition from the proposal but is NOT bound by
it for safety: if a proposal says AUTO_ACTION but the guard blocks the tool,
the ticket does not close and the handler reports the block truthfully. The
disposition label and the execution status are separate axes throughout (D-04).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from helix.executor import Executor
from helix.guards import NO_APPROVAL_RECORD
from helix.mock import MockWorld, canonical_fingerprint
from helix.models import (
    Decision,
    Disposition,
    ExecutionContext,
    ExecutionStatus,
    ProposedIntent,
    TicketStatus,
)
from helix.planner import Planner
from helix.policies import load_policy_pack
from helix.privacy import Redactor
from helix.retrieval import Retriever

_POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"


class Agent:
    def __init__(self, world: MockWorld, planner: Planner, audit, policies_dir: Path = _POLICIES_DIR):
        self.world = world
        self.planner = planner
        self.audit = audit
        self.spans = load_policy_pack(policies_dir)
        self.retriever = Retriever(self.spans)
        self.executor = Executor(world, audit)

    # -- public API used by the harness/CLI ----------------------------------

    def process(self, ticket_id: str, injected_proposal: Optional[dict] = None) -> dict:
        ticket = self.world.get_ticket(ticket_id)
        if ticket is None:
            return {"error": "no_such_ticket"}

        # Per-ticket redaction boundary, installed before any generated output.
        redactor = Redactor(self.world.known_secrets())
        self.audit.set_redactor(redactor)
        self.executor.set_redactor(redactor)

        ctx = ExecutionContext(
            ticket_id=ticket_id, revision=ticket.revision, tenant_id=ticket.tenant_id,
            requester_id=ticket.reporter_id, run_id=uuid.uuid4().hex[:8],
            dispatch_id=uuid.uuid4().hex[:8],
        )

        # Withdrawn before we even start: honor it (spec §5.3, D-05).
        if ticket.withdrawn:
            return self._finish(ctx, Disposition.DEFER_HUMAN, ExecutionStatus.WITHDRAWN,
                                TicketStatus.WITHDRAWN, [], reason="ticket withdrawn").model_dump(mode="json")

        # Get the proposal. Injected proposals still pass the strict schema.
        if injected_proposal is not None:
            proposal = ProposedIntent.model_validate(injected_proposal)
        else:
            proposal = self._plan(ticket, redactor)

        # Record (redacted) planner input coverage for the output sink test.
        # The summary is ticket text too, a secret typed into the title is
        # as leaked as one in the body.
        self.audit.model_input_note(redactor.redact_text(f"{ticket.summary} {ticket.body}"))

        # Citation support: keep only citations the retriever actually backs.
        results = self.retriever.retrieve(f"{ticket.summary} {ticket.body}")
        supported = [c for c in proposal.span_ids if self.retriever.supports([c], results)]

        handler = {
            Disposition.ANSWER_ONLY: self._answer_only,
            Disposition.AUTO_ACTION: self._auto_action,
            Disposition.PROPOSE_FOR_APPROVAL: self._propose_for_approval,
            Disposition.ESCALATE_INCIDENT: self._escalate_incident,
            Disposition.ASK_CLARIFICATION: self._ask_clarification,
            Disposition.DEFER_HUMAN: self._defer_human,
        }[proposal.disposition]
        decision = handler(ctx, ticket, proposal, supported)
        return decision.model_dump(mode="json")

    def hostile_dispatch(self, tool: str, ticket_id: str, args: dict) -> dict:
        """A direct call into the guarded executor, skipping the workflow,
        the attacker's path. Guards must hold (D-01)."""
        ticket = self.world.get_ticket(ticket_id)
        if ticket is None:
            return {"execution_status": ExecutionStatus.BLOCKED.value, "reason": "no ticket"}
        redactor = Redactor(self.world.known_secrets())
        self.executor.set_redactor(redactor)
        ctx = ExecutionContext(
            ticket_id=ticket_id, revision=ticket.revision, tenant_id=ticket.tenant_id,
            requester_id=ticket.reporter_id, run_id=uuid.uuid4().hex[:8], dispatch_id="hostile",
        )
        target = args.pop("target", "self") if isinstance(args, dict) else "self"
        return self.executor.execute(tool, ctx, target, args)

    # -- planning -------------------------------------------------------------

    def _plan(self, ticket, redactor: Redactor) -> ProposedIntent:
        try:
            # LivePlanner takes an extra redactor kwarg; the fake ignores it.
            try:
                return self.planner.propose(ticket, self.spans, self.retriever, redactor=redactor)  # type: ignore[call-arg]
            except TypeError:
                return self.planner.propose(ticket, self.spans, self.retriever)
        except Exception:
            # A model failure or malformed proposal is never a silent action.
            # It defers to a human.
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, rationale="planner unavailable/invalid")

    # -- disposition handlers -------------------------------------------------

    def _answer_only(self, ctx, ticket, proposal, cites) -> Decision:
        # Pure grounded answer. If we cannot ground it, that is a DEFER, not a
        # confident-but-unsupported reply (spec §5.6).
        if not cites:
            return self._defer_human(ctx, ticket, proposal, cites, reason="no supported citation")
        body = f"{proposal.rationale}. See {', '.join(cites)}."
        self._emit_artifact(ctx, "jira.comment", {"body": body})
        self.executor.execute("jira.transition", ctx, "self", {"to_status": TicketStatus.DONE.value})
        return self._finish(ctx, Disposition.ANSWER_ONLY, ExecutionStatus.NONE, TicketStatus.DONE,
                            cites, reason="answered from policy", comment=body)

    def _auto_action(self, ctx, ticket, proposal, cites) -> Decision:
        if not proposal.tool:
            return self._defer_human(ctx, ticket, proposal, cites, reason="auto action without a tool")

        # Idempotency/duplicate: stamp this action's fingerprint and check for
        # an in-flight duplicate before acting (D-12).
        fp = canonical_fingerprint(
            {"tool": proposal.tool, "target": ticket.reporter_id, "params": proposal.params}
        )
        dup = self.world.find_inflight_duplicate(ticket, fp)
        if dup:
            self.executor.execute("jira.link_issues", ctx, "self", {"other_id": dup})
            return self._finish(ctx, Disposition.AUTO_ACTION, ExecutionStatus.DUPLICATE_LINKED,
                                ticket.status, cites, reason=f"linked in-flight duplicate {dup}")
        self.world.stamp_fingerprint(ticket.ticket_id, fp)

        res = self.executor.execute(proposal.tool, ctx, proposal.target_ref or "self", proposal.params)
        status = ExecutionStatus(res["execution_status"])
        if status == ExecutionStatus.VERIFIED:
            comment = f"Done: {proposal.tool} completed and verified. Basis: {', '.join(cites) or proposal.rationale}."
            self._emit_artifact(ctx, "jira.comment", {"body": comment})
            self.executor.execute("jira.transition", ctx, "self", {"to_status": TicketStatus.DONE.value})
            return self._finish(ctx, Disposition.AUTO_ACTION, status, TicketStatus.DONE, cites,
                                reason="action verified", comment=comment)
        # GREEN* promotion (spec §3, §5.1): the unlock guard read a live
        # compromise / MFA-fatigue / impossible-travel signal on the
        # requester's own account. That is trusted evidence of an active
        # attack, however innocent the ticket sounds, escalate with
        # containment instead of leaving a "could not complete" note.
        if proposal.tool == "okta.unlock_account" and str(res.get("reason", "")).startswith("risk signal"):
            return self._escalate_incident(ctx, ticket, proposal, cites, force_containment=True)
        # Blocked or unverified: do NOT close. Comment truthfully.
        comment = f"Could not complete {proposal.tool}: {res.get('reason', 'effect not verified')}."
        self._emit_artifact(ctx, "jira.comment", {"body": comment})
        return self._finish(ctx, Disposition.AUTO_ACTION, status, TicketStatus.IN_PROGRESS, cites,
                            reason=res.get("reason", "not verified"), comment=comment)

    def _propose_for_approval(self, ctx, ticket, proposal, cites) -> Decision:
        # Same guard as _auto_action, and it is not theoretical: a live model
        # asked for approval without naming a tool, which reached the executor
        # as tool=None and raised out of the agent instead of deferring. An
        # unnamed action cannot be routed for approval either, because there
        # is nothing for an approver to approve.
        if not proposal.tool:
            return self._defer_human(ctx, ticket, proposal, cites,
                                     reason="approval proposed without a tool")

        # Check IAM first. APPROVED + matching -> execute; else route/relay.
        res = self.executor.execute(proposal.tool, ctx, proposal.target_ref or "self", proposal.params)
        status = ExecutionStatus(res["execution_status"])
        if status == ExecutionStatus.VERIFIED:
            comment = f"Approved and executed: {proposal.tool}. Basis: {', '.join(cites) or proposal.rationale}."
            self._emit_artifact(ctx, "jira.comment", {"body": comment})
            self.executor.execute("jira.transition", ctx, "self", {"to_status": TicketStatus.DONE.value})
            return self._finish(ctx, Disposition.PROPOSE_FOR_APPROVAL, status, TicketStatus.DONE, cites,
                                approval_id=ticket.approval_ref, reason="approved+verified", comment=comment)

        # Not executable now. Route ONLY when the guard's sole objection was a
        # missing record. Any other refusal (policy-blocked disable_mfa,
        # deactivated user, unresolved / cross-tenant target) means the
        # action is prohibited outright and no approval is filed for it
        # (spec §3: "get no approval filed at all, refuse or defer").
        rec = self.world.iam_get_approval(ticket.approval_ref)
        reason = str(res.get("reason", ""))
        if rec is None and reason != NO_APPROVAL_RECORD:
            return self._defer_human(ctx, ticket, proposal, cites, reason=reason or "not routable")
        if rec is None:
            approvers = ["manager", "data-owner"]
            route = self.executor.execute("iam.create_approval", ctx, "self", {
                "tool": proposal.tool, "params": proposal.params, "approvers": approvers,
                "description": f"Route {proposal.tool} for {ctx.requester_id}",
            })
            approval_id = (route.get("result") or {}).get("approval_id")
            if ExecutionStatus(route["execution_status"]) != ExecutionStatus.VERIFIED or not approval_id:
                return self._defer_human(ctx, ticket, proposal, cites,
                                         reason=route.get("reason", "approval routing failed"))
            ticket = ticket.model_copy(update={"approval_ref": approval_id})
            self.world.put_ticket(ticket)
            comment = (f"Routed {proposal.tool} for approval ({approval_id}); awaiting {', '.join(approvers)}. "
                       f"Basis: {', '.join(cites) or proposal.rationale}. Not executed.")
            self._emit_artifact(ctx, "jira.comment", {"body": comment})
            self.executor.execute("jira.transition", ctx, "self", {"to_status": TicketStatus.PENDING_APPROVAL.value})
            return self._finish(ctx, Disposition.PROPOSE_FOR_APPROVAL, ExecutionStatus.PENDING_APPROVAL,
                                TicketStatus.PENDING_APPROVAL, cites, approval_id=approval_id,
                                reason="routed for approval", comment=comment)

        # A record exists but is not executable: relay its TRUE status; never
        # act on an in-band claim (spec §4, §5.5).
        # Include the guard's reason: an APPROVED record that belongs to a
        # different requester/tenant/action is "approved" for someone else,
        # and the comment should not read as if the approval is merely late.
        comment = (f"Approval {rec.approval_id} status is {rec.status.value}; cannot execute "
                   f"{proposal.tool} ({reason or 'record does not match this action'}).")
        self._emit_artifact(ctx, "jira.comment", {"body": comment})
        return self._finish(ctx, Disposition.PROPOSE_FOR_APPROVAL, ExecutionStatus.BLOCKED,
                            TicketStatus.PENDING_APPROVAL, cites, approval_id=rec.approval_id,
                            reason=f"approval {rec.status.value}", comment=comment)

    def _escalate_incident(self, ctx, ticket, proposal, cites, force_containment: bool = False) -> Decision:
        # Open incident + page, take any GREEN containment available, give the
        # POL-09 instruction, never close (spec §4). Containment failing does
        # not roll back what already stuck (D-18).
        sev = "SEV-2"
        low = ticket.body.lower()
        if "patient" in low or "phi" in low or "restricted" in low:
            sev = "SEV-2"
        redactor = Redactor(self.world.known_secrets())
        # Redact FIRST, truncate second. Truncating the raw body could cut a
        # secret in half so the exact-match redactor never saw it, and ship
        # the first half to SOC.
        summary = redactor.redact_text(f"{ticket.summary}: {ticket.body}")[:160]
        # The incident evidence is a trusted-context fact: only this handler
        # sets it, and the RED guard reads it from ctx, never from params.
        ctx = ctx.model_copy(update={"incident_evidence": True})
        self.executor.execute("soc.open_incident", ctx, "self", {"sev": sev, "summary": summary})
        self.executor.execute("soc.page_oncall", ctx, "self", {"team": "SOC"})

        exec_status = ExecutionStatus.VERIFIED
        # Containment for account compromise: revoke sessions (step 1), force
        # reset (step 2). Keep step 1 even if step 2 fails. A live risk
        # signal (force_containment) counts as compromise evidence even when
        # the ticket text says nothing of the sort.
        if force_containment or "compromis" in low or "logins from" in low or "impossible" in low or "session" in low:
            r1 = self.executor.execute("okta.revoke_sessions", ctx, "self", {})
            r2 = self.executor.execute("okta.force_password_reset", ctx, "self", {})
            if ExecutionStatus(r2["execution_status"]) != ExecutionStatus.VERIFIED:
                exec_status = ExecutionStatus.INCOMPLETE

        instruction = ("Do NOT power off the device. Disconnect it from the network and await SOC "
                       "instructions (POL-09 9.2).")
        comment = f"Escalated as {sev}. {instruction}"
        self._emit_artifact(ctx, "jira.comment", {"body": comment})
        self.executor.execute("jira.transition", ctx, "self", {"to_status": TicketStatus.ESCALATED.value})
        return self._finish(ctx, Disposition.ESCALATE_INCIDENT, exec_status, TicketStatus.ESCALATED,
                            cites or ["POL-09 9.1"], reason="security incident escalated", comment=comment)

    def _ask_clarification(self, ctx, ticket, proposal, cites) -> Decision:
        q = proposal.clarification_question or "Could you provide the missing details?"
        self._emit_artifact(ctx, "jira.comment", {"body": q})
        self._emit_artifact(ctx, "jira.add_label", {"label": "needs-clarification"})
        self.executor.execute("jira.transition", ctx, "self",
                              {"to_status": TicketStatus.WAITING_FOR_CUSTOMER.value})
        return self._finish(ctx, Disposition.ASK_CLARIFICATION, ExecutionStatus.NONE,
                            TicketStatus.WAITING_FOR_CUSTOMER, cites, reason="asked for detail", comment=q)

    def _defer_human(self, ctx, ticket, proposal, cites, reason: str = "") -> Decision:
        why = reason or proposal.rationale or "out of scope / below confidence"
        comment = f"Routing to a human: {why}."
        self._emit_artifact(ctx, "jira.comment", {"body": comment})
        self._emit_artifact(ctx, "jira.add_label", {"label": "deferred"})
        return self._finish(ctx, Disposition.DEFER_HUMAN, ExecutionStatus.NONE, TicketStatus.IN_PROGRESS,
                            cites, reason=why, comment=comment)

    # -- workflow artifacts ---------------------------------------------------

    # Which param carries the artifact body for each keyless JIRA write. Only
    # these two are deduped: transitions are validated by the mock's own
    # table and link_issues already no-ops on a present link.
    _ARTIFACT_BODY_PARAM = {"jira.comment": "body", "jira.add_label": "label"}

    def _emit_artifact(self, ctx, tool: str, params: dict) -> dict:
        """D-07 dedup in front of the executor. The worker re-runs the whole
        pipeline on every non-terminal ticket (D-03), and a deferred or
        waiting ticket stays non-terminal for as long as a human takes, so
        without this, each sweep would post the same comment and label again.
        The key is (ticket, requester revision, kind, sha256(body)); a
        requester edit moves the revision and legitimately reopens the same
        wording. This is a workflow concern, not a guard: the executor still
        sees, audits and guards every write that does go through."""
        kind = self._ARTIFACT_BODY_PARAM[tool]
        body = str(params.get(kind, ""))
        if self.world.artifact_seen(ctx.ticket_id, ctx.revision, kind, body):
            return {"execution_status": ExecutionStatus.NONE.value, "reason": "duplicate artifact"}
        res = self.executor.execute(tool, ctx, "self", params)
        # Remember only what landed. A refused write (withdrawn, tenant) must
        # not poison the key for a later pass that is allowed to speak.
        if res.get("execution_status") == ExecutionStatus.VERIFIED.value:
            self.world.record_artifact(ctx.ticket_id, ctx.revision, kind, body)
        return res

    # -- result assembly ------------------------------------------------------

    def _finish(self, ctx, disposition, exec_status, ticket_status, cites, *,
                approval_id=None, reason="", comment="") -> Decision:
        decision = Decision(
            ticket_id=ctx.ticket_id, disposition=disposition, execution_status=exec_status,
            ticket_status=ticket_status, citations=cites, approval_id=approval_id,
            reason_code=reason, comment=comment,
        )
        self.audit.record_decision(decision)
        return decision
