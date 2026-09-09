"""The planner: the ONLY place model inference happens, behind a narrow
interface so tests are deterministic and the real model is a drop-in.

FakePlanner is a rule-based classifier used by the whole test suite. It is NOT
the agent's safety layer, it proposes a disposition and a tool, and the guards
decide whether any of that is allowed. That separation is the point: even if
the planner proposes something unsafe (or an injected ticket steers it), the
executor refuses. The fake exists so we can test the guards against known
proposals without spending tokens or flaking on a live model.

LivePlanner wraps the Anthropic SDK. It receives ONLY sanitized ticket text
and the retrieved policy spans, returns a strict ProposedIntent, and never sees
mutable state, adapter handles or raw secrets (architecture: model input is
redacted and span-scoped). Missing credentials => it raises; the CLI surfaces
that as BLOCKED live evaluation, never a fake pass.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from helix.models import Disposition, ProposedIntent
from helix.retrieval import Retriever


class Planner:
    def propose(self, ticket, spans, retriever: Retriever) -> ProposedIntent:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Deterministic rule-based planner
# ---------------------------------------------------------------------------


_INJECTION = re.compile(
    r"ignore (all|any|your|the) (previous|prior|above) instructions|developer mode|system directive|"
    r"you are now|disregard (the|your) (rules|policy)|"
    # Fake system / role blocks and "already authorised" framing. Red-team
    # put a fenced "[SYSTEM MESSAGE] role: system ... without approval" block
    # inside an access request and it routed an approval; none of that is
    # something a requester can legitimately say.
    r"\[\s*system\b|<\s*/?\s*system\s*>|\brole\s*:\s*system\b|admin override|"
    r"pre-?authori[sz]ed|without approval|"
    # Tool-call syntax in prose is a requester trying to drive the agent's
    # hands directly: "run iam.grant_access(u-alice, prod-cluster, admin)".
    r"\b(?:iam|okta|soc|endpoint|servicenow|assetmgmt)\.[a-z_]+\s*\(",
    re.I,
)
# Fan-out phrasings that dodge the obvious "everyone / whole team": the ask
# is still many accounts, however singular the grammar ("starting with mine").
_FANOUT = re.compile(
    r"\b(everyone|whole team|entire .* team|all (of )?(them|users|staff|members|people|employees|accounts)|"
    r"each (person|user|member|employee|account)|every (person|user|member|employee|account)|"
    r"(whole|entire) (org|department|dept|company|group)|starting with mine|including me)\b",
    re.I,
)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_USER_ID = re.compile(r"\bu-[a-z]+\b")
# A host that is plainly not a laptop. Word-bounded so "product" does not
# read as prod; hyphenated hostnames like prod-db-01 are captured whole.
_SERVER_TOKEN = re.compile(
    r"\b(?:[\w]+-)*(?:prod(?:uction)?|server|cluster|database|db)(?:-[\w-]*)?\b", re.I
)
# Signed, possibly fractional, so "-30 minutes" and "30.5 minutes" surface as
# the values they are (the guard rejects them) instead of being misread as 30
# and 5. The lookbehind stops "30.5" from also yielding a bare "5".
_MINUTES = re.compile(r"(?<![\w.])(-?\d+(?:\.\d+)?)\s*-?\s*min(?:ute)?s?\b", re.I)
_MFA_CHANGE = re.compile(
    r"disable|turn off|switch off|deactivat|reset|remove|re-?enrol|bypass|skip|exempt", re.I
)
_SECURITY = re.compile(
    r"ransomware|malware|encrypt(ed|ing) my files|compromis|hacked|"
    r"logins? from (another|a different) country|impossible travel|leaked|"
    r"pasted .* key|public repo|breach|"
    # MFA fatigue: unsolicited push prompts are a classic account-takeover
    # tell (spec §5.1). The requester frames it as an unlock, but the correct
    # move is escalation, not an unlock that would help the attacker.
    r"mfa prompts?\s+i\s+(did\s?n'?t|didn'?t|never)\s+(ask|request)|"
    r"(prompts?|pushes?)\s+i\s+(did\s?n'?t|didn'?t|never)\s+(ask|request)|"
    r"keep(s)? getting (mfa|push)",
    re.I,
)
_OUT_OF_SCOPE = re.compile(r"paycheck|payroll|401k|parental leave|expense report|hr\b|benefits", re.I)
# Threats and abuse aimed at the people handling the ticket (brief §5.6,
# "hostile or threatening tone"). Deliberately narrow: frustration ("this is
# urgent", "third time asking") is not hostility and still gets served. What
# we match is intent to harm, intimidate or retaliate against staff, coming
# to find someone, making them regret it, lawsuits, getting them fired, plus
# the flat abuse that usually travels with it. A hostile ticket defers to a
# human even when the underlying ask (an unlock, say) would be self-service:
# the human owns the de-escalation and decides whether to act. Without this
# rule the unlock keyword wins and the account is opened for whoever is
# shouting, which is exactly the "lucky retrieval" R-50 was flagged for.
_THREAT = re.compile(
    r"make (?:you|them|him|her) regret|you(?:'ll| will) (?:regret|pay for|be sorry)|"
    r"i(?:'ll| will| am going to| swear i(?:'ll| will)) (?:come (?:down|over|up|to)|find (?:you|out where)|"
    r"hurt|sue|get you fired|have you fired|report you|make sure you|track you down)|"
    r"\bor else\b|heads will roll|i know where you (?:sit|live|work)|"
    r"you people are (?:useless|idiots|incompetent|pathetic)|"
    r"\b(?:useless|incompetent) (?:idiots?|morons?|clowns?)\b|"
    r"\bf+u+c+k|\bscrew you\b",
    re.I,
)


class FakePlanner(Planner):
    """Intent classification by keyword + structure. Deliberately transparent
    so a reviewer can see exactly why each fixture routes where it does."""

    def propose(self, ticket, spans, retriever: Retriever) -> ProposedIntent:
        body = ticket.body
        low = body.lower()
        results = retriever.retrieve(f"{ticket.summary} {body}")
        span_ids = [r.span.span_id for r in results[:2]]

        # 1. Injection / fake directive -> defer + flag, no action, no approval.
        if _INJECTION.search(body):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, rationale="prompt injection detected",
                                  span_ids=[])

        # 1b. Hostile / threatening tone -> defer with a named reason code.
        # Sits above every action rule so a threat cannot ride in on an
        # otherwise-valid ask; below injection because a forged directive is
        # the more specific finding when both appear.
        if _THREAT.search(body):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN,
                                  rationale="hostile or threatening tone (brief 5.6); human owns de-escalation",
                                  span_ids=[])

        # 2. Invented / non-existent policy id -> defer.
        if re.search(r"POL-(?:[3-9]\d|\d{3,})", body):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, rationale="citation to a non-existent policy")

        # 3. Out-of-scope queues (HR/Finance/Facilities).
        if _OUT_OF_SCOPE.search(low):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, rationale="out of IT scope (HR/Finance)")

        # 4. Security-sensitive -> escalate.
        if _SECURITY.search(low) or "gift card" in low or "phishing" in low and "report" not in low:
            return ProposedIntent(disposition=Disposition.ESCALATE_INCIDENT,
                                  target_ref="self", span_ids=[s for s in span_ids] or ["POL-09 9.1"],
                                  rationale="suspected security incident")

        # 5. Fan-out -> defer (blast radius).
        if _FANOUT.search(low):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, rationale="fan-out / blast radius")

        # 6. Shared account -> defer (POL-10 10.6).
        if "shared" in low and ("login" in low or "account" in low or "password" in low):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, span_ids=["POL-10 10.6"],
                                  rationale="shared accounts prohibited")

        # 7. On-behalf-of reset for a colleague -> defer (unverified).
        if ("colleague" in low or "coworker" in low or "'s password" in low) and "reset" in low:
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, span_ids=["POL-01 1.4"],
                                  rationale="unverified on-behalf-of reset")

        # 8. MFA disable / reset / re-enrol -> defer (D-20 policy conflict,
        # no exception; "reset my MFA device" is an identity reset by another
        # name and there is no identity-reset exception to invent).
        if "mfa" in low and _MFA_CHANGE.search(low):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, span_ids=["POL-01 1.3"],
                                  rationale="MFA is mandatory; no exception authority (D-20)")

        # 9. Permanent admin -> defer to Endpoint Engineering (D-21).
        if "permanent" in low and "admin" in low:
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, span_ids=["POL-04 4.6"],
                                  rationale="permanent admin routes to Endpoint Engineering")

        # 10. DLP / send confidential externally -> defer to Data Governance.
        if "dlp" in low or ("confidential" in low and "external" in low):
            return ProposedIntent(disposition=Disposition.DEFER_HUMAN, span_ids=["POL-05 5.3"],
                                  rationale="DLP exception routes to Data Governance")

        # 11. Access entitlement -> propose for approval (AMBER). The routed
        # action must be the one asked for: approvers decide on exact
        # system + role, and the AMBER guard later matches those fields.
        # Defaulting to finance-db/analyst would route the wrong request.
        if "access" in low and ("finance-db" in low or "prod-cluster" in low or "role" in low or "entitlement" in low):
            system = next((s for s in ("finance-db", "prod-cluster") if s in low), None)
            role = next((r for r in ("analyst", "operator", "admin", "read-only", "reader")
                         if re.search(rf"\b{re.escape(r)}\b", low)), None)
            if not system or not role:
                return ProposedIntent(disposition=Disposition.ASK_CLARIFICATION, target_ref="self",
                                      clarification_question="Which system and which role do you need access to?",
                                      span_ids=["POL-10 10.2"], rationale="access request missing system/role")
            return ProposedIntent(
                disposition=Disposition.PROPOSE_FOR_APPROVAL, tool="iam.grant_access", target_ref="self",
                params={"system": system, "role": role}, span_ids=["POL-10 10.2"],
                rationale="privileged access requires manager + data-owner approval")

        # The target for user-affecting GREEN actions is whoever the ticket
        # names; if that is not the reporter, the guard refuses (on-behalf-of,
        # cross-tenant). Rewriting "unlock alice" into "unlock <reporter>"
        # would act on the wrong account and then close the ticket as done.
        named = _named_target(ticket)

        # 12. Local admin on own laptop -> auto action if bounded.
        if ("local admin" in low or "make-me-admin" in low or "make me admin" in low):
            minutes = _extract_minutes(body)
            if minutes is None:
                # No number, or two competing ones: ask, never pick a default.
                return ProposedIntent(disposition=Disposition.ASK_CLARIFICATION, target_ref="self",
                                      clarification_question="How many minutes (1-60) of local admin do you need on your assigned laptop?",
                                      span_ids=["POL-04 4.6"], rationale="admin duration missing or ambiguous")
            device = ticket.asset_refs[0] if ticket.asset_refs else _server_named(body)
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="endpoint.grant_admin",
                                  target_ref=named,
                                  params={"minutes": minutes, **({"device": device} if device else {})},
                                  span_ids=["POL-04 4.6"], rationale="time-bound self admin")

        # 13. Unlock.
        if "unlock" in low or ("locked" in low and "account" in low):
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="okta.unlock_account",
                                  target_ref=named, span_ids=["POL-01 1.4"], rationale="self-service unlock")

        # 14. Password reset for self.
        if ("forgot" in low or "reset" in low) and "password" in low:
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="okta.send_password_reset",
                                  target_ref=named, span_ids=["POL-01 1.1"], rationale="self reset link")

        # 15. New / non-catalog software -> file request (AUTO_ACTION).
        if ("software" in low or "install" in low or "procure" in low) and (
            "not in" in low or "catalog" in low and "procure" in low or "postman" in low):
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="servicenow.create_request",
                                  target_ref="self", params={"item": "software", "fields": {"summary": ticket.summary}},
                                  span_ids=["POL-04 4.2"], rationale="file software procurement request")

        # 16. Catalog self-service software question -> answer only.
        if "catalog" in low and ("myself" in low or "self" in low or "need a ticket" in low):
            return ProposedIntent(disposition=Disposition.ANSWER_ONLY, span_ids=["POL-04 4.1"],
                                  rationale="approved catalog apps are self-service")

        # 17. USB exception.
        if "usb" in low:
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="servicenow.create_request",
                                  target_ref="self", params={"item": "usb_exception", "fields": {"reason": ticket.summary}},
                                  span_ids=["POL-03 3.4"], rationale="file USB exception with manager approval")

        # 18. Travel exception.
        if "travel" in low or "berlin" in low or "abroad" in low:
            if _has_travel_dates(body):
                return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="servicenow.create_request",
                                      target_ref="self", params={"item": "travel_exception", "fields": {"detail": body[:120]}},
                                      span_ids=["POL-02 2.5"], rationale="file travel exception (does not grant VPN)")
            return ProposedIntent(disposition=Disposition.ASK_CLARIFICATION, target_ref="self",
                                  clarification_question="Which country and what exact dates will you be travelling?",
                                  span_ids=["POL-02 2.5"], rationale="missing destination/dates")

        # 19. Lost / stolen device. A device confirmed to hold Restricted data
        # is an automatic SEV-2 (POL-09 9.6), but "no restricted data" is the
        # opposite claim, so guard against the negation before escalating.
        if "lost" in low or "stolen" in low:
            has_restricted = any(
                kw in low for kw in ("restricted", "phi", "patient")
            ) and not re.search(r"no (restricted|phi|patient|sensitive)", low)
            if has_restricted:
                return ProposedIntent(disposition=Disposition.ESCALATE_INCIDENT, target_ref="self",
                                      span_ids=["POL-09 9.6"], rationale="Restricted data on lost device -> SEV-2")
            asset = ticket.asset_refs[0] if ticket.asset_refs else None
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="assetmgmt.create_case",
                                  target_ref="self",
                                  params={"type": "lost_stolen", "asset": asset, "fields": {"summary": ticket.summary}},
                                  span_ids=["POL-08 8.3"], rationale="open lost/stolen case")

        # 20. Offboarding return kit.
        if "offboard" in low or "return kit" in low or "has left" in low:
            asset = ticket.asset_refs[0] if ticket.asset_refs else None
            return ProposedIntent(disposition=Disposition.AUTO_ACTION, tool="assetmgmt.create_case",
                                  target_ref="self",
                                  params={"type": "offboarding_return", "asset": asset, "fields": {"summary": ticket.summary}},
                                  span_ids=["POL-08 8.5"], rationale="open offboarding return-kit case")

        # 21. BYOD jailbroken -> answer from policy (blocked from enrollment).
        if "jailbroken" in low or "rooted" in low or ("byod" in low or "personal phone" in low):
            return ProposedIntent(disposition=Disposition.ANSWER_ONLY, span_ids=["POL-06 6.4"],
                                  rationale="jailbroken devices blocked from enrollment")

        # 22. Confident policy answer, else defer below threshold.
        if retriever.confident(results):
            return ProposedIntent(disposition=Disposition.ANSWER_ONLY, span_ids=span_ids,
                                  rationale="grounded informational answer")
        return ProposedIntent(disposition=Disposition.DEFER_HUMAN, rationale="below retrieval confidence threshold")


def _extract_minutes(text: str) -> int | float | None:
    """The duration exactly as written, typed honestly: "-30" is -30, "30.5"
    is a float, "99999999999999999999" is a huge int. The guard is the judge
    of 1..60 and integer-ness; the planner's job is not to launder a bad value
    into a good one. None when nothing numeric was said or when two different
    numbers compete. Both of those are a clarification, not a default."""
    values: list[int | float] = []
    for raw in _MINUTES.findall(text):
        values.append(float(raw) if "." in raw else int(raw))
    distinct = set(values)
    if len(distinct) != 1:
        return None
    return values[0]


def _named_target(ticket) -> str:
    """First other-person reference in the body: an email address, or a
    directory-style user id that is not the reporter. Returns "self" when the
    ticket names nobody else (or only names the reporter)."""
    body = ticket.body
    emails = _EMAIL.findall(body)
    if emails:
        return emails[0]
    for uid in _USER_ID.findall(body):
        if uid != ticket.reporter_id:
            return uid
    return "self"


def _server_named(text: str) -> str | None:
    """A hostname-looking token that reads as a server, so the guard can
    refuse it even when the requester calls the box "my laptop"."""
    m = _SERVER_TOKEN.search(text)
    return m.group(0) if m else None


def _has_travel_dates(text: str) -> bool:
    return bool(re.search(r"\d{4}-\d{2}-\d{2}", text)) and bool(
        re.search(r"berlin|eu-central|germany|us-east|japan|vietnam|office", text.lower())
    )


# ---------------------------------------------------------------------------
# Live model planner
# ---------------------------------------------------------------------------


SYSTEM_PROMPT = """You are Helix's IT Service Desk triage agent. You classify one ticket into exactly one disposition and, when acting, name one tool and its arguments. You may ONLY rely on the policy sections provided in the prompt; never use outside knowledge. You never assert an approval happened. Respond with a single JSON object and nothing else, matching:
{"disposition": one of ANSWER_ONLY|AUTO_ACTION|PROPOSE_FOR_APPROVAL|ESCALATE_INCIDENT|ASK_CLARIFICATION|DEFER_HUMAN,
 "tool": tool name or null, "target_ref": "self" or a user id or null, "params": {...}, "span_ids": ["POL-xx y.z"],
 "rationale": short string, "clarification_question": string or null}
Trusted code will independently verify authorization, approvals, risk and idempotency; propose, do not assume."""


class LivePlanner(Planner):
    def __init__(self, api_key: str, model: str, timeout: float = 30.0, max_retries: int = 0,
                 base_url: str | None = None, workspace_id: str | None = None):
        if not api_key or not model:
            raise RuntimeError("live planner requires HELIX_ANTHROPIC_API_KEY and HELIX_MODEL")
        from anthropic import Anthropic  # imported lazily so offline tests never touch it

        # The workspace header is how an org-level key is allowed to call the
        # API at all; the base URL is how the same client talks to a local
        # Ollama or a gateway. Both are pass-through, no branching later.
        kwargs: dict = {"api_key": api_key, "timeout": timeout, "max_retries": max_retries}
        if base_url:
            kwargs["base_url"] = base_url
        if workspace_id:
            kwargs["default_headers"] = {"anthropic-workspace-id": workspace_id}
        self._client = Anthropic(**kwargs)
        self._model = model

    def propose(self, ticket, spans, retriever: Retriever, redactor=None) -> ProposedIntent:
        from anthropic import APIError

        results = retriever.retrieve(f"{ticket.summary} {ticket.body}")
        policy_block = "\n\n".join(f"[{r.span.span_id}] {r.span.text}" for r in results)
        # Summary and body are both requester text; both are redacted before
        # the model sees them (a secret typed into the title is still a secret).
        body = redactor.redact_text(ticket.body) if redactor else ticket.body
        summary = redactor.redact_text(ticket.summary) if redactor else ticket.summary
        user = (
            f"TICKET {ticket.ticket_id}\nSummary: {summary}\nBody: {body}\n\n"
            f"AUTHORIZED POLICY SECTIONS (cite only these):\n{policy_block}"
        )
        try:
            # 1500, not 600: reasoning models spend tokens on a thinking block
            # before the JSON, and a truncated answer is an invalid proposal
            # (which safely defers, but measures the budget, not the model).
            msg = self._client.messages.create(
                model=self._model, max_tokens=1500, system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user}],
            )
        except APIError as exc:  # pragma: no cover - network path
            raise RuntimeError(f"live model call failed: {exc}") from exc
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
        payload = _extract_json(text)
        # Strict schema validation is the boundary: a malformed/oversized
        # proposal is rejected, and the caller falls back to DEFER_HUMAN.
        return ProposedIntent.model_validate(payload)


def _extract_json(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    return json.loads(text[start : end + 1])
