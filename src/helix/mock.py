"""The synthetic enterprise world: Okta, IAM, ServiceNow, SOC, directory,
asset management and a JIRA-like ticket surface, all behind one SQLite file.

Design rules that matter here:

- SQLite is the single source of state AND the idempotency ledger (D-03).
  The ledger row and the effect commit in one transaction, so a repeat of the
  same logical key replays the stored first result without re-acting (D-06).
  We keep that honest by namespacing keys as tenant + tool + logical_key and
  binding each to a canonical fingerprint of the arguments, the same key with
  a *different* payload is refused, never silently replayed.

- Two deliberate failure modes ship with the mock because the spec
  grades recovery (spec §6): a silent no-op (the API answers ok=True but state
  does not change, the agent must read state back before claiming success)
  and a second-step failure (containment step two raises after step one
  landed, the agent must keep the useful containment and flag the rest).
  Both are switched per-tool via the failure_controls table, test-only.

- Mutation counting counts ACTUAL effects. A dispatched call that no-ops
  increments nothing; the evaluator separately counts the unsafe *dispatch*
  from the event stream (D-19). Don't merge those two meanings.

- generated_text() aggregates every string the system generated into the
  world (comments, approval descriptions, incident summaries). The redaction
  tests grep it; raw *seeded* ticket bodies are input, not output, and are
  excluded on purpose (architecture: the immutable input ticket may retain a
  synthetic secret; generated artifacts may not).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from helix.models import (
    ApprovalRecord,
    ApprovalStatus,
    Ticket,
    TicketStatus,
    User,
)


def canonical_fingerprint(payload: dict[str, Any]) -> str:
    """Stable hash of effect-bearing arguments. Canonical JSON so key order
    and int/float noise cannot make the same request look different."""

    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


class MockWorld:
    # Permitted JIRA-ish transitions. Guarded workflow code consults this; a
    # transition outside the table is refused (and scored as unsafe if it
    # somehow lands, D-19).
    TRANSITIONS: dict[str, set[str]] = {
        TicketStatus.OPEN.value: {
            TicketStatus.IN_PROGRESS.value,
            TicketStatus.WAITING_FOR_CUSTOMER.value,
            TicketStatus.PENDING_APPROVAL.value,
            TicketStatus.ESCALATED.value,
            TicketStatus.DONE.value,
            TicketStatus.WITHDRAWN.value,
        },
        TicketStatus.IN_PROGRESS.value: {
            TicketStatus.WAITING_FOR_CUSTOMER.value,
            TicketStatus.PENDING_APPROVAL.value,
            TicketStatus.ESCALATED.value,
            TicketStatus.DONE.value,
            TicketStatus.WITHDRAWN.value,
        },
        TicketStatus.WAITING_FOR_CUSTOMER.value: {
            TicketStatus.IN_PROGRESS.value,
            TicketStatus.WITHDRAWN.value,
            TicketStatus.DONE.value,
        },
        TicketStatus.PENDING_APPROVAL.value: {
            TicketStatus.IN_PROGRESS.value,
            TicketStatus.DONE.value,
            TicketStatus.WITHDRAWN.value,
            TicketStatus.ESCALATED.value,
        },
        TicketStatus.ESCALATED.value: {TicketStatus.IN_PROGRESS.value},
        # Done / Withdrawn are terminal.
        TicketStatus.DONE.value: set(),
        TicketStatus.WITHDRAWN.value: set(),
    }

    def __init__(self, path: Path | str):
        self.path = str(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self._init_schema()
        # Fixture clock (D-14): UTC, advanced explicitly by tests/CLI, so
        # calendar-day idempotency keys are stable on replay.
        self.now = self._get_meta("clock") or "2026-09-07T09:00:00Z"

    # ------------------------------------------------------------------ infra

    def _init_schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS accounts(user_id TEXT PRIMARY KEY, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS entitlements(
                user_id TEXT, system TEXT, role TEXT,
                PRIMARY KEY(user_id, system, role));
            CREATE TABLE IF NOT EXISTS admin_grants(
                user_id TEXT PRIMARY KEY, minutes INTEGER, granted_at TEXT);
            CREATE TABLE IF NOT EXISTS requests(
                request_id TEXT PRIMARY KEY, user_id TEXT, item TEXT, doc TEXT, day TEXT);
            CREATE TABLE IF NOT EXISTS cases(
                case_id TEXT PRIMARY KEY, case_type TEXT, asset TEXT, doc TEXT);
            CREATE TABLE IF NOT EXISTS approvals(approval_id TEXT PRIMARY KEY, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents(
                incident_id TEXT PRIMARY KEY, sev TEXT, summary TEXT, ticket_id TEXT,
                status TEXT DEFAULT 'OPEN');
            CREATE TABLE IF NOT EXISTS pages(
                page_id TEXT PRIMARY KEY, team TEXT, ticket_id TEXT);
            CREATE TABLE IF NOT EXISTS tickets(ticket_id TEXT PRIMARY KEY, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS comments(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT, author TEXT, body TEXT, at TEXT);
            -- Workflow-artifact dedup (D-07). JIRA comments and labels have no
            -- catalog idempotency key, so the worker's re-process-from-state
            -- loop (D-03) would post the same comment on every sweep. The
            -- workflow claims (ticket, revision, kind, sha256(body)) here
            -- before it writes and skips on a hit. revision is the requester
            -- content revision: a requester edit legitimately reopens the
            -- same wording, the agent's own bookkeeping never does.
            CREATE TABLE IF NOT EXISTS artifacts(
                ticket_id TEXT, revision INTEGER, kind TEXT, sha256 TEXT, at TEXT,
                PRIMARY KEY(ticket_id, revision, kind, sha256));
            -- The idempotency ledger. UNIQUE key is the whole point.
            CREATE TABLE IF NOT EXISTS ledger(
                tenant_id TEXT, tool TEXT, logical_key TEXT,
                fingerprint TEXT NOT NULL, result TEXT NOT NULL,
                effect INTEGER NOT NULL, at TEXT,
                PRIMARY KEY(tenant_id, tool, logical_key));
            -- Actual-effect counter per tool (mutations() in the harness).
            CREATE TABLE IF NOT EXISTS effect_counts(tool TEXT PRIMARY KEY, n INTEGER NOT NULL);
            -- Test-only failure switches: silent_noop:<tool> -> remaining count,
            -- fail_step:<tool> -> remaining count.
            CREATE TABLE IF NOT EXISTS failure_controls(name TEXT PRIMARY KEY, remaining INTEGER);
            -- Secret values seeded into the world so the redactor can treat
            -- them as known-sensitive strings (test canaries).
            CREATE TABLE IF NOT EXISTS known_secrets(value TEXT PRIMARY KEY);
            """
        )
        self.db.commit()

    def _get_meta(self, k: str) -> Optional[str]:
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row["v"] if row else None

    def _set_meta(self, k: str, v: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, v))
        self.db.commit()

    def set_clock(self, iso: str) -> None:
        self.now = iso
        self._set_meta("clock", iso)

    @property
    def day(self) -> str:
        return self.now[:10]

    def _bump_effect(self, tool: str) -> None:
        self.db.execute(
            "INSERT INTO effect_counts(tool,n) VALUES(?,1) "
            "ON CONFLICT(tool) DO UPDATE SET n=n+1",
            (tool,),
        )

    def mutation_count(self, tool: str) -> int:
        row = self.db.execute("SELECT n FROM effect_counts WHERE tool=?", (tool,)).fetchone()
        return row["n"] if row else 0

    # ----------------------------------------------------- failure controls

    def arm_failure(self, name: str, tool: str, count: int = 1) -> None:
        """name is 'silent_noop' or 'fail_step'. Test/seed plumbing only."""
        self.db.execute(
            "INSERT OR REPLACE INTO failure_controls(name,remaining) VALUES(?,?)",
            (f"{name}:{tool}", count),
        )
        self.db.commit()

    def _consume_failure(self, name: str, tool: str) -> bool:
        key = f"{name}:{tool}"
        row = self.db.execute(
            "SELECT remaining FROM failure_controls WHERE name=?", (key,)
        ).fetchone()
        if row and row["remaining"] > 0:
            self.db.execute(
                "UPDATE failure_controls SET remaining=remaining-1 WHERE name=?", (key,)
            )
            self.db.commit()
            return True
        return False

    # ------------------------------------------------------------- ledger

    def ledger_call(
        self,
        tenant_id: str,
        tool: str,
        logical_key: str,
        payload: dict[str, Any],
        effect_fn,
    ) -> dict[str, Any]:
        """Run a state-changing operation exactly once per logical key.

        Repeat with the same key AND same fingerprint -> stored first result,
        marked replayed, zero new effect. Same key, different payload -> hard
        refusal: someone is trying to ride an old key (D-06). The silent-noop
        failure mode is applied here so it is indistinguishable from a real
        flaky API from the caller's perspective.
        """

        fp = canonical_fingerprint(payload)
        row = self.db.execute(
            "SELECT fingerprint, result FROM ledger WHERE tenant_id=? AND tool=? AND logical_key=?",
            (tenant_id, tool, logical_key),
        ).fetchone()
        if row:
            if row["fingerprint"] != fp:
                return {
                    "ok": False,
                    "error": "idempotency_key_conflict",
                    "detail": "same logical key with different payload refused",
                }
            out = json.loads(row["result"])
            out["replayed"] = True
            return out

        if self._consume_failure("silent_noop", tool):
            # Lie like a flaky API: success on the wire, nothing changed.
            # Record it in the ledger so a naive retry under the same key gets
            # the same lie back instead of accidentally acting (the agent's
            # correct move is verification + flag, not key rotation).
            result = {"ok": True, "noop": True}
            self.db.execute(
                "INSERT INTO ledger(tenant_id,tool,logical_key,fingerprint,result,effect,at) "
                "VALUES(?,?,?,?,?,0,?)",
                (tenant_id, tool, logical_key, fp, json.dumps(result), self.now),
            )
            self.db.commit()
            return dict(result)

        result = effect_fn()
        had_effect = bool(result.pop("_effect", True)) and result.get("ok", False)
        self.db.execute(
            "INSERT INTO ledger(tenant_id,tool,logical_key,fingerprint,result,effect,at) "
            "VALUES(?,?,?,?,?,?,?)",
            (tenant_id, tool, logical_key, fp, json.dumps(result), int(had_effect), self.now),
        )
        if had_effect:
            self._bump_effect(tool)
        self.db.commit()
        return dict(result)

    # ---------------------------------------------------------- directory

    def get_user(self, user_id: str) -> Optional[User]:
        row = self.db.execute("SELECT doc FROM users WHERE user_id=?", (user_id,)).fetchone()
        return User.model_validate_json(row["doc"]) if row else None

    def directory_lookup(self, ref: str, tenant_id: str) -> Optional[User]:
        """Resolve a user reference (id or email) WITHIN a tenant. A ref from
        another tenant resolves to nothing, wrong-tenant requests get no
        tenant data (CLAUDE.md invariants)."""
        for row in self.db.execute("SELECT doc FROM users").fetchall():
            u = User.model_validate_json(row["doc"])
            if u.tenant_id != tenant_id:
                continue
            if ref in (u.user_id, u.email):
                return u
        return None

    def verify_manager(self, manager_id: str, report_id: str) -> bool:
        report = self.get_user(report_id)
        return bool(report and report.manager_id == manager_id)

    def asset_owner(self, asset: str) -> Optional[User]:
        """The user an asset tag is assigned to, or None if unassigned/unknown.
        Case-insensitive because asset tags arrive typed by humans."""
        if not asset:
            return None
        want = asset.strip().lower()
        for row in self.db.execute("SELECT doc FROM users").fetchall():
            u = User.model_validate_json(row["doc"])
            if u.assigned_laptop and u.assigned_laptop.lower() == want:
                return u
        return None

    # -------------------------------------------------------------- okta

    def get_account(self, user_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT doc FROM accounts WHERE user_id=?", (user_id,)).fetchone()
        return json.loads(row["doc"]) if row else {}

    def _put_account(self, user_id: str, doc: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO accounts(user_id,doc) VALUES(?,?)",
            (user_id, json.dumps(doc)),
        )

    def okta_risk_signals(self, user_id: str) -> dict[str, Any]:
        acct = self.get_account(user_id)
        return acct.get(
            "risk", {"compromise": False, "mfa_fatigue": False, "impossible_travel": False}
        )

    def okta_unlock(self, tenant_id: str, user_id: str, logical_key: str) -> dict[str, Any]:
        def effect():
            acct = self.get_account(user_id)
            if not acct.get("locked"):
                return {"ok": True, "already_unlocked": True, "_effect": False}
            acct["locked"] = False
            self._put_account(user_id, acct)
            return {"ok": True, "unlocked": user_id}

        return self.ledger_call(
            tenant_id, "okta.unlock_account", logical_key, {"user": user_id}, effect
        )

    def okta_send_reset(self, tenant_id: str, user_id: str, logical_key: str) -> dict[str, Any]:
        def effect():
            acct = self.get_account(user_id)
            acct["reset_link_sent_day"] = self.day
            self._put_account(user_id, acct)
            return {"ok": True, "reset_sent": user_id}

        return self.ledger_call(
            tenant_id, "okta.send_password_reset", logical_key, {"user": user_id}, effect
        )

    def okta_revoke_sessions(self, tenant_id: str, user_id: str, logical_key: str) -> dict:
        def effect():
            acct = self.get_account(user_id)
            if acct.get("sessions", 0) == 0:
                return {"ok": True, "already_zero": True, "_effect": False}
            acct["sessions"] = 0
            self._put_account(user_id, acct)
            return {"ok": True, "sessions_revoked": user_id}

        return self.ledger_call(
            tenant_id, "okta.revoke_sessions", logical_key, {"user": user_id}, effect
        )

    def okta_force_reset(self, tenant_id: str, user_id: str, logical_key: str) -> dict:
        # Second-step failure mode lives here because force-reset is the
        # canonical "step two" of containment (revoke -> force reset).
        if self._consume_failure("fail_step", "okta.force_password_reset"):
            raise RuntimeError("okta.force_password_reset: upstream 503")

        def effect():
            acct = self.get_account(user_id)
            acct["force_reset"] = True
            self._put_account(user_id, acct)
            return {"ok": True, "force_reset": user_id}

        return self.ledger_call(
            tenant_id, "okta.force_password_reset", logical_key, {"user": user_id}, effect
        )

    def okta_disable_mfa(self, tenant_id: str, user_id: str, logical_key: str) -> dict:
        def effect():
            acct = self.get_account(user_id)
            acct["mfa_enabled"] = False
            self._put_account(user_id, acct)
            return {"ok": True, "mfa_disabled": user_id}

        return self.ledger_call(
            tenant_id, "okta.disable_mfa", logical_key, {"user": user_id}, effect
        )

    # -------------------------------------------------------- servicenow

    SUPPORTED_ITEMS = {"software", "usb_exception", "travel_exception"}

    def servicenow_create_request(
        self, tenant_id: str, user_id: str, item: str, fields: dict, logical_key: str
    ) -> dict:
        def effect():
            rid = f"REQ-{self.db.execute('SELECT COUNT(*) c FROM requests').fetchone()['c'] + 1:04d}"
            self.db.execute(
                "INSERT INTO requests(request_id,user_id,item,doc,day) VALUES(?,?,?,?,?)",
                (rid, user_id, item, json.dumps(fields), self.day),
            )
            return {"ok": True, "request_id": rid, "item": item}

        return self.ledger_call(
            tenant_id,
            "servicenow.create_request",
            logical_key,
            {"user": user_id, "item": item, "fields": fields},
            effect,
        )

    # ---------------------------------------------------------- endpoint

    def endpoint_grant_admin(
        self, tenant_id: str, user_id: str, minutes: int, logical_key: str
    ) -> dict:
        def effect():
            self.db.execute(
                "INSERT OR REPLACE INTO admin_grants(user_id,minutes,granted_at) VALUES(?,?,?)",
                (user_id, minutes, self.now),
            )
            return {"ok": True, "granted": user_id, "minutes": minutes}

        return self.ledger_call(
            tenant_id,
            "endpoint.grant_admin",
            logical_key,
            {"user": user_id, "minutes": minutes},
            effect,
        )

    # --------------------------------------------------------- assetmgmt

    CASE_TYPES = {"lost_stolen", "offboarding_return"}

    def assetmgmt_create_case(
        self, tenant_id: str, case_type: str, asset: str, fields: dict, logical_key: str
    ) -> dict:
        def effect():
            cid = f"CASE-{self.db.execute('SELECT COUNT(*) c FROM cases').fetchone()['c'] + 1:04d}"
            self.db.execute(
                "INSERT INTO cases(case_id,case_type,asset,doc) VALUES(?,?,?,?)",
                (cid, case_type, asset, json.dumps(fields)),
            )
            return {"ok": True, "case_id": cid, "type": case_type}

        return self.ledger_call(
            tenant_id,
            "assetmgmt.create_case",
            logical_key,
            {"type": case_type, "asset": asset, "fields": fields},
            effect,
        )

    # --------------------------------------------------------------- iam

    def iam_get_approval(self, approval_id: Optional[str]) -> Optional[ApprovalRecord]:
        if not approval_id:
            return None
        row = self.db.execute(
            "SELECT doc FROM approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()
        return ApprovalRecord.model_validate_json(row["doc"]) if row else None

    def iam_create_approval(
        self,
        tenant_id: str,
        requester_id: str,
        target_id: str,
        tool: str,
        params: dict,
        approvers: list[str],
        logical_key: str,
        description: str,
    ) -> dict:
        def effect():
            aid = f"APR-{self.db.execute('SELECT COUNT(*) c FROM approvals').fetchone()['c'] + 1:04d}"
            rec = ApprovalRecord(
                approval_id=aid,
                tenant_id=tenant_id,
                requester_id=requester_id,
                target_id=target_id,
                tool=tool,
                params=params,
                canonical_hash=canonical_fingerprint(
                    {
                        "tenant": tenant_id,
                        "tool": tool,
                        "requester": requester_id,
                        "target": target_id,
                        "params": params,
                    }
                ),
                status=ApprovalStatus.PENDING,
                required_approvers=approvers,
            )
            self.db.execute(
                "INSERT INTO approvals(approval_id,doc) VALUES(?,?)",
                (aid, rec.model_dump_json()),
            )
            # The routed description is generated output, store it where the
            # redaction sweep can see it.
            self._record_generated(f"approval {aid}: {description}")
            return {"ok": True, "approval_id": aid}

        return self.ledger_call(
            tenant_id, "iam.create_approval", logical_key,
            {"requester": requester_id, "target": target_id, "tool": tool, "params": params},
            effect,
        )

    def iam_grant_access(
        self, tenant_id: str, user_id: str, system: str, role: str, logical_key: str
    ) -> dict:
        def effect():
            self.db.execute(
                "INSERT OR IGNORE INTO entitlements(user_id,system,role) VALUES(?,?,?)",
                (user_id, system, role),
            )
            return {"ok": True, "granted": [user_id, system, role]}

        return self.ledger_call(
            tenant_id, "iam.grant_access", logical_key,
            {"user": user_id, "system": system, "role": role},
            effect,
        )

    def admin_set_approval(self, approval_id: str, status: str) -> None:
        """Out-of-band approver decision (D-10). Test and demo harness only;
        never reachable from the model or the workflow."""
        rec = self.iam_get_approval(approval_id)
        if not rec:
            raise KeyError(approval_id)
        decisions = {a: status for a in rec.required_approvers}
        updated = rec.model_copy(
            update={
                "status": ApprovalStatus(status),
                "decisions": decisions,
                "version": rec.version + 1,
            }
        )
        self.db.execute(
            "UPDATE approvals SET doc=? WHERE approval_id=?",
            (updated.model_dump_json(), approval_id),
        )
        self.db.commit()

    # --------------------------------------------------------------- soc

    def soc_open_incident(
        self, tenant_id: str, sev: str, summary: str, ticket_id: str, logical_key: str
    ) -> dict:
        def effect():
            iid = f"INC-{self.db.execute('SELECT COUNT(*) c FROM incidents').fetchone()['c'] + 1:04d}"
            self.db.execute(
                "INSERT INTO incidents(incident_id,sev,summary,ticket_id) VALUES(?,?,?,?)",
                (iid, sev, summary, ticket_id),
            )
            self._record_generated(f"incident {iid} [{sev}]: {summary}")
            return {"ok": True, "incident_id": iid, "sev": sev}

        return self.ledger_call(
            tenant_id, "soc.open_incident", logical_key,
            {"sev": sev, "summary": summary, "ticket": ticket_id},
            effect,
        )

    def soc_page_oncall(self, tenant_id: str, team: str, ticket_id: str, logical_key: str) -> dict:
        def effect():
            pid = f"PAGE-{self.db.execute('SELECT COUNT(*) c FROM pages').fetchone()['c'] + 1:04d}"
            self.db.execute(
                "INSERT INTO pages(page_id,team,ticket_id) VALUES(?,?,?)",
                (pid, team, ticket_id),
            )
            return {"ok": True, "page_id": pid, "team": team}

        return self.ledger_call(
            tenant_id, "soc.page_oncall", logical_key, {"team": team, "ticket": ticket_id}, effect
        )

    # ------------------------------------------------------------ tickets

    def get_ticket(self, ticket_id: str) -> Optional[Ticket]:
        row = self.db.execute("SELECT doc FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
        return Ticket.model_validate_json(row["doc"]) if row else None

    def put_ticket(self, t: Ticket) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO tickets(ticket_id,doc) VALUES(?,?)",
            (t.ticket_id, t.model_dump_json()),
        )
        self.db.commit()

    def jira_comment(self, ticket_id: str, body: str, author: str = "agent") -> dict:
        # Comments are generated output: always recorded where the redaction
        # sweep looks. Workflow keys are n/a per the catalog; dedup by
        # (ticket, revision, artifact hash) lives in
        # workflow.py::Agent._emit_artifact, backed by artifact_seen /
        # record_artifact below. This method itself stays keyless on purpose:
        # a hostile or buggy caller reaching it directly is what the audit
        # trail and the evaluator are for, not a silent swallow here.
        self.db.execute(
            "INSERT INTO comments(ticket_id,author,body,at) VALUES(?,?,?,?)",
            (ticket_id, author, body, self.now),
        )
        self.db.commit()
        self._bump_effect("jira.comment")
        return {"ok": True}

    def jira_transition(self, ticket_id: str, to_status: str) -> dict:
        t = self.get_ticket(ticket_id)
        if not t:
            return {"ok": False, "error": "no_such_ticket"}
        allowed = self.TRANSITIONS.get(t.status.value, set())
        if to_status not in allowed:
            return {"ok": False, "error": f"illegal_transition {t.status.value} -> {to_status}"}
        # Status, labels and links are the agent's own bookkeeping and leave
        # revision alone. revision tracks requester-visible content (edits,
        # replies) because it is part of the D-07 dedup key: if our own writes
        # moved it, every sweep would see a "new" ticket and re-post.
        t = t.model_copy(update={"status": TicketStatus(to_status)})
        self.put_ticket(t)
        self._bump_effect("jira.transition")
        return {"ok": True, "status": to_status}

    def jira_add_label(self, ticket_id: str, label: str) -> dict:
        t = self.get_ticket(ticket_id)
        if not t:
            return {"ok": False, "error": "no_such_ticket"}
        if label not in t.labels:
            t = t.model_copy(update={"labels": t.labels + [label]})
            self.put_ticket(t)
            self._bump_effect("jira.add_label")
        return {"ok": True}

    def jira_link_issues(self, ticket_id: str, other_id: str) -> dict:
        t = self.get_ticket(ticket_id)
        if not t:
            return {"ok": False, "error": "no_such_ticket"}
        if other_id not in t.links:
            t = t.model_copy(update={"links": t.links + [other_id]})
            self.put_ticket(t)
            self._bump_effect("jira.link_issues")
        return {"ok": True}

    # Workflow-artifact dedup (D-07). Two calls rather than one atomic claim
    # because the write in between can still be refused (withdrawn ticket,
    # tenant mismatch) and we only want to remember artifacts that landed.
    # The body is hashed, not stored: a comment can carry redacted ticket text
    # and this table is not a generated sink the redaction sweep reads.

    @staticmethod
    def _artifact_hash(body: str) -> str:
        return hashlib.sha256(body.encode()).hexdigest()

    def artifact_seen(self, ticket_id: str, revision: int, kind: str, body: str) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM artifacts WHERE ticket_id=? AND revision=? AND kind=? AND sha256=?",
            (ticket_id, revision, kind, self._artifact_hash(body)),
        ).fetchone()
        return row is not None

    def record_artifact(self, ticket_id: str, revision: int, kind: str, body: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO artifacts(ticket_id,revision,kind,sha256,at) VALUES(?,?,?,?,?)",
            (ticket_id, revision, kind, self._artifact_hash(body), self.now),
        )
        self.db.commit()

    def find_inflight_duplicate(self, ticket: Ticket, fingerprint: str) -> Optional[str]:
        """An exact in-flight duplicate: another non-terminal ticket whose
        bound-request fingerprint matches (D-12). Fingerprints are stamped on
        tickets by the workflow when it binds an action."""
        for row in self.db.execute("SELECT doc FROM tickets").fetchall():
            t = Ticket.model_validate_json(row["doc"])
            if t.ticket_id == ticket.ticket_id:
                continue
            if t.status.value in (TicketStatus.DONE.value, TicketStatus.WITHDRAWN.value):
                continue
            if self._get_meta(f"fp:{t.ticket_id}") == fingerprint:
                return t.ticket_id
        return None

    def stamp_fingerprint(self, ticket_id: str, fingerprint: str) -> None:
        self._set_meta(f"fp:{ticket_id}", fingerprint)

    # -------------------------------------------------- observation utils

    def _record_generated(self, text: str) -> None:
        self._set_meta(
            "generated",
            (self._get_meta("generated") or "") + "\n" + text,
        )

    def generated_text(self) -> str:
        parts = [self._get_meta("generated") or ""]
        for row in self.db.execute("SELECT author, body FROM comments").fetchall():
            if row["author"] == "agent":
                parts.append(row["body"])
        # Request and case field docs are sinks too: the agent copies ticket
        # text into them (a travel request's "detail", a case's summary). A
        # secret that reaches ServiceNow is just as leaked as one in a comment,
        # so the redaction sweep has to see these rows.
        for table in ("requests", "cases"):
            for row in self.db.execute(f"SELECT doc FROM {table}").fetchall():
                parts.append(row["doc"])
        return "\n".join(parts)

    def known_secrets(self) -> list[str]:
        return [r["value"] for r in self.db.execute("SELECT value FROM known_secrets").fetchall()]

    def inspect(self, path: str) -> Any:
        """Dotted-path read for tests/CLI: 'accounts.u-alice', 'tickets.T-1',
        'approvals.APR-0001', 'requests', 'incidents', 'entitlements.u-x'."""
        head, _, rest = path.partition(".")
        if head == "accounts":
            return self.get_account(rest)
        if head == "tickets":
            t = self.get_ticket(rest)
            return json.loads(t.model_dump_json()) if t else None
        if head == "approvals":
            a = self.iam_get_approval(rest)
            return json.loads(a.model_dump_json()) if a else None
        if head == "users":
            u = self.get_user(rest)
            return json.loads(u.model_dump_json()) if u else None
        if head == "entitlements":
            return [
                dict(r)
                for r in self.db.execute(
                    "SELECT user_id, system, role FROM entitlements WHERE user_id=?", (rest,)
                ).fetchall()
            ]
        if head == "admin_grants":
            row = self.db.execute(
                "SELECT minutes, granted_at FROM admin_grants WHERE user_id=?", (rest,)
            ).fetchone()
            return dict(row) if row else None
        if head == "requests":
            return [
                dict(r)
                for r in self.db.execute(
                    "SELECT request_id, user_id, item, day FROM requests"
                ).fetchall()
            ]
        if head == "cases":
            return [
                dict(r)
                for r in self.db.execute("SELECT case_id, case_type, asset FROM cases").fetchall()
            ]
        if head == "incidents":
            return [
                dict(r)
                for r in self.db.execute(
                    "SELECT incident_id, sev, summary, ticket_id, status FROM incidents"
                ).fetchall()
            ]
        if head == "pages":
            return [
                dict(r)
                for r in self.db.execute("SELECT page_id, team, ticket_id FROM pages").fetchall()
            ]
        if head == "comments":
            return [
                dict(r)
                for r in self.db.execute(
                    "SELECT author, body, at FROM comments WHERE ticket_id=?", (rest,)
                ).fetchall()
            ]
        raise KeyError(path)


# ---------------------------------------------------------------------------
# Scenario seeding
# ---------------------------------------------------------------------------


def load_world_fixture(world: MockWorld, fixture: dict[str, Any]) -> None:
    """Import a world.json document. Explicit command only (D-15): the CLI's
    seed/reset, never on worker resume."""

    with world.db:
        for table in (
            "users", "accounts", "entitlements", "admin_grants", "requests", "cases",
            "approvals", "incidents", "pages", "tickets", "comments", "ledger",
            "effect_counts", "failure_controls", "known_secrets", "meta",
        ):
            world.db.execute(f"DELETE FROM {table}")
        for u in fixture.get("users", []):
            user = User.model_validate(u)
            world.db.execute(
                "INSERT INTO users(user_id,doc) VALUES(?,?)", (user.user_id, user.model_dump_json())
            )
        for user_id, acct in fixture.get("accounts", {}).items():
            world.db.execute(
                "INSERT INTO accounts(user_id,doc) VALUES(?,?)", (user_id, json.dumps(acct))
            )
        for e in fixture.get("entitlements", []):
            world.db.execute(
                "INSERT INTO entitlements(user_id,system,role) VALUES(?,?,?)",
                (e["user_id"], e["system"], e["role"]),
            )
        for a in fixture.get("approvals", []):
            rec = ApprovalRecord.model_validate(a)
            world.db.execute(
                "INSERT INTO approvals(approval_id,doc) VALUES(?,?)",
                (rec.approval_id, rec.model_dump_json()),
            )
        for t in fixture.get("tickets", []):
            ticket = Ticket.model_validate(t)
            world.db.execute(
                "INSERT INTO tickets(ticket_id,doc) VALUES(?,?)",
                (ticket.ticket_id, ticket.model_dump_json()),
            )
        for s in fixture.get("known_secrets", []):
            world.db.execute("INSERT OR IGNORE INTO known_secrets(value) VALUES(?)", (s,))
        for fp in fixture.get("fingerprints", {}).items():
            world.db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (f"fp:{fp[0]}", fp[1]))
    world.set_clock(fixture.get("clock", "2026-09-07T09:00:00Z"))
    for arm in fixture.get("failures", []):
        world.arm_failure(arm["mode"], arm["tool"], arm.get("count", 1))


def load_scenario(world: MockWorld, name: str) -> None:
    """Named scenarios are slices/overrides of fixtures/world.json plus
    per-scenario ticket & failure additions defined in fixtures/scenarios.json.
    Keeping them as data (not code) means the eval and the demo seed the exact
    same worlds."""

    root = Path(__file__).resolve().parents[2] / "fixtures"
    base = json.loads((root / "world.json").read_text())
    scenarios = json.loads((root / "scenarios.json").read_text())
    if name not in scenarios:
        raise KeyError(f"unknown scenario {name!r}")
    overlay = scenarios[name]
    merged = dict(base)
    for key in ("tickets", "approvals", "users", "entitlements", "known_secrets", "failures"):
        merged[key] = list(base.get(key, [])) + list(overlay.get(key, []))
    merged["accounts"] = {**base.get("accounts", {}), **overlay.get("accounts", {})}
    merged["fingerprints"] = {**base.get("fingerprints", {}), **overlay.get("fingerprints", {})}
    if "clock" in overlay:
        merged["clock"] = overlay["clock"]
    load_world_fixture(world, merged)
