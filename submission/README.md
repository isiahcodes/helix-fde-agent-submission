# Helix IT Service Desk Agent

**The customer's problem:** Helix's helpdesk is drowning in tickets that ask
for *actions*. Unlock me, reset me, give me access. They arrive in a
SOX/HIPAA/GDPR environment where one wrong action is worse than a hundred
wrong answers.
**The solution design:** an agent that monitors the JIRA Service Desk, commits
each ticket to exactly one of six dispositions and, where the disposition is
to act, executes the correct tool against mock enterprise systems (Okta, IAM,
ServiceNow, SOC, asset management). Every mutating path is gated by trusted
code, never by the model. The organizing idea is **judgment under the ability
to act**.

## Architecture

One plain Python state machine, one worker, one SQLite file for both the
synthetic world and the idempotency ledger. No LangGraph, no vector store, no
UI on the critical path.

```
new ticket / reply / approval update / retry
  → worker loads the CURRENT ticket (trusted reporter id + tenant from login)
  → build a per-ticket redactor from known secrets; install on audit + executor
  → retrieve only authorized policy sections (BM25 + exact-id, calibrated conf.)
  → planner (LLM or fake) proposes ONE disposition + tool + args + citations
  → controller validates citation SUPPORT, routes to one of six handlers
  → executor: re-read state → guard → derive key/hash → dispatch → verify effect
  → grounded receipt, permitted transition, sanitized audit line
```

The model proposes. It never asserts. A `ProposedIntent` is a strict schema
that **rejects** any requester id, tenant, canonical hash, idempotency key or
"approved" flag. Those are claims. Trusted code (`guards.py`, `executor.py`)
derives and validates all of them from adapter reads. Every mutating adapter is
reachable **only** through the guarded executor, so a direct hostile call is
refused exactly as a workflow call is.

## Prompt strategy & grounding

The planner receives only sanitized ticket text plus the retrieved policy
spans, and must return strict JSON. Grounding is enforced two ways: retrieval
is limited to the 60 authorized policy sections (an eleventh policy is a
reviewed config change, never a file drop), and every citation is
**support-validated**. A real policy id the ticket never pointed at is not
grounding and is dropped. Below-confidence retrieval defers rather than
improvising.

## Where we drew the act-vs-instruct line

| Class | Rule enforced in code |
|---|---|
| **GREEN** | Execute autonomously once grounded **and** the requester is authorized for the target. Only ever the requester's own account/device. |
| **GREEN\*** (unlock) | Read current risk **inside dispatch**. A compromise / MFA-fatigue / impossible-travel signal withholds the unlock and routes to escalation. |
| **AMBER** (grant_access, disable_mfa) | Never executed without an `APPROVED` record matching tenant, requester, target, tool and effect params, re-read immediately before the write. No record → draft + route via `iam.create_approval`, leave pending. In-band "already approved" claims are ignored. |
| **RED** (SOC) | Escalation only. Needs incident evidence, not an approval. Never closes as resolved. |

Hard refusals, by policy, with no approval ever filed: `okta.disable_mfa`
(POL-01 1.3 mandates MFA, and no exception authority is supplied, so it is
policy-blocked and DEFER_HUMAN at ticket level), permanent local admin (routes
to Endpoint Engineering, POL-04 4.6), DLP external-send and auto-forwarding
(route to Data Governance), shared accounts (POL-10 10.6), fan-out requests,
prompt injection, and citations to non-existent policies.

## Idempotency, verification, recovery

Every state-changing call carries the catalog's documented idempotency key,
namespaced `tenant + tool + logical_key` and bound to a canonical fingerprint.
A repeat replays the first result with zero new effect, and the same key with a
different payload is refused. API `ok` is never proof. After every action the
executor **reads state back**, so the mock's silent-no-op failure mode is
caught and never reported as done. On a multi-step containment where step two
fails, successful step one (revoked sessions) is preserved and the remainder
flagged, never rolled back. Withdrawals are honored on a re-read immediately
before dispatch. Exact in-flight duplicates link instead of re-acting.

## Secrets

A per-ticket redactor (seeded canaries + heuristic patterns) is applied
recursively through nested structures, before model input and at every
generated sink: comment, log, trace, exception, approval description,
incident summary. Incident detection is preserved without ever storing the
secret value.

## Evaluation

`python -m helix evaluate` runs the full gold set in isolated worlds and scores
**independently** from the dispatch event stream and before/after state, never
from the guard's own verdict. It counts unsafe dispatch (even on a no-op),
unsafe effect, false success, secret leak and missed eligible action
separately, plus a confusion matrix and per-disposition precision/recall. Any
unsafe action, leak, false success or required-case miss exits nonzero. See
`submission/evaluation/eval-{gold,adversarial,heldout}.{csv,json}`, exported with this
bundle, and regenerated into `reports/` on every run.

Latest deterministic run: **gold 44/44, adversarial 42/42, held-out 23/23, with 0
unsafe actions, 0 unsafe effects, 0 false successes, 0 secret leaks and 0 missed
actions across all three sets.** Every hole the red-team lane found became a
guard with a regression test.

## Run it

```sh
uv venv --python 3.12 .venv && uv pip sync --python .venv/bin/python requirements.lock.txt
uv pip install --python .venv/bin/python -e .
.venv/bin/python -m pytest -q                         # 167 tests
.venv/bin/python -m helix evaluate                    # gold
.venv/bin/python -m helix evaluate --gold fixtures/adversarial.jsonl   # red-team, unsafe must be 0
.venv/bin/python -m helix evaluate --gold fixtures/heldout.jsonl       # held-out
# approval round-trip demo:
.venv/bin/python -m helix seed pending_access
.venv/bin/python -m helix process T-ACCESS            # routes for approval, does NOT execute
.venv/bin/python -m helix mock-approve APR-0005 APPROVED
.venv/bin/python -m helix process T-ACCESS            # executes once, verified
```

Live evaluation (`--live`) requires `HELIX_ANTHROPIC_API_KEY` and `HELIX_MODEL`
in a local `.env`. Without them it is reported BLOCKED rather than faked.

It has been run, and the results are reported apart from the deterministic
numbers because they measure a different thing. A live model matched the
expected disposition far less often (gold 20/44, adversarial 29/42, held-out
12/23) while **still producing zero unsafe actions, zero unsafe effects and
zero secret leaks on every set**. That gap is the argument for this design.
The planner is where correctness varies, and the guards are what stop a bad
plan from becoming a bad action.

## Deployment judgment

In platform terms, this is one **Colleague** running one **Agent Operating
Protocol** (the six-disposition workflow), where each catalog tool is a
**Skill** with a risk class, and the guarded executor is the **Orchestrator**
that decides whether a Skill may fire. The reusable asset for the catalog is
the AOP plus its guard table and eval fixtures, not the prompt.

**Before a real Colleague touches Okta.** The first weeks after go-live are
hypercare, owned by the FDE. In that window I would run the agent in
*propose-only* mode for every GREEN Skill
(AUTO_ACTION drafted, human clicks execute), sample 100% of AUTO_ACTIONs
against the audit log, flag any Skill whose risk class the customer's
security team wants promoted (unlock and grant_admin are the usual AMBER
candidates in regulated shops), and confirm residency and SSO constraints
before any tenant data flows.

**Healthcare vs. fintech.** The disposition machine and guards are
customer-agnostic. What changes is the policy pack, the risk thresholds, and
which classes escalate. For a healthcare customer, POL-05/POL-09 (PHI, Restricted
device loss → SEV-2) carry the most weight and the "Restricted geography" and
retention rules (HIPAA, 10-year PHI) become gating. For fintech, SOX
change-control and payment-data handling (13-month purge) dominate, and more
GREEN actions become AMBER because segregation-of-duties requires an approver
even for routine grants. Neither is a code change. Both are policy content plus
a reviewed risk-class table.

**Onboarding policy #11 / tool #11.** A content-only policy enters retrieval
through a reviewed pack directory with no prompt edits and grants no new
capability (retrieval surfaces text, while permissions live in the registry).
A new tool is one `ToolSpec` row carrying its risk class, permission guard, key
recipe and postcondition inspector, plus its mock adapter and positive/negative
tests. The registry is the single onboarding surface.

**Another language.** Retrieval and the planner prompt are language-scoped.
We would localize the policy corpus, add per-language retrieval calibration
fixtures, and keep the guards (which read ids and state, not prose) unchanged.

## What we would harden before production

Real external APIs cannot share the mock's single-transaction
ledger-plus-effect atomicity, so production needs conditional/versioned
authorization where the vendor supports it, remote idempotency keys, an outbox
with reconciliation, and explicit handling of the time-of-check/time-of-use
window our immediate re-read narrows but does not eliminate. Add rate limiting
and per-tenant isolation on the ticket intake, a real secrets manager, dense
retrieval where measured gaps justify it, and human-in-the-loop review sampling
on GREEN auto-actions during rollout.
