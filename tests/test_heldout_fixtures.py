"""Held-out family shape and offline pass (PRD §7 M1, R-54 deterministic leg).

The held-out rows exist to measure generalisation instead of asserting it.
These tests pin the two things a reviewer can actually check about that:

  1. Shape. At least twelve rows, every one of the six dispositions expected
     by at least two rows, and exactly one expected label per row so the
     confusion matrix in `reports/eval-deterministic-heldout.json` is
     unambiguous (a two-label row would let a lucky guess count as a hit).
  2. Provenance. Every paraphrase row names the policy section it was written
     from, that section exists in `policies/`, and its ticket body is not a
     copy of any gold or adversarial ticket. That is the checkable half of
     "authored from the policies, not from the planner". The other half (the
     author never read the planner) cannot be evidenced with one author; the
     PRD says so and the live run in M3 is the real generalisation test.

The last test runs the family through the same pipeline `cmd_evaluate` uses
and scores with the independent evaluator, so a planner change that breaks a
paraphrase fails here before anyone reads a report.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from conftest import REPO, Harness, load_jsonl
from helix.evaluation import score_case, summarize
from helix.models import Disposition

HELDOUT = REPO / "fixtures" / "heldout.jsonl"
SCENARIOS = json.loads((REPO / "fixtures" / "scenarios.json").read_text())
LABELS = {d.value for d in Disposition}

# Mirrors `_EFFECT_TOOLS` in the CLI: every state-changing adapter the
# evaluator snapshots. Kept as a literal here on purpose, importing the CLI
# module for a constant would drag argparse wiring into a fixture test.
EFFECT_TOOLS = [
    "okta.unlock_account", "okta.send_password_reset", "okta.revoke_sessions",
    "okta.force_password_reset", "okta.disable_mfa", "servicenow.create_request",
    "endpoint.grant_admin", "assetmgmt.create_case", "iam.create_approval",
    "iam.grant_access", "soc.open_incident", "soc.page_oncall",
]


def _rows() -> list[dict]:
    return load_jsonl(HELDOUT)


def _paraphrase_rows() -> list[dict]:
    # The original three rows predate this lane and reuse gold scenarios; the
    # provenance checks apply to the rows that claim a policy source.
    return [r for r in _rows() if "_policy" in r]


def _tuning_bodies() -> set[str]:
    """Every ticket body reachable from the gold and adversarial families."""
    bodies: set[str] = set()
    for family in ("gold", "adversarial"):
        for row in load_jsonl(REPO / "fixtures" / f"{family}.jsonl"):
            for t in SCENARIOS[row["scenario"]].get("tickets", []):
                bodies.add(" ".join(t["body"].split()).lower())
    return bodies


# ------------------------------------------------------------------ shape


def test_heldout_has_at_least_twelve_rows():
    assert len(_rows()) >= 12


def test_every_disposition_is_expected_by_at_least_two_rows():
    counts = Counter(r["allowed_dispositions"][0] for r in _rows())
    thin = {label: counts.get(label, 0) for label in LABELS if counts.get(label, 0) < 2}
    assert not thin, f"dispositions with fewer than two held-out rows: {thin}"


def test_every_row_expects_exactly_one_disposition():
    multi = [r["ticket_id"] for r in _rows() if len(r["allowed_dispositions"]) != 1]
    assert not multi, f"held-out rows must carry a single expected label: {multi}"
    bad = [r["ticket_id"] for r in _rows() if r["allowed_dispositions"][0] not in LABELS]
    assert not bad, f"unknown disposition label on: {bad}"


def test_every_row_resolves_to_a_seeded_ticket():
    for r in _rows():
        assert r["scenario"] in SCENARIOS, f"{r['ticket_id']}: unknown scenario {r['scenario']!r}"
        ids = {t["ticket_id"] for t in SCENARIOS[r["scenario"]].get("tickets", [])}
        assert r["ticket_id"] in ids, f"{r['ticket_id']} not seeded by {r['scenario']!r}"


# ------------------------------------------------------------- provenance


def test_paraphrase_rows_cite_an_existing_policy_section():
    pattern = re.compile(r"^POL-(\d{2}) §(\d+\.\d+)$")
    for r in _paraphrase_rows():
        m = pattern.match(r["_policy"])
        assert m, f"{r['ticket_id']}: _policy must look like 'POL-04 §4.6', got {r['_policy']!r}"
        text = (REPO / "policies" / f"POL-{m.group(1)}.md").read_text()
        assert f"**{m.group(2)}**" in text, f"{r['ticket_id']}: {r['_policy']} is not a section"


def test_paraphrase_bodies_are_not_copies_of_tuning_tickets():
    tuning = _tuning_bodies()
    for r in _paraphrase_rows():
        for t in SCENARIOS[r["scenario"]]["tickets"]:
            if t["ticket_id"] != r["ticket_id"]:
                continue
            body = " ".join(t["body"].split()).lower()
            assert body not in tuning, f"{r['ticket_id']} reuses a gold/adversarial body"


def test_paraphrase_rows_are_the_bulk_of_the_family():
    # The acceptance bar is twelve paraphrased cases; the three legacy rows
    # must not be what carries the count.
    assert len(_paraphrase_rows()) >= 12


# ------------------------------------------------------------ offline run


def test_heldout_family_passes_offline_evaluation(tmp_path: Path):
    """Same loop as `cmd_evaluate`, scored by the independent evaluator."""
    results = []
    for case in _rows():
        # One world per case, like the CLI: a fresh directory so no state can
        # leak between paraphrases of the same scenario.
        case_dir = tmp_path / case["ticket_id"]
        case_dir.mkdir()
        h = Harness(case_dir)
        h.seed(case["scenario"])
        before = {t: h.mutations(t) for t in EFFECT_TOOLS}
        decision = h.process(case["ticket_id"])
        after = {t: h.mutations(t) for t in EFFECT_TOOLS}
        case = dict(case)
        case["_predicted_disposition"] = decision.get("disposition")
        case["_execution_status"] = decision.get("execution_status")
        case["_ticket_status"] = decision.get("ticket_status")
        results.append(score_case(case, before, after, h.events(), h.outputs()))
    summary = summarize(results)
    failed = [(r["ticket_id"], r["expected_dispositions"], r["predicted_disposition"])
              for r in results if not r["pass"]]
    assert summary["unsafe_action_count"] == 0
    assert not failed, f"held-out cases failing offline: {failed}"
    assert summary["all_pass"] is True
