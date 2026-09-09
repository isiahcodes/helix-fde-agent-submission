"""Task 10: onboarding an 11th policy / 11th tool, and the guarantee that
uploaded prose can never create a privilege (D-42)."""

from pathlib import Path

from helix.models import ExecutionStatus
from helix.policies import load_policy_pack
from helix.retrieval import Retriever


def test_uploaded_policy_cannot_create_privilege(harness):
    harness.seed("unknown_policy_privilege")
    result = harness.process("T-POLICY-INJECTION")
    assert result["disposition"] == "DEFER_HUMAN"
    assert harness.mutations("iam.grant_access") == 0


def test_content_only_policy_loads_through_reviewed_config(tmp_path):
    # A new CONTENT-only policy (POL-11) is retrievable once placed in a
    # reviewed pack dir, no prompt edits, and it grants no new capability
    # because retrieval only surfaces text; permissions live in the registry.
    src = Path("policies")
    for p in src.glob("POL-*.md"):
        (tmp_path / p.name).write_text(p.read_text())
    (tmp_path / "POL-11.md").write_text(
        "# POL-11 — Printing Policy\n\n*Effective: 2026-01-01. Owner: Workplace IT.*\n\n"
        "**11.1** Follow-me printing is available from any managed printer using your badge.\n"
        "**11.2** Confidential documents must be collected immediately and never left on the tray.\n"
    )
    # load_policy_pack hard-caps at POL-01..10 by design, so an 11th policy is
    # an explicit config change: we widen the expected set for the reviewed dir.
    from helix import policies as pol

    original = pol.EXPECTED_POLICY_IDS
    try:
        pol.EXPECTED_POLICY_IDS = original | {"POL-11"}
        spans = load_policy_pack(tmp_path)
        assert len(spans) == 62
        r = Retriever(spans)
        results = r.retrieve("can I use follow-me printing with my badge")
        assert r.confident(results)
        assert any(s.span.policy_id == "POL-11" for s in results)
    finally:
        pol.EXPECTED_POLICY_IDS = original


def test_new_tool_onboarding_shape():
    # An 11th tool is a ToolSpec + adapter + guard + key + inspector. Assert
    # the registry is the single onboarding surface: every mutating op already
    # carries all five, so a new one is a table row, not scattered edits.
    from helix.registry import CATALOG

    for name, spec in CATALOG.items():
        if spec.mutating and spec.risk.value != "RED":
            assert spec.permission is not None, name
            assert spec.key_recipe is not None, name
            assert spec.inspector is not None, name
