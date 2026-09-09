"""Task 3: the stateful mock and idempotency ledger."""

from helix.mock import canonical_fingerprint


def test_same_unlock_has_one_effect(harness):
    harness.seed("clean_unlock")
    harness.process("T-UNLOCK")
    harness.process("T-UNLOCK")
    assert harness.mutations("okta.unlock_account") == 1
    assert harness.inspect("accounts.u-alice")["locked"] is False


def test_ledger_refuses_old_key_with_new_payload(harness):
    harness.seed("clean_unlock")
    w = harness.world
    r1 = w.okta_send_reset("helix", "u-alice", "u-alice:2026-09-07")
    assert r1["ok"]
    # Reuse the key with a different fingerprint via a raw ledger call.
    out = w.ledger_call("helix", "okta.send_password_reset", "u-alice:2026-09-07",
                        {"user": "u-DIFFERENT"}, lambda: {"ok": True})
    assert out["ok"] is False and out["error"] == "idempotency_key_conflict"


def test_operation_namespacing_soc_open_and_page(harness):
    harness.seed("account_compromise")
    w = harness.world
    a = w.soc_open_incident("helix", "SEV-2", "x", "T-COMPROMISE", "T-COMPROMISE")
    b = w.soc_page_oncall("helix", "SOC", "T-COMPROMISE", "T-COMPROMISE")
    # Same logical key (ticket id) but different tools -> both act once.
    assert a["ok"] and b["ok"]
    assert w.mutation_count("soc.open_incident") == 1
    assert w.mutation_count("soc.page_oncall") == 1


def test_silent_noop_returns_ok_but_no_effect(harness):
    harness.seed("silent_noop_unlock")
    w = harness.world
    r = w.okta_unlock("helix", "u-alice", "u-alice:epoch")
    assert r["ok"] is True and r.get("noop") is True
    assert w.mutation_count("okta.unlock_account") == 0
    assert w.inspect("accounts.u-alice")["locked"] is True  # never actually unlocked


def test_persistence_across_reopen(harness, tmp_path):
    harness.seed("clean_unlock")
    harness.process("T-UNLOCK")
    # Reopen the same SQLite file as a fresh world; effect + ledger persist.
    from helix.mock import MockWorld

    reopened = MockWorld(harness.db_path)
    assert reopened.mutation_count("okta.unlock_account") == 1
    assert reopened.get_account("u-alice")["locked"] is False


def test_all_21_operations_present():
    from helix.registry import ALL_OPERATIONS

    assert len(ALL_OPERATIONS) == 21
    assert "okta.disable_mfa" in ALL_OPERATIONS
    assert "soc.page_oncall" in ALL_OPERATIONS
