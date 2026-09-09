"""Task 6: postconditions and recovery, verify before success, keep useful
containment on partial failure, honor withdrawal, don't double-act.

The M2 additions at the bottom pin the retry *schedule* (R-59): the delays
the executor actually sleeps, the jitter bound, and the hung-adapter path.
They patch time.sleep so the suite stays fast, and they set the policy on the
executor directly rather than through the environment, because Settings reads
os.environ at import time and a per-test env change would not reach it."""

import threading
import time

import pytest

from helix.executor import RetryPolicy
from helix.models import ExecutionStatus


def test_noop_not_reported_done(harness):
    harness.seed("silent_noop_unlock")
    result = harness.process("T-NOOP")
    assert result["execution_status"] != ExecutionStatus.VERIFIED.value
    assert result["ticket_status"] != "Done"
    assert harness.mutations("okta.unlock_account") == 0


def test_partial_containment_keeps_step_one(harness):
    # revoke_sessions succeeds, force_password_reset fails -> INCOMPLETE, but
    # sessions stay revoked (never rolled back) and the incident is open.
    harness.seed("partial_containment")
    result = harness.process("T-PARTIAL")
    assert result["disposition"] == "ESCALATE_INCIDENT"
    assert result["execution_status"] == ExecutionStatus.INCOMPLETE.value
    assert harness.inspect("accounts.u-victor")["sessions"] == 0  # containment preserved
    assert harness.mutations("okta.force_password_reset") == 0  # step 2 never landed
    incidents = harness.inspect("incidents")
    assert incidents and incidents[0]["ticket_id"] == "T-PARTIAL"


def test_withdrawal_before_dispatch_honored(harness):
    harness.seed("withdrawn_before_dispatch")

    def withdraw():
        t = harness.world.get_ticket("T-WITHDRAW")
        harness.world.put_ticket(t.model_copy(update={"withdrawn": True}))

    harness.before_next_dispatch(withdraw)
    result = harness.process("T-WITHDRAW")
    assert harness.mutations("okta.unlock_account") == 0
    assert result["execution_status"] in (
        ExecutionStatus.WITHDRAWN.value, ExecutionStatus.FAILED.value, ExecutionStatus.BLOCKED.value)


def test_duplicate_unlock_links_not_reacts(harness):
    # T-DUP-A is already in flight with its action fingerprint stamped (seeded).
    # Processing its duplicate T-DUP-B must link, not unlock a second time.
    harness.seed("duplicate_unlock")
    result = harness.process("T-DUP-B")
    assert result["execution_status"] == ExecutionStatus.DUPLICATE_LINKED.value
    assert harness.mutations("okta.unlock_account") == 0  # never acted


def test_verified_unlock_then_replay_no_second_effect(harness):
    harness.seed("clean_unlock")
    harness.process("T-UNLOCK")
    harness.process("T-UNLOCK")  # retry
    assert harness.mutations("okta.unlock_account") == 1


def test_transient_failure_recovered_by_bounded_retry(harness):
    # Step two fails once, then succeeds. The retry re-enters under the SAME
    # logical key, so the ledger guarantees at most one effect, and the
    # containment completes.
    harness.seed("transient_containment")
    result = harness.process("T-TRANSIENT")
    assert result["execution_status"] == ExecutionStatus.VERIFIED.value
    assert harness.mutations("okta.force_password_reset") == 1
    assert harness.inspect("accounts.u-victor")["force_reset"] is True
    retries = [e for e in harness.events() if e.get("phase") == "retry"]
    assert len(retries) == 1


def test_retry_never_mints_a_new_key(harness):
    # Persistent failure exhausts attempts; every attempt used the same key
    # and no effect ever landed.
    harness.seed("partial_containment")
    harness.process("T-PARTIAL")
    keys = {e.get("logical_key") for e in harness.events()
            if e.get("tool") == "okta.force_password_reset" and e.get("logical_key")}
    assert len(keys) == 1  # every retry and the final failure carried the same key
    assert harness.mutations("okta.force_password_reset") == 0


# -- M2 / R-59: the schedule itself, not just "a retry happened" -------------


def _record_sleeps(monkeypatch) -> list[float]:
    """Swap time.sleep for a recorder. The executor calls time.sleep through the
    module, so patching the attribute is enough and the suite never waits."""
    seen: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: seen.append(s))
    return seen


def test_backoff_schedule_is_honoured(harness, monkeypatch):
    # partial_containment keeps failing, so all three attempts run. With base
    # 0.1 and no jitter the executor must sleep 0.1 after attempt one and 0.2
    # after attempt two, and NOT sleep after the last attempt (nothing follows
    # it). Every attempt rides the same logical key.
    sleeps = _record_sleeps(monkeypatch)
    harness.agent.executor.retry = RetryPolicy(base_seconds=0.1)
    harness.seed("partial_containment")
    harness.process("T-PARTIAL")

    assert sleeps == pytest.approx([0.1, 0.2])
    retries = [e for e in harness.events()
               if e.get("phase") == "retry" and e.get("tool") == "okta.force_password_reset"]
    assert len(retries) == 3
    assert len({e["logical_key"] for e in retries}) == 1
    assert harness.mutations("okta.force_password_reset") == 0


def test_backoff_jitter_stays_within_configured_bound(harness, monkeypatch):
    # Jitter is additive and bounded: each sleep lands in [delay, delay + jitter].
    # We assert the bound rather than a seeded value so the test pins the
    # contract, not the random module's internals.
    sleeps = _record_sleeps(monkeypatch)
    harness.agent.executor.retry = RetryPolicy(base_seconds=0.1, jitter_seconds=0.05)
    harness.seed("partial_containment")
    harness.process("T-PARTIAL")

    assert len(sleeps) == 2
    for observed, floor in zip(sleeps, (0.1, 0.2)):
        assert floor <= observed <= floor + 0.05 + 1e-9


def test_zero_base_means_no_sleep_at_all(harness, monkeypatch):
    # The default policy (base 0.0) is what keeps the suite fast; guard it so a
    # future default change is a visible decision, not an accidental slowdown.
    sleeps = _record_sleeps(monkeypatch)
    harness.seed("partial_containment")
    harness.process("T-PARTIAL")
    assert sleeps == []


def test_hung_adapter_times_out_as_failed_under_one_key(harness):
    # An adapter that never returns must not hang the run. With a per-adapter
    # timeout the executor treats the hang as a transient failure: a `retry`
    # event per attempt, all on ONE logical key, then FAILED. It must never
    # mint a new key to "get around" the hang, and nothing may have mutated.
    release = threading.Event()

    def hung_unlock(tenant_id, user_id, logical_key):
        release.wait()  # blocks until the test lets the worker threads go
        return {"ok": False, "error": "released after test"}

    harness.seed("clean_unlock")
    harness.world.okta_unlock = hung_unlock
    harness.agent.executor.retry = RetryPolicy(base_seconds=0.0, adapter_timeout_seconds=0.05)
    try:
        result = harness.process("T-UNLOCK")
    finally:
        release.set()  # let the parked daemon threads exit cleanly

    assert result["execution_status"] == ExecutionStatus.FAILED.value
    assert result["ticket_status"] != "Done"
    retries = [e for e in harness.events()
               if e.get("phase") == "retry" and e.get("tool") == "okta.unlock_account"]
    assert len(retries) == 3
    assert all("timed out" in (e.get("error") or "") for e in retries)
    keys = {e.get("logical_key") for e in harness.events()
            if e.get("tool") == "okta.unlock_account" and e.get("logical_key")}
    assert len(keys) == 1
    assert harness.mutations("okta.unlock_account") == 0
