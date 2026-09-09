"""Task 8: worker and durable lifecycle, the approval round-trip executes
exactly once, and replays never double-act."""

from helix.models import ExecutionStatus


def test_approval_event_rechecks_and_executes_once(harness):
    harness.seed("pending_access")
    first = harness.process("T-ACCESS")
    assert harness.mutations("iam.grant_access") == 0
    assert first["approval_id"]
    # Out-of-band approval, then re-process from current state.
    harness.set_approval(first["approval_id"], "APPROVED")
    second = harness.process("T-ACCESS")
    assert second["execution_status"] == ExecutionStatus.VERIFIED.value
    # A third pass must not grant again (approval id is the idempotency key).
    harness.process("T-ACCESS")
    assert harness.mutations("iam.grant_access") == 1


def test_revocation_after_planning_blocks_execution(harness):
    harness.seed("pending_access")
    first = harness.process("T-ACCESS")
    harness.set_approval(first["approval_id"], "APPROVED")
    # Revoke right before the execution pass dispatches.
    def revoke():
        harness.set_approval(first["approval_id"], "REVOKED")

    harness.before_next_dispatch(revoke)
    second = harness.process("T-ACCESS")
    assert second["execution_status"] != ExecutionStatus.VERIFIED.value
    assert harness.mutations("iam.grant_access") == 0


def test_agent_comments_do_not_create_infinite_work(harness):
    from helix.worker import Worker

    harness.seed("answer_vpn")
    w = Worker(harness.agent)
    w.run_once()  # T-VPN answered and closed
    # Second sweep: the answered ticket is terminal, so it is not re-picked.
    assert "T-VPN" not in w.pending_tickets()


def _comment_count(harness, ticket_id: str) -> int:
    row = harness.world.db.execute(
        "SELECT COUNT(*) c FROM comments WHERE ticket_id=?", (ticket_id,)
    ).fetchone()
    return row["c"]


def _attempts(harness, tool: str, ticket_id: str) -> int:
    # Dispatch attempts, not effects: jira.add_label is a no-op once the label
    # exists, so mutation_count() alone could not tell a skipped call from a
    # re-issued one that happened to change nothing.
    # .get: the audit stream also carries model_input notes with no tool key.
    return sum(
        1 for e in harness.events()
        if e.get("tool") == tool and e.get("phase") == "attempted" and e.get("ticket_id") == ticket_id
    )


def test_second_sweep_emits_no_duplicate_comments(harness):
    """D-07 / F-16: a deferred ticket stays non-terminal, so the worker picks it
    up again on the next sweep. Re-running the pipeline is by design (D-03);
    re-posting the same comment and label to JIRA is not."""
    from helix.worker import Worker

    harness.seed("hr_defer")
    w = Worker(harness.agent)
    w.run_once()
    assert _comment_count(harness, "T-HR") == 1
    assert _attempts(harness, "jira.add_label", "T-HR") == 1
    # Still open work, the durability model WANTS it re-picked.
    assert "T-HR" in w.pending_tickets()

    w.run_once()
    assert _comment_count(harness, "T-HR") == 1
    assert _attempts(harness, "jira.add_label", "T-HR") == 1


def test_requester_edit_reopens_the_comment(harness):
    """The dedup key includes the ticket revision on purpose: when the requester
    changes the ticket, the same wording is a fresh answer to fresh content and
    must land again. Only requester-side changes move the revision, the
    agent's own label/transition bookkeeping does not, or every sweep would
    mint a new revision and D-07 could never fire."""
    from helix.worker import Worker

    harness.seed("hr_defer")
    w = Worker(harness.agent)
    w.run_once()
    after_first = harness.world.get_ticket("T-HR")
    assert after_first.revision == 1, "agent bookkeeping must not bump revision"

    edited = after_first.model_copy(update={"revision": after_first.revision + 1})
    harness.world.put_ticket(edited)
    w.run_once()
    assert _comment_count(harness, "T-HR") == 2
