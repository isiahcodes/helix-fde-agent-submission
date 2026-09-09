"""Durable worker lifecycle.

The worker is the re-processing loop (D-03): there are no interrupts or
checkpointers. New tickets, meaningful requester replies, approval updates and
explicit retries all do the same thing: re-enqueue the ticket and run the full
guarded pipeline from CURRENT state. A pending approval is just durable data;
when it flips APPROVED, the next pass reads it live inside dispatch and executes
exactly once (the approval id is the idempotency key, so a third pass is a
no-op).

Two lifecycle hazards this guards against:
  - the agent's own comments must not wake the worker forever (comments are
    authored 'agent' and skipped when scanning for work).
  - resume must not reseed or trust a stale in-memory approval status, every
    pass re-reads the world from SQLite.
"""

from __future__ import annotations

from helix.mock import MockWorld
from helix.models import TicketStatus


class Worker:
    def __init__(self, agent):
        self.agent = agent
        self.world: MockWorld = agent.world

    def process_once(self, ticket_id: str) -> dict:
        return self.agent.process(ticket_id)

    def pending_tickets(self) -> list[str]:
        """Tickets that still need a pass: open / in-progress / pending-approval,
        excluding terminal states. Agent-authored comments never create work."""
        out: list[str] = []
        for row in self.world.db.execute("SELECT ticket_id, doc FROM tickets").fetchall():
            from helix.models import Ticket

            t = Ticket.model_validate_json(row["doc"])
            if t.status.value not in (TicketStatus.DONE.value, TicketStatus.WITHDRAWN.value):
                out.append(t.ticket_id)
        return out

    def run_once(self) -> list[dict]:
        """One sweep over all non-terminal tickets."""
        return [self.agent.process(tid) for tid in self.pending_tickets()]
