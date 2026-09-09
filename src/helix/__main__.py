"""Helix agent CLI.

Commands (provisioning.md, implementation plan Task 8):
  seed <scenario>              reset the world to a named scenario
  process <ticket_id>          run one ticket, print the decision
  worker --once                one sweep over all non-terminal tickets
  mock-approve <id> <status>   out-of-band approver decision (demo/human only)
  inspect <path>               read mock state (e.g. accounts.u-alice)
  evaluate [--live]            run the full gold set, write reports/

Deterministic evaluate uses the FakePlanner; --live requires HELIX_ANTHROPIC_API_KEY
+ HELIX_MODEL and runs the real model. Without them, live is refused (BLOCKED),
never silently downgraded to a fake pass.

State lives in a single SQLite file (default ./helix-world.sqlite3) so process
and worker share it across invocations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from helix.audit import AuditLog
from helix.config import load_settings
from helix.evaluation import score_case, summarize
from helix.mock import MockWorld, load_scenario
from helix.planner import FakePlanner
from helix.workflow import Agent

DEFAULT_DB = Path("helix-world.sqlite3")
REPORTS = Path("reports")


def _agent(db: Path, audit_dir: Path, planner=None) -> Agent:
    world = MockWorld(db)
    audit = AuditLog(audit_dir)
    return Agent(world, planner or FakePlanner(), audit)


def cmd_seed(args) -> int:
    world = MockWorld(args.db)
    load_scenario(world, args.scenario)
    print(json.dumps({"seeded": args.scenario, "db": str(args.db)}))
    return 0


def cmd_process(args) -> int:
    agent = _agent(args.db, args.audit)
    print(json.dumps(agent.process(args.ticket_id), indent=2))
    return 0


def cmd_worker(args) -> int:
    from helix.worker import Worker

    agent = _agent(args.db, args.audit)
    results = Worker(agent).run_once()
    print(json.dumps(results, indent=2))
    return 0


def cmd_mock_approve(args) -> int:
    world = MockWorld(args.db)
    world.admin_set_approval(args.approval_id, args.status)
    print(json.dumps({"approval": args.approval_id, "status": args.status}))
    return 0


def cmd_inspect(args) -> int:
    world = MockWorld(args.db)
    print(json.dumps(world.inspect(args.path), indent=2, default=str))
    return 0


def cmd_evaluate(args) -> int:
    """Process every gold case in an ISOLATED world, capture the real event
    stream + before/after state, and score independently. Exit nonzero on any
    unsafe action, secret leak, false success or required-case miss."""

    settings = load_settings()
    planner = None
    mode = "deterministic"
    if args.live:
        if not settings.live_ready:
            print(json.dumps({
                "live_evaluation": "BLOCKED",
                "reason": "HELIX_ANTHROPIC_API_KEY and HELIX_MODEL required; not faking a pass",
            }))
            return 2
        from helix.planner import LivePlanner

        planner = LivePlanner(settings.api_key, settings.model, timeout=settings.timeout,
                              base_url=settings.anthropic_base_url or None,
                              workspace_id=settings.anthropic_workspace_id or None)
        mode = "live"

    gold_path = Path(args.gold)
    cases = [json.loads(line) for line in gold_path.read_text().splitlines() if line.strip()]
    REPORTS.mkdir(exist_ok=True)
    results = []
    for case in cases:
        # Fresh world per case: isolation so one case cannot leak state to the
        # next, and the before/after snapshots are meaningful.
        tmp_db = REPORTS / f".eval-{case['scenario']}-{case['ticket_id']}.sqlite3"
        if tmp_db.exists():
            tmp_db.unlink()
        world = MockWorld(tmp_db)
        load_scenario(world, case["scenario"])
        audit = AuditLog(REPORTS / f".eval-audit-{case['ticket_id']}")
        agent = Agent(world, planner or FakePlanner(), audit)

        before = {"effects": {t: world.mutation_count(t) for t in _EFFECT_TOOLS}}
        decision = agent.process(case["ticket_id"])
        after = {"effects": {t: world.mutation_count(t) for t in _EFFECT_TOOLS}}
        outputs = audit.dump_text() + "\n" + world.generated_text()

        case["_predicted_disposition"] = decision.get("disposition")
        case["_execution_status"] = decision.get("execution_status")
        case["_ticket_status"] = decision.get("ticket_status")
        case["_citations"] = decision.get("citations")
        case["_reason_code"] = decision.get("reason_code")
        results.append(score_case(case, before, after, audit.events(), outputs))
        tmp_db.unlink(missing_ok=True)

    summary = summarize(results)
    summary["mode"] = mode
    summary["model"] = settings.model if args.live else "fake"
    # Which host answered matters when the same model name can be served by
    # api.anthropic.com or a local Ollama; the key never goes anywhere near this.
    summary["endpoint"] = (settings.anthropic_base_url or "https://api.anthropic.com") if args.live else "none"
    summary["gold"] = str(gold_path)
    summary["gold_set"] = gold_path.stem

    # One report per (mode, gold set) so gold / adversarial / heldout can
    # coexist, the presentation build reads all three side by side.
    tag = f"{mode}-{gold_path.stem}"
    _write_csv(results, REPORTS / f"eval-{tag}.csv")
    (REPORTS / f"eval-{tag}.json").write_text(json.dumps({"summary": summary, "cases": results}, indent=2))
    (REPORTS / f"decisions-{tag}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in results) + "\n"
    )

    print(json.dumps(summary, indent=2))
    # Nonzero exit if anything unsafe or any required case failed.
    return 0 if summary["all_pass"] else 1


_EFFECT_TOOLS = [
    "okta.unlock_account", "okta.send_password_reset", "okta.revoke_sessions",
    "okta.force_password_reset", "okta.disable_mfa", "servicenow.create_request",
    "endpoint.grant_admin", "assetmgmt.create_case", "iam.create_approval",
    "iam.grant_access", "soc.open_incident", "soc.page_oncall",
]


def _write_csv(results: list[dict], path: Path) -> None:
    import csv

    cols = ["ticket_id", "expected_dispositions", "predicted_disposition", "execution_status",
            "ticket_status", "tools_dispatched", "citation", "reason", "unsafe_action_count",
            "unsafe_effect_count", "false_success_count", "secret_leak_count",
            "missed_action_count", "pass"]
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in results:
            w.writerow([
                r["ticket_id"], "|".join(r["expected_dispositions"]), r["predicted_disposition"],
                r["execution_status"], r["ticket_status"], "|".join(r["tools_dispatched"]),
                "|".join(r["citation"] or []), r["reason"], r["unsafe_action_count"],
                r["unsafe_effect_count"], r["false_success_count"], r["secret_leak_count"],
                r["missed_action_count"], r["pass"],
            ])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="helix", description="Helix IT Service Desk agent")
    p.add_argument("--db", type=Path, default=DEFAULT_DB)
    p.add_argument("--audit", type=Path, default=Path("audit"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed"); s.add_argument("scenario"); s.set_defaults(fn=cmd_seed)
    s = sub.add_parser("process"); s.add_argument("ticket_id"); s.set_defaults(fn=cmd_process)
    s = sub.add_parser("worker"); s.add_argument("--once", action="store_true"); s.set_defaults(fn=cmd_worker)
    s = sub.add_parser("mock-approve"); s.add_argument("approval_id"); s.add_argument("status"); s.set_defaults(fn=cmd_mock_approve)
    s = sub.add_parser("inspect"); s.add_argument("path"); s.set_defaults(fn=cmd_inspect)
    s = sub.add_parser("evaluate")
    s.add_argument("--live", action="store_true")
    s.add_argument("--gold", default="fixtures/gold.jsonl")
    s.set_defaults(fn=cmd_evaluate)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
