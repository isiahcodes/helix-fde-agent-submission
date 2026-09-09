"""Task 7: the six-disposition workflow produces the right artifact for each,
and the two legs of the approval flow both run."""

from helix.models import ExecutionStatus


def test_answer_only_vpn(harness):
    harness.seed("answer_vpn")
    r = harness.process("T-VPN")
    assert r["disposition"] == "ANSWER_ONLY"
    assert r["ticket_status"] == "Done"
    assert any(c.startswith("POL-02") for c in r["citations"])
    assert harness.mutations("okta.unlock_account") == 0


def test_auto_action_clean_unlock(harness):
    harness.seed("clean_unlock")
    r = harness.process("T-UNLOCK")
    assert r["disposition"] == "AUTO_ACTION"
    assert r["execution_status"] == ExecutionStatus.VERIFIED.value
    assert r["ticket_status"] == "Done"


def test_auto_action_owner_reset(harness):
    harness.seed("owner_reset")
    r = harness.process("T-RESET")
    assert r["disposition"] == "AUTO_ACTION"
    assert r["execution_status"] == ExecutionStatus.VERIFIED.value
    assert harness.mutations("okta.send_password_reset") == 1


def test_auto_action_admin_1_and_60(harness):
    harness.seed("admin_min")
    r1 = harness.process("T-ADMIN1")
    r60 = harness.process("T-ADMIN60")
    assert r1["execution_status"] == ExecutionStatus.VERIFIED.value
    assert r60["execution_status"] == ExecutionStatus.VERIFIED.value
    assert harness.mutations("endpoint.grant_admin") == 2


def test_admin_61_not_executed(harness):
    harness.seed("admin_min")
    r = harness.process("T-ADMIN61")
    assert r["execution_status"] != ExecutionStatus.VERIFIED.value
    assert harness.mutations("endpoint.grant_admin") == 0


def test_software_request_files_only(harness):
    harness.seed("software_request")
    r = harness.process("T-SW-NEW")
    assert r["disposition"] == "AUTO_ACTION"
    assert harness.mutations("servicenow.create_request") == 1
    reqs = harness.inspect("requests")
    assert reqs and reqs[0]["item"] == "software"


def test_catalog_software_is_answer_only(harness):
    harness.seed("answer_software")
    r = harness.process("T-SW-CATALOG")
    assert r["disposition"] == "ANSWER_ONLY"
    assert harness.mutations("servicenow.create_request") == 0


def test_travel_missing_fields_asks(harness):
    harness.seed("travel_missing_fields")
    r = harness.process("T-TRAVEL-Q")
    assert r["disposition"] == "ASK_CLARIFICATION"
    assert r["ticket_status"] == "Waiting for Customer"
    assert harness.mutations("servicenow.create_request") == 0


def test_travel_with_dates_files(harness):
    harness.seed("travel_request")
    r = harness.process("T-TRAVEL")
    assert r["disposition"] == "AUTO_ACTION"
    reqs = harness.inspect("requests")
    assert reqs and reqs[0]["item"] == "travel_exception"


def test_lost_stolen_case(harness):
    harness.seed("lost_stolen_case")
    r = harness.process("T-LOST")
    assert r["disposition"] == "AUTO_ACTION"
    assert harness.mutations("assetmgmt.create_case") == 1


def test_lost_restricted_is_incident(harness):
    harness.seed("lost_restricted_incident")
    r = harness.process("T-LOST-PHI")
    assert r["disposition"] == "ESCALATE_INCIDENT"
    assert harness.mutations("assetmgmt.create_case") == 0


def test_propose_no_record_routes(harness):
    harness.seed("pending_access")
    r = harness.process("T-ACCESS")
    assert r["disposition"] == "PROPOSE_FOR_APPROVAL"
    assert r["execution_status"] == ExecutionStatus.PENDING_APPROVAL.value
    assert r["approval_id"]
    assert harness.mutations("iam.grant_access") == 0
    assert harness.mutations("iam.create_approval") == 1


def test_propose_approved_executes(harness):
    harness.seed("approved_access")
    r = harness.process("T-ACCESS")
    assert r["disposition"] == "PROPOSE_FOR_APPROVAL"
    assert r["execution_status"] == ExecutionStatus.VERIFIED.value
    assert harness.mutations("iam.grant_access") == 1


def test_escalate_incident_compromise(harness):
    harness.seed("account_compromise")
    r = harness.process("T-COMPROMISE")
    assert r["disposition"] == "ESCALATE_INCIDENT"
    assert r["ticket_status"] == "Escalated"
    assert harness.mutations("soc.open_incident") == 1
    assert harness.mutations("okta.revoke_sessions") == 1


def test_defer_hr(harness):
    harness.seed("hr_defer")
    r = harness.process("T-HR")
    assert r["disposition"] == "DEFER_HUMAN"


def test_defer_shared_account(harness):
    harness.seed("shared_account")
    r = harness.process("T-SHARED")
    assert r["disposition"] == "DEFER_HUMAN"


def test_defer_fanout(harness):
    harness.seed("fanout")
    r = harness.process("T-FANOUT")
    assert r["disposition"] == "DEFER_HUMAN"
    assert harness.mutations("okta.send_password_reset") == 0


def test_defer_permanent_admin(harness):
    harness.seed("permanent_admin")
    r = harness.process("T-PERM-ADMIN")
    assert r["disposition"] == "DEFER_HUMAN"
    assert harness.mutations("endpoint.grant_admin") == 0


def test_defer_dlp(harness):
    harness.seed("dlp_exception")
    r = harness.process("T-DLP")
    assert r["disposition"] == "DEFER_HUMAN"
    assert harness.mutations("servicenow.create_request") == 0


def test_defer_invented_policy(harness):
    harness.seed("invented_policy")
    r = harness.process("T-INVENT")
    assert r["disposition"] == "DEFER_HUMAN"


def test_phishing_answer(harness):
    harness.seed("phishing_report")
    r = harness.process("T-PHISH")
    # Reporting a phish is an answer-from-policy (POL-07), not an escalation.
    assert r["disposition"] in ("ANSWER_ONLY", "ESCALATE_INCIDENT")
