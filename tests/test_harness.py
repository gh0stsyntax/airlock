import json
import time

import pytest

from airlock import AgentPolicy, AuditLog, Harness, Policy, Registry


@pytest.fixture
def setup(tmp_path):
    reg = Registry()
    sent = []

    @reg.tool(risk="read")
    def read_note(note_id: int):
        return f"note {note_id}"

    @reg.tool(risk="write")
    def write_note(note_id: int, text: str):
        return "saved"

    @reg.tool(risk="external")
    def send_mail(to: str, body: str, api_key: str = ""):
        sent.append(to)
        return "sent"

    @reg.tool(risk="destructive")
    def delete_all():
        return "deleted"

    @reg.tool(risk="read")
    def slow():
        time.sleep(0.5)
        return "late"

    @reg.tool(risk="read")
    def boom():
        raise RuntimeError("disk on fire")

    policy = Policy({
        "reader": AgentPolicy(allow=("read_*", "slow", "boom"), max_risk="read", max_calls=3, timeout_s=0.1),
        "writer": AgentPolicy(allow=("read_*", "write_*", "send_*", "delete_*"), deny=("delete_*",), max_risk="external"),
        "admin": AgentPolicy(allow=("*",), max_risk="destructive"),
    })
    log = tmp_path / "audit.jsonl"
    return reg, policy, log, sent


def make(setup, approver=None):
    reg, policy, log, sent = setup
    return Harness(reg, policy, AuditLog(log), approver), log, sent


def test_allowed_read_call(setup):
    h, _, _ = make(setup)
    assert h.call("reader", "read_note", {"note_id": 1}) == {"status": "ok", "result": "note 1"}


def test_unknown_agent_and_unknown_tool_are_denied(setup):
    h, _, _ = make(setup)
    assert h.call("ghost", "read_note", {"note_id": 1})["status"] == "denied"
    r = h.call("reader", "nope")
    assert r["status"] == "denied" and "unknown tool" in r["message"]


def test_allowlist_blocks_tools_outside_pattern(setup):
    h, _, _ = make(setup)
    r = h.call("reader", "write_note", {"note_id": 1, "text": "x"})
    assert r["status"] == "denied" and "allowlist" in r["message"]


def test_deny_wins_over_allow(setup):
    h, _, _ = make(setup)
    r = h.call("writer", "delete_all", confirm=True)
    assert r["status"] == "denied" and "denied" in r["message"]


def test_risk_ceiling(setup):
    reg, policy, log, _ = setup
    p = Policy({"a": AgentPolicy(allow=("*",), max_risk="read")})
    h = Harness(reg, p, AuditLog(log))
    r = h.call("a", "write_note", {"note_id": 1, "text": "x"})
    assert r["status"] == "denied" and "ceiling" in r["message"]


def test_external_is_dry_run_by_default_and_has_no_effect(setup):
    h, _, sent = make(setup, approver=lambda *a: True)
    r = h.call("writer", "send_mail", {"to": "a@example.com", "body": "hi"})
    assert r["status"] == "dry_run" and sent == []


def test_external_with_confirm_and_approver_runs(setup):
    h, _, sent = make(setup, approver=lambda agent, tool, args: args["to"].endswith("@example.com"))
    assert h.call("writer", "send_mail", {"to": "a@example.com", "body": "hi"}, confirm=True)["status"] == "ok"
    assert sent == ["a@example.com"]


def test_approver_can_refuse(setup):
    h, _, sent = make(setup, approver=lambda *a: False)
    r = h.call("writer", "send_mail", {"to": "evil@example.org", "body": "hi"}, confirm=True)
    assert r["status"] == "denied" and sent == []


def test_confirm_without_approver_is_denied(setup):
    """The agent cannot approve itself: confirm=True alone is never enough."""
    h, _, sent = make(setup, approver=None)
    r = h.call("writer", "send_mail", {"to": "a@example.com", "body": "hi"}, confirm=True)
    assert r["status"] == "denied" and "no approver" in r["message"] and sent == []


def test_budget_counts_only_executed_calls(setup):
    h, _, _ = make(setup)
    for i in range(3):
        assert h.call("reader", "read_note", {"note_id": i})["status"] == "ok"
    r = h.call("reader", "read_note", {"note_id": 9})
    assert r["status"] == "denied" and "budget" in r["message"]
    h.reset_budget("reader")
    assert h.call("reader", "read_note", {"note_id": 9})["status"] == "ok"
    # denied/dry-run attempts do not eat budget
    h2, _, _ = make(setup)
    for _ in range(10):
        h2.call("reader", "write_note", {"note_id": 1, "text": "x"})
    assert h2.call("reader", "read_note", {"note_id": 1})["status"] == "ok"


def test_timeout_and_error_are_reported_not_raised(setup):
    h, _, _ = make(setup)
    assert h.call("reader", "slow")["status"] == "timeout"
    r = h.call("reader", "boom")
    assert r["status"] == "error" and "disk on fire" in r["message"] and "Traceback" not in r["message"]


def test_visible_tools_hide_what_the_agent_may_not_use(setup):
    h, _, _ = make(setup)
    assert h.visible_tools("reader") == ["boom", "read_note", "slow"]
    assert "delete_all" not in h.visible_tools("writer") and "send_mail" in h.visible_tools("writer")
    assert h.visible_tools("ghost") == []


def test_every_decision_is_audited_and_secrets_are_redacted(setup):
    h, log, _ = make(setup, approver=lambda *a: True)
    h.call("writer", "send_mail", {"to": "a@example.com", "body": "token sk-abcdefghijklmnopqrstuv", "api_key": "super-secret"}, confirm=True)
    h.call("reader", "write_note", {"note_id": 1, "text": "x"})
    rows = [json.loads(json.loads(l)["body"]) for l in log.read_text(encoding="utf-8").splitlines()]
    assert [r["event"] for r in rows] == ["ok", "denied"]
    text = log.read_text(encoding="utf-8")
    assert "super-secret" not in text and "sk-abcdefghijklmnopqrstuv" not in text and "***" in text
    ok, bad = AuditLog.verify(log)
    assert ok and bad is None


def test_audit_chain_detects_edit_and_deletion(setup):
    h, log, _ = make(setup)
    for i in range(4):
        h.call("reader", "read_note", {"note_id": i}) if i < 3 else h.call("reader", "read_note", {"note_id": i})
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4 and AuditLog.verify(log) == (True, None)
    edited = lines[:]
    rec = json.loads(edited[1]); rec["body"] = rec["body"].replace('"ok"', '"denied"'); edited[1] = json.dumps(rec)
    log.write_text("\n".join(edited) + "\n", encoding="utf-8")
    assert AuditLog.verify(log) == (False, 1)
    log.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")        # a record removed
    assert AuditLog.verify(log) == (False, 1)


def test_audit_continues_chain_after_restart(setup):
    reg, policy, log, _ = setup
    Harness(reg, policy, AuditLog(log)).call("reader", "read_note", {"note_id": 1})
    Harness(reg, policy, AuditLog(log)).call("reader", "read_note", {"note_id": 2})     # new process, same file
    assert AuditLog.verify(log) == (True, None)


def test_invalid_configuration_fails_loudly():
    reg = Registry()
    with pytest.raises(ValueError):
        reg.tool(risk="harmless")
    with pytest.raises(ValueError):
        Policy({"a": AgentPolicy(max_risk="root")})
    reg.tool(name="x")(lambda: 1)
    with pytest.raises(ValueError):
        reg.tool(name="x")(lambda: 2)
