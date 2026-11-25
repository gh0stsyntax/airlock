"""The three-role example (examples/team.py): isolation between roles, fail-closed pipeline, approval, audit."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from team import build_world, run_pipeline  # noqa: E402

from airlock import AuditLog  # noqa: E402

approve_seven = lambda agent, tool, args: args.get("ticket_id") == 7   # noqa: E731


@pytest.fixture
def log(tmp_path):
    return tmp_path / "audit.jsonl"


def test_each_role_sees_only_its_tools(log):
    h, _ = build_world(log)
    assert h.visible_tools("researcher") == ["read_ticket", "search_docs"]
    assert h.visible_tools("builder") == ["read_ticket", "write_note", "write_patch"]
    assert h.visible_tools("reviewer") == ["read_ticket", "release_fix", "run_tests"]
    seen = {tool for role in ("researcher", "builder", "reviewer") for tool in h.visible_tools(role)}
    assert "purge_tickets" not in seen                                  # nobody is even told about the destructive tool


def test_happy_path_releases_exactly_once_after_dry_run_and_approval(log):
    h, state = build_world(log, approver=approve_seven)
    result = run_pipeline(h, 7)
    assert result["outcome"] == "released"
    assert [(s["role"], s["tool"], s["status"]) for s in result["steps"]] == [
        ("researcher", "read_ticket", "ok"), ("researcher", "search_docs", "ok"), ("builder", "write_patch", "ok"),
        ("reviewer", "run_tests", "ok"), ("reviewer", "release_fix", "dry_run"), ("reviewer", "release_fix", "ok")]
    assert state["released"] == [7] and len(state["patches"]) == 1


def test_failing_tests_stop_the_pipeline_before_any_release(log):
    h, state = build_world(log, approver=approve_seven, tests_pass=False)
    result = run_pipeline(h, 7)
    assert result["outcome"] == "halted: reviewer: tests failed"
    assert state["released"] == []
    assert all(s["tool"] != "release_fix" for s in result["steps"])         # not even a dry run was attempted


def test_refused_approval_means_no_release(log):
    h, state = build_world(log, approver=lambda *a: False)
    result = run_pipeline(h, 7)
    assert result["outcome"].startswith("halted: reviewer/release_fix denied")
    assert state["released"] == []


def test_no_approver_means_no_external_effect_at_all(log):
    h, state = build_world(log, approver=None)
    assert run_pipeline(h, 7)["outcome"].startswith("halted")
    assert state["released"] == []


def test_roles_cannot_use_each_others_tools(log):
    h, state = build_world(log, approver=lambda *a: True)                   # even a permissive approver does not widen a role
    assert h.call("builder", "release_fix", {"ticket_id": 7}, confirm=True)["status"] == "denied"
    assert h.call("builder", "purge_tickets", confirm=True)["status"] == "denied"
    assert h.call("researcher", "write_patch", {"ticket_id": 7, "patch": "x"})["status"] == "denied"
    assert h.call("reviewer", "write_note", {"ticket_id": 7, "text": "x"})["status"] == "denied"
    assert h.call("reviewer", "purge_tickets", confirm=True)["status"] == "denied"
    assert state == {"patches": [], "notes": [], "released": [], "purged": []}


def test_a_role_cannot_exceed_its_call_budget(log):
    h, _ = build_world(log)
    assert [h.call("researcher", "read_ticket", {"ticket_id": i})["status"] for i in range(6)] == ["ok"] * 6
    over = h.call("researcher", "read_ticket", {"ticket_id": 99})
    assert over["status"] == "denied" and "budget" in over["message"]
    assert h.call("builder", "read_ticket", {"ticket_id": 1})["status"] == "ok"      # budgets are per role


def test_hanging_dependency_times_out_and_later_roles_never_run(log):
    h, state = build_world(log, approver=approve_seven, search_delay_s=1.0, search_timeout_s=0.2)
    result = run_pipeline(h, 7)
    assert result["outcome"] == "halted: researcher/search_docs timeout"
    assert [s["role"] for s in result["steps"]] == ["researcher", "researcher"]
    assert state["patches"] == [] and state["released"] == []


def test_audit_log_covers_every_role_and_detects_tampering(log):
    h, _ = build_world(log, approver=approve_seven)
    run_pipeline(h, 7)
    h.call("builder", "release_fix", {"ticket_id": 7}, confirm=True)                # denied, but must be on record
    rows = [json.loads(json.loads(line)["body"]) for line in log.read_text(encoding="utf-8").splitlines()]
    assert {r["agent"] for r in rows} == {"researcher", "builder", "reviewer"}
    assert any(r["event"] == "denied" and r["agent"] == "builder" and r["tool"] == "release_fix" for r in rows)
    assert any(r["event"] == "dry_run" and r["agent"] == "reviewer" for r in rows)
    assert AuditLog.verify(log) == (True, None)
    lines = log.read_text(encoding="utf-8").splitlines()
    assert "read_ticket" in lines[0]                                                # first record is the researcher's read
    lines[0] = lines[0].replace("read_ticket", "purge_tickets")                     # rewrite history
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert AuditLog.verify(log) == (False, 0)


def test_a_rejected_preview_stops_the_run_before_the_real_release_is_even_tried(log):
    """The release step is only attempted after a successful dry run. Reviewer budget is 4: use 3, run_tests takes
    the 4th, so the preview is denied for budget reasons and the pipeline must stop right there."""
    h, state = build_world(log, approver=lambda *a: True)
    for i in range(3):
        assert h.call("reviewer", "read_ticket", {"ticket_id": i})["status"] == "ok"
    result = run_pipeline(h, 7)
    assert result["outcome"] == "halted: reviewer/release_fix preview was denied"
    assert [s["status"] for s in result["steps"]][-2:] == ["ok", "denied"]           # run_tests ok, preview denied, nothing after
    assert state["released"] == []
