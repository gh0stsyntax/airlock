"""Three agents, one harness: researcher -> builder -> reviewer.

Each role gets only the tools its job needs (least privilege), its own call budget and timeout, and the only step
with an outside effect (`release_fix`) needs an approval. The pipeline fails closed: any step that is not `ok`
halts the run, so a later role never works on top of a failed earlier one. Roles hand over data, not tools.

Run it:  python examples/team.py
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from airlock import AgentPolicy, AuditLog, Harness, Policy, Registry


def build_world(audit_path: str | Path, approver: Optional[Callable] = None, *, tests_pass: bool = True,
                search_delay_s: float = 0.0, search_timeout_s: float = 5.0) -> tuple[Harness, Dict[str, list]]:
    """A tiny ticket system. `state` records every effect so tests can assert what really happened."""
    reg = Registry()
    state: Dict[str, list] = {"patches": [], "notes": [], "released": [], "purged": []}

    @reg.tool(risk="read")
    def read_ticket(ticket_id: int):
        return {"id": ticket_id, "title": "Login fails after password reset"}

    @reg.tool(risk="read")
    def search_docs(query: str):
        time.sleep(search_delay_s)                                    # lets tests simulate a hanging dependency
        return ["KB-12: reset tokens expire after 15 minutes"]

    @reg.tool(risk="write")
    def write_patch(ticket_id: int, patch: str):
        state["patches"].append((ticket_id, patch))
        return {"patch_id": len(state["patches"])}

    @reg.tool(risk="write")
    def write_note(ticket_id: int, text: str):
        state["notes"].append((ticket_id, text))
        return "saved"

    @reg.tool(risk="read")
    def run_tests(patch_id: int):
        return {"patch_id": patch_id, "passed": tests_pass}

    @reg.tool(risk="external")
    def release_fix(ticket_id: int):
        state["released"].append(ticket_id)
        return "released"

    @reg.tool(risk="destructive")
    def purge_tickets():
        state["purged"].append("all")
        return "gone"

    policy = Policy({
        "researcher": AgentPolicy(allow=("read_*", "search_*"), max_risk="read", max_calls=6, timeout_s=search_timeout_s),
        "builder": AgentPolicy(allow=("read_*", "write_patch", "write_note"), max_risk="write", max_calls=6, timeout_s=5),
        "reviewer": AgentPolicy(allow=("read_*", "run_tests", "release_fix"), max_risk="external", max_calls=4, timeout_s=5),
    })
    return Harness(reg, policy, AuditLog(audit_path), approver=approver), state


def run_pipeline(h: Harness, ticket_id: int) -> Dict[str, Any]:
    """Returns {"outcome": "released" | "halted: <why>", "steps": [{"role", "tool", "status"}, ...]}."""
    steps: list[dict] = []

    def step(role: str, tool: str, args: dict, confirm: bool = False) -> Dict[str, Any]:
        r = h.call(role, tool, args, confirm=confirm)
        steps.append({"role": role, "tool": tool, "status": r["status"]})
        return r

    def halted(why: str) -> Dict[str, Any]:
        return {"outcome": f"halted: {why}", "steps": steps}

    ticket = step("researcher", "read_ticket", {"ticket_id": ticket_id})
    if ticket["status"] != "ok":
        return halted(f"researcher/read_ticket {ticket['status']}")
    docs = step("researcher", "search_docs", {"query": ticket["result"]["title"]})
    if docs["status"] != "ok":
        return halted(f"researcher/search_docs {docs['status']}")

    patch = step("builder", "write_patch", {"ticket_id": ticket_id, "patch": f"fix based on {docs['result'][0]}"})
    if patch["status"] != "ok":
        return halted(f"builder/write_patch {patch['status']}")

    tests = step("reviewer", "run_tests", {"patch_id": patch["result"]["patch_id"]})
    if tests["status"] != "ok" or not tests["result"]["passed"]:
        return halted("reviewer: tests failed")
    preview = step("reviewer", "release_fix", {"ticket_id": ticket_id})                 # no confirm -> dry run, nothing happens
    if preview["status"] != "dry_run":
        return halted(f"reviewer/release_fix preview was {preview['status']}")
    release = step("reviewer", "release_fix", {"ticket_id": ticket_id}, confirm=True)  # the approver decides
    if release["status"] != "ok":
        return halted(f"reviewer/release_fix {release['status']}")
    return {"outcome": "released", "steps": steps}


if __name__ == "__main__":
    log = Path(tempfile.mkdtemp()) / "team-audit.jsonl"
    h, state = build_world(log, approver=lambda agent, tool, args: args.get("ticket_id") == 7)
    for role in ("researcher", "builder", "reviewer"):
        print(f"{role:11} sees: {h.visible_tools(role)}")
    result = run_pipeline(h, 7)
    for s in result["steps"]:
        print(f"  {s['role']:11} {s['tool']:13} {s['status']}")
    print("outcome:", result["outcome"], "| released:", state["released"])
    print("builder tries to release on its own:", h.call("builder", "release_fix", {"ticket_id": 7}, confirm=True)["status"])
    ok, _ = AuditLog.verify(log)
    print(f"audit records: {len(log.read_text(encoding='utf-8').splitlines())}, chain intact: {ok}")
    sys.exit(0 if ok and result["outcome"] == "released" else 1)
