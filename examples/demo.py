"""Five things an agent loop will try sooner or later – and what the harness does about each."""
import sys
import tempfile
from pathlib import Path

from airlock import AgentPolicy, AuditLog, Harness, Policy, Registry

reg = Registry()
outbox: list = []


@reg.tool(risk="read")
def read_ticket(ticket_id: int):
    return {"id": ticket_id, "title": "Login fails", "customer": "Example Clinic"}


@reg.tool(risk="write")
def write_note(ticket_id: int, text: str):
    return "note saved"


@reg.tool(risk="external")
def send_mail(to: str, body: str):
    outbox.append(to)
    return "mail sent"


@reg.tool(risk="destructive")
def purge_tickets():
    return "all tickets deleted"


policy = Policy({
    "triage-agent": AgentPolicy(allow=("read_*", "write_note"), max_risk="write", max_calls=5),
    "release-agent": AgentPolicy(allow=("read_*", "send_*"), max_risk="external", max_calls=5),
})

log_file = Path(tempfile.mkdtemp()) / "audit.jsonl"
h = Harness(reg, policy, AuditLog(log_file), approver=lambda agent, tool, args: args.get("to", "").endswith("@example.com"))

print("tools the triage agent may see:", h.visible_tools("triage-agent"))
steps = [
    ("1 normal work", h.call("triage-agent", "read_ticket", {"ticket_id": 7})),
    ("2 tries a tool it was never given", h.call("triage-agent", "purge_tickets")),
    ("3 tries to escalate to external (no confirm)", h.call("release-agent", "send_mail", {"to": "x@example.com", "body": "hi"})),
    ("4 same call, approved by the approver", h.call("release-agent", "send_mail", {"to": "x@example.com", "body": "hi"}, confirm=True)),
    ("5 same call to an address the approver rejects", h.call("release-agent", "send_mail", {"to": "x@other.org", "body": "hi"}, confirm=True)),
]
for name, result in steps:
    print(f"{name:52} -> {result['status']}" + (f": {result['message']}" if result["status"] != "ok" else ""))

assert outbox == ["x@example.com"], outbox                      # exactly one mail left the system
ok, broken_at = AuditLog.verify(log_file)
print(f"audit records: {len(log_file.read_text(encoding='utf-8').splitlines())}, chain intact: {ok}")
sys.exit(0 if ok else 1)
