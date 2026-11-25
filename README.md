# airlock

*A controlled passage between AI agents and the outside world* – a small, tested gate between agents and their tools.

Agents are fast and sometimes wrong. This repository is a reference implementation of the controls I put around them
in my own multi-agent assistant: **least privilege per agent, risk classes, approval with dry-run as the default,
call budgets, timeouts and a tamper-evident audit log.** About 275 lines of Python, no dependencies, 26 tests.

```text
agent ──call("send_mail", args)──► Harness ──► allowlist → risk ceiling → budget → approval → timeout → tool
                                      └──────► audit log (every decision, secrets redacted, hash-chained)
```

## What it does

| Control | Behaviour |
|---|---|
| **Allowlist per agent** | fnmatch patterns (`read_*`); `deny` wins over `allow`; unknown agent = nothing allowed. `visible_tools()` shows an agent only what it may use. |
| **Risk classes** | Every tool declares `read < write < external < destructive`. Each agent has a ceiling. |
| **Approval, dry-run first** | `external` and `destructive` calls are a **dry run** unless `confirm=True` *and* an approver says yes. No approver configured = no external effects. An agent cannot approve itself. |
| **Budgets** | Max executed calls per run and a timeout per call. Denied and dry-run attempts do not use budget. |
| **Audit log** | JSON lines, one record per decision, secrets redacted by key name and by value pattern, each record carries the hash of the previous one – editing or deleting a line is detected by `AuditLog.verify()`. |
| **Errors** | Policy problems return a status (`denied`, `dry_run`, `timeout`, `error`) instead of raising, so the agent loop can feed it back to the model. |

## Try it

```bash
pip install -e ".[test]"
python -m pytest -q          # 26 tests
python examples/demo.py      # five typical agent mistakes and what happens to each
python examples/team.py      # three roles (researcher, builder, reviewer) on one harness
```

Demo output (shortened):

```text
2 tries a tool it was never given       -> denied: tool 'purge_tickets' is not in the allowlist of 'triage-agent'
3 tries to escalate to external         -> dry_run: send_mail (external) was NOT executed; repeat with confirm=True after approval
5 same call to an address the approver rejects -> denied: approval refused
audit records: 5, chain intact: True
```

## Example: three roles on one harness

`examples/team.py` runs a small pipeline with a *researcher*, a *builder* and a *reviewer*. Each role sees only the tools it
needs (`visible_tools` differs per role), has its own call budget and timeout, and the only outside effect (`release_fix`)
needs a dry run first and then an approval. The pipeline **fails closed**: any step that is not `ok` (denied, timeout, error,
failed tests) halts the run, so a later role never builds on a failed earlier one. Roles hand over data, never tools.
`tests/test_team.py` covers the happy path, role isolation, refused approval, exhausted budget, a hanging dependency, a
rejected preview and tampering with the audit log; 7 deliberate breakages of the example (builder allowed to release,
reviewer with all rights, release without confirmation ...) were all caught.

## Are the tests any good?

A green test suite proves little on its own, so I checked the tests the other way round: I removed one rule at a time in a
throw-away copy (deny ignored, budget ignored, risk ceiling ignored, dry-run default removed, approval without approver,
hash-chain check removed, secret redaction removed, budget never counted). **All 8 mutations were caught** by at least one test.

## What it does not do (read this before using it)

- **No sandbox.** Tools run in-process. For real isolation use containers, OS users or a separate service – this is the
  policy layer in front of that, not a replacement.
- **Timeouts cannot kill a thread.** A timed-out tool may still finish in the background. Side-effecting tools must be
  idempotent or enforce their own timeouts.
- **The audit log is tamper-evident, not tamper-proof.** Someone who can rewrite the whole file can forge a new chain.
  Store the latest hash somewhere else if that matters.
- **No tenant separation, authentication or per-user policy.** One policy object, one process.
- **Not proven with third-party users.** It is the clean version of patterns I use daily in a personal system; it has not been run in production for others.

See [docs/DESIGN.md](docs/DESIGN.md) for the decisions and for two real cases where an agent was wrong.

## License

MIT. Author: Nico Vogel ([@gh0stsyntax](https://github.com/gh0stsyntax)).
