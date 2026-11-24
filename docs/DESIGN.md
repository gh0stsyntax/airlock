# Design notes

## Principles

1. **An agent can only misuse what it can see.** `visible_tools()` filters the tool list per agent before the model ever gets it;
   the allowlist check in `call()` is the second line, not the first.
2. **Denial is information, not an exception.** The harness returns `denied` with a reason. The agent loop passes that back to the model,
   which can then choose another way instead of crashing the run.
3. **Dry-run is the default for anything that leaves the machine.** The safe path needs no flag; the dangerous path needs a flag *and* an approver.
4. **Approval is separate from the agent.** `confirm=True` only asks for approval; the `approver` callback (a human prompt, a stricter rule set) decides.
5. **Every decision is logged, including refusals.** Refusals are the interesting records when you review what an agent tried.
6. **Fail loudly at configuration time.** Unknown risk class, duplicate tool name, unknown ceiling → `ValueError` at start-up, not a silent default.

## Why these risk classes

`read < write < external < destructive` is deliberately coarse. Four classes are easy to assign when writing a tool and easy to review.
`external` is its own class because it is the one you cannot take back by restoring a backup (mail sent, post published, payment made).

## Where the agent was wrong (and how it was caught)

These two cases shaped the rules above. They come from my own setup.

**1. The quality score that did not mean anything (flowsmith, 24 Nov 2026).**
A local LLM generated UiPath workflows and the project's own validator scored them 84–99/100. When I built the same files with the real UiPath
toolchain (`uip rpa build`), **none of the five loaded**: wrong type syntax, a legacy VB settings block, invented activity properties, undeclared variables,
C# in a VB project. The score measured best practices, not whether the file works. Fix: deterministic compiler corrections, each one as a regression test,
and a build check against the real tool (5/5 build afterwards). Lesson: an agent's or a heuristic's score is never the final check; the real consumer of the output is.
→ [flowsmith](https://github.com/gh0stsyntax/flowsmith)

**2. "Tests passed (exit code 0)" with zero tests (19–24 Nov 2026).**
An agent reported green tests. The test file had been started directly with Python instead of pytest – no test ran, the exit code was 0.
Running the suite properly (`pytest`) showed a real bug in a change made earlier. Fix: the rule "report `N passed`, never just an exit code", written into the
agent instructions. Lesson: ask for evidence that can be wrong (a count), not for a verdict.

## Mapping to a production setup

| Here | In a production system |
|---|---|
| `AgentPolicy.allow/deny` | Per-agent tool lists in the harness config; separate credentials per agent |
| `max_risk` + approval | Review gate before deploy/migration tools; human approver in chat or a pull request |
| `max_calls`, `timeout_s` | Token/cost budgets and wall-clock limits per task |
| `AuditLog` | Append-only log shipped to storage the agent cannot write |
| *not covered* | Sandboxing, network egress rules, tenant separation (row-level security), secrets management |
