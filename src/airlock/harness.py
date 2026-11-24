"""The gate between an agent and its tools. Every call is checked, limited and logged.

call() never raises for policy reasons – it returns a status the agent loop can show to the model:
  ok | dry_run | denied | timeout | error
`external` and `destructive` tools run as a DRY RUN unless the caller passes confirm=True AND an approver
(a human or a stricter automatic check) says yes. No approver configured = no external effects, by design.
"""
from __future__ import annotations

import concurrent.futures
from collections import defaultdict
from typing import Any, Callable, Dict, Optional

from .audit import AuditLog
from .policy import Policy
from .registry import Registry, UnknownTool

Approver = Callable[[str, str, Dict[str, Any]], bool]


class Harness:
    def __init__(self, registry: Registry, policy: Policy, audit: AuditLog, approver: Optional[Approver] = None) -> None:
        self.registry, self.policy, self.audit, self.approver = registry, policy, audit, approver
        self._calls: Dict[str, int] = defaultdict(int)

    def reset_budget(self, agent: str) -> None:
        self._calls[agent] = 0

    def visible_tools(self, agent: str) -> list[str]:
        return self.policy.visible_tools(agent, [self.registry.get(n) for n in self.registry.names()])

    def call(self, agent: str, tool_name: str, args: Optional[Dict[str, Any]] = None, confirm: bool = False) -> Dict[str, Any]:
        args = dict(args or {})
        try:
            tool = self.registry.get(tool_name)
        except UnknownTool:
            return self._deny(agent, tool_name, args, f"unknown tool {tool_name!r}")
        decision = self.policy.check(agent, tool, self._calls[agent])
        if not decision.allowed:
            return self._deny(agent, tool_name, args, decision.reason)
        if decision.needs_approval:
            if not confirm:
                self.audit.record({"event": "dry_run", "agent": agent, "tool": tool_name, "risk": tool.risk, "args": args})
                return {"status": "dry_run", "message": f"{tool_name} ({tool.risk}) was NOT executed; repeat with confirm=True after approval", "args": args}
            if self.approver is None:
                return self._deny(agent, tool_name, args, "no approver configured: external effects stay disabled")
            if not self.approver(agent, tool_name, args):
                return self._deny(agent, tool_name, args, "approval refused")
        self._calls[agent] += 1                       # only calls that actually run count against the budget
        timeout = self.policy.for_agent(agent).timeout_s
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(tool.fn, **args)
        try:
            result = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            # A Python thread cannot be killed: the tool may still finish in the background. Tools with
            # side effects must therefore be idempotent or use their own timeouts (see docs/DESIGN.md).
            self.audit.record({"event": "timeout", "agent": agent, "tool": tool_name, "risk": tool.risk, "args": args, "timeout_s": timeout})
            return {"status": "timeout", "message": f"{tool_name} exceeded {timeout}s"}
        except Exception as e:                        # the agent gets the class and message, never a traceback with paths
            self.audit.record({"event": "error", "agent": agent, "tool": tool_name, "risk": tool.risk, "args": args, "error": f"{type(e).__name__}: {e}"})
            return {"status": "error", "message": f"{type(e).__name__}: {e}"}
        finally:
            pool.shutdown(wait=False)
        self.audit.record({"event": "ok", "agent": agent, "tool": tool_name, "risk": tool.risk, "args": args, "confirmed": bool(confirm and decision.needs_approval)})
        return {"status": "ok", "result": result}

    def _deny(self, agent: str, tool: str, args: Dict[str, Any], reason: str) -> Dict[str, Any]:
        self.audit.record({"event": "denied", "agent": agent, "tool": tool, "args": args, "reason": reason})
        return {"status": "denied", "message": reason}
