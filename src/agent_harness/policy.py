"""Per-agent policy: least privilege by default.

An agent sees only tools matching its `allow` patterns, never above `max_risk`, never more than
`max_calls` calls per run, and tools from `external` upwards need an explicit approval.
Order of checks (first failure wins): unknown agent -> deny pattern -> allow pattern -> risk ceiling -> call budget.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Dict, Tuple

from .registry import RISK_ORDER, Tool


@dataclass(frozen=True)
class AgentPolicy:
    allow: Tuple[str, ...] = ()               # fnmatch patterns, e.g. ("read_*", "search")
    deny: Tuple[str, ...] = ()                # wins over allow
    max_risk: str = "write"
    max_calls: int = 50
    timeout_s: float = 30.0


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    needs_approval: bool = False


class Policy:
    def __init__(self, agents: Dict[str, AgentPolicy], approval_from: str = "external") -> None:
        for name, p in agents.items():
            if p.max_risk not in RISK_ORDER:
                raise ValueError(f"agent {name!r}: unknown max_risk {p.max_risk!r}")
        if approval_from not in RISK_ORDER:
            raise ValueError(f"unknown approval_from {approval_from!r}")
        self.agents = dict(agents)
        self.approval_from = approval_from

    def for_agent(self, agent: str) -> AgentPolicy | None:
        return self.agents.get(agent)

    def visible_tools(self, agent: str, tools: list[Tool]) -> list[str]:
        """What the agent may even be told about (a model cannot misuse a tool it never sees)."""
        p = self.agents.get(agent)
        if p is None:
            return []
        return sorted(t.name for t in tools if self._matches(p, t) and RISK_ORDER[t.risk] <= RISK_ORDER[p.max_risk])

    @staticmethod
    def _matches(p: AgentPolicy, tool: Tool) -> bool:
        if any(fnmatchcase(tool.name, pat) for pat in p.deny):
            return False
        return any(fnmatchcase(tool.name, pat) for pat in p.allow)

    def check(self, agent: str, tool: Tool, calls_so_far: int) -> Decision:
        p = self.agents.get(agent)
        if p is None:
            return Decision(False, f"unknown agent {agent!r}")
        if any(fnmatchcase(tool.name, pat) for pat in p.deny):
            return Decision(False, f"tool {tool.name!r} is denied for {agent!r}")
        if not any(fnmatchcase(tool.name, pat) for pat in p.allow):
            return Decision(False, f"tool {tool.name!r} is not in the allowlist of {agent!r}")
        if RISK_ORDER[tool.risk] > RISK_ORDER[p.max_risk]:
            return Decision(False, f"risk {tool.risk!r} exceeds ceiling {p.max_risk!r} of {agent!r}")
        if calls_so_far >= p.max_calls:
            return Decision(False, f"call budget exhausted ({p.max_calls}) for {agent!r}")
        return Decision(True, "ok", needs_approval=RISK_ORDER[tool.risk] >= RISK_ORDER[self.approval_from])
