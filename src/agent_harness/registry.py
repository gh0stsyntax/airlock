"""Tool registry: every tool declares a name and a risk class.

Risk classes (ascending): read < write < external < destructive.
  read        – no side effects
  write       – changes local state (files, database)
  external    – leaves the machine (mail, HTTP POST, payments, publishing)
  destructive – deletes or overwrites data that cannot be restored
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

RISK_ORDER = {"read": 0, "write": 1, "external": 2, "destructive": 3}


class UnknownTool(KeyError):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    fn: Callable[..., Any]
    risk: str
    description: str = ""


class Registry:
    def __init__(self) -> None:
        self._tools: Dict[str, Tool] = {}

    def tool(self, name: Optional[str] = None, risk: str = "read", description: str = ""):
        """Decorator. The risk class is mandatory knowledge: an unknown class is a programming error."""
        if risk not in RISK_ORDER:
            raise ValueError(f"unknown risk class {risk!r}; use one of {sorted(RISK_ORDER, key=RISK_ORDER.get)}")

        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            if tool_name in self._tools:
                raise ValueError(f"tool {tool_name!r} already registered")
            self._tools[tool_name] = Tool(tool_name, fn, risk, description or (fn.__doc__ or "").strip())
            return fn

        return wrap

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise UnknownTool(name) from None

    def names(self) -> List[str]:
        return sorted(self._tools)
