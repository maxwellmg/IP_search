from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Fact:
    key: str
    value: Any
    source: str  # id in sources.SOURCES
    note: str = ""


@dataclass
class Signal:
    """A potential fraud indicator or incongruity."""
    severity: str  # info | low | medium | high
    message: str
    evidence: list[str] = field(default_factory=list)  # source ids


@dataclass
class Section:
    title: str
    facts: list[Fact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # parsed values for compare.py, not printed

    def add(self, key, value, source, note=""):
        if value not in (None, "", [], {}):
            self.facts.append(Fact(key, value, source, note))

    def to_dict(self):
        d = asdict(self)
        d.pop("raw")
        return d
