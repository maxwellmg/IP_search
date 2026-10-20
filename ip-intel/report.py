from __future__ import annotations

import os
import sys
import textwrap

from .sources import SOURCES

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
SEV_COLOR = {"high": "31;1", "medium": "33;1", "low": "36", "info": "90"}


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def render_text(r: dict, show_sources=True) -> str:
    out = [_c("1", f"\n=== {r['ip']} ===")]
    if r["claims"]:
        out.append("Claimed: " + ", ".join(f"{k}={v}" for k, v in r["claims"].items()))

    out.append(_c("1", "\n-- Signals --"))
    if not r["signals"]:
        out.append("  (none)")
    for s in r["signals"]:
        tag = _c(SEV_COLOR[s["severity"]], f"[{s['severity'].upper():6}]")
        src = _c("90", f"  <- {', '.join(s['evidence'])}") if s["evidence"] else ""
        out.append(f"  {tag} {s['message']}{src}")

    used = set()
    for sec in r["sections"]:
        out.append(_c("1", f"\n-- {sec['title']} --"))
        width = max((len(f["key"]) for f in sec["facts"]), default=0)
        for f in sec["facts"]:
            used.add(f["source"])
            out.append(f"  {f['key']:<{width}}  {f['value']}  {_c('90', '[' + f['source'] + ']')}")
            if f["note"]:
                out.append(_c("90", textwrap.indent(textwrap.fill(f["note"], 90), " " * (width + 4))))
        for e in sec["errors"]:
            out.append(_c("31", f"  error: {e}"))

    if show_sources:
        out.append(_c("1", "\n-- Sources (what each [label] means) --"))
        for sid in [k for k in SOURCES if k in used | {e for s in r["signals"] for e in s["evidence"]}]:
            src = SOURCES[sid]
            out.append(f"  [{sid}] {src['name']}")
            for k in ("method", "url", "meaning", "caveat"):
                out.append(textwrap.fill(f"{k}: {src[k]}", 100, initial_indent=" " * 6,
                                         subsequent_indent=" " * 8))
    return "\n".join(out)
