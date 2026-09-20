"""Assert the two defense layers never reference each other.

Checked against the AST, not the source text, so the docstrings that document
this invariant cannot trip it - and, more importantly, cannot mask a real
violation either.

The invariant matters because the layers must fail independently. If detection
consults the gate (or vice versa) the factorial decomposition is meaningless:
the "detection only" arm would silently contain some prevention.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PAIRS = [("defense/detection.py", "prevention"), ("defense/prevention.py", "detection")]


def modules_imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names |= {f"{node.module}.{a.name}" for a in node.names}
    return names


def main() -> int:
    failed = False
    for filename, forbidden in PAIRS:
        path = Path(filename)
        hits = {m for m in modules_imported(path) if forbidden in m}
        if hits:
            print(f"FAIL {filename} imports {sorted(hits)}")
            failed = True
        else:
            print(f"ok   {filename} does not import anything named {forbidden!r}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
