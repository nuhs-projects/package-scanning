#!/usr/bin/env python3
"""PR check: the library lists are well formed.

    python3 scripts/check_lists.py

Exits 1 and prints every bad line when a list has a line in the wrong format,
out of order, duplicated, or naming an internal Maven artifact: a group under
any prefix in INTERNAL_GROUPS (comma- or space-separated; in CI a repository
variable, so the prefixes are not committed). A list file that does not exist
counts as empty.
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PYPI = r"^[a-z0-9]+(?:-[a-z0-9]+)*==[A-Za-z0-9][A-Za-z0-9.+!_-]*$"
MAVEN = r"^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9][A-Za-z0-9_.+-]*$"
NPM = r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~-][a-z0-9._~-]*@[0-9A-Za-z][0-9A-Za-z.+-]*$"

LISTS = {
    "python/requirements.txt": re.compile(PYPI),
    "java/dependencies.txt": re.compile(MAVEN),
    "npm/packages.txt": re.compile(NPM),
}


def internal_groups(env=os.environ):
    return tuple(p for p in re.split(r"[\s,]+", env.get("INTERNAL_GROUPS", "")) if p)


def check_lines(name, lines, pattern, internal=()):
    """Return a list of problems for one list file's lines."""
    problems = []
    seen = set()
    previous = None
    for number, line in enumerate(lines, 1):
        where = f"{name}:{number}"
        if not pattern.match(line):
            problems.append(f"{where}: bad format: {line!r}")
            continue
        group = line.split(":", 1)[0]
        if name.startswith("java/") and any(group == p or group.startswith(p + ".") for p in internal):
            problems.append(f"{where}: internal artifact: {line}")
        if line in seen:
            problems.append(f"{where}: duplicate: {line}")
        if previous is not None and line < previous:
            problems.append(f"{where}: not sorted: {line}")
        seen.add(line)
        previous = line
    return problems


def check_root(root, internal=()):
    problems = []
    for name, pattern in LISTS.items():
        path = Path(root) / name
        if not path.exists():
            continue
        text = path.read_text()
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        elif text:
            problems.append(f"{name}: missing trailing newline")
        problems += check_lines(name, lines, pattern, internal)
    return problems


def main():
    problems = check_root(ROOT, internal_groups())
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
