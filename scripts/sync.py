"""Rebuild the library lists (python/, java/, npm/) from local project manifests.

Run on a developer machine that can reach the projects and their registry
(GitHub Actions cannot), with Python 3.11+ and nothing else:

    python3 scripts/sync.py [--sources sources.local] [--root ~/projects] [--no-maven]

--sources FILE   One manifest path per line (relative to --root, or absolute);
                 '#' starts a comment. FILE is gitignored: it is the only place
                 that knows which projects feed the lists. Default:
                 sources.local next to the repo root.
--root DIR       Base directory for relative paths in FILE. Default: current
                 directory.
--no-maven       Skip pom.xml sources (no mvn run); the Maven list is then
                 written empty, so do not commit the result.

The manifest type is taken from the file name:

    uv.lock               registry packages only (editable/virtual/directory/git
                          sources are the project itself or not public)
    requirements*.txt     exact pins `name==version` only
    package-lock.json     lockfile v2/v3 `packages` map, dev included
    pom.xml               `mvn dependency:list` with test scope (which also
                          covers compile and runtime), transitive included

Lists are rebuilt from scratch from every source, so a version no project uses
any more drops out. Output is sorted, deduplicated, one entry per line.
Internal Maven artifacts are never listed: every groupId declared in the
project's own pom.xml files (its reactor modules) is dropped, and so is any
group under a prefix in INTERNAL_GROUPS (comma- or space-separated, e.g.
`INTERNAL_GROUPS=com.example`), which covers internal libraries that come from
other projects. Nothing but libraries and versions is written: no project
names, no paths.
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POM_NS = "{http://maven.apache.org/POM/4.0.0}"
# maven-dependency-plugin version used for `dependency:list`. Newer releases
# (or their dependencies) may be blocked by the registry mirror.
DEPENDENCY_PLUGIN = "3.7.0"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Where each list lives, relative to the repo root.
LIST_FILES = {
    "pypi": "python/requirements.txt",
    "maven": "java/dependencies.txt",
    "npm": "npm/packages.txt",
}

REQ_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")


def normalise_pypi(name):
    """PEP 503: so Foo_Bar, foo.bar and foo-bar are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_uv_lock(text):
    found = set()
    for pkg in tomllib.loads(text).get("package", []):
        source = pkg.get("source", {})
        # Only a registry source is a published library; editable, virtual,
        # directory and git entries are the project itself or private.
        if "registry" not in source or "version" not in pkg:
            continue
        found.add((normalise_pypi(pkg["name"]), pkg["version"]))
    return found


def parse_requirements(text):
    found = set()
    # Join backslash continuations so `--hash` lines attach to their package.
    for line in text.replace("\\\n", " ").splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = line.split(";", 1)[0].strip()
        line = re.sub(r"\s--hash=\S+", "", line).strip()
        m = REQ_PIN.match(line)
        if m and "*" not in m.group(2):
            found.add((normalise_pypi(m.group(1)), m.group(2)))
    return found


def parse_package_lock(text):
    found = set()
    for key, entry in json.loads(text).get("packages", {}).items():
        if not key.startswith("node_modules/") and "/node_modules/" not in key:
            continue  # Workspace directories are local, even when named.
        if entry.get("link") or "version" not in entry:
            continue
        resolved = entry.get("resolved", "")
        parsed = urllib.parse.urlparse(resolved)
        if resolved and (
            parsed.scheme not in ("http", "https")
            or parsed.path.endswith(".git")
            or parsed.hostname in ("github.com", "gitlab.com", "bitbucket.org")
        ):
            continue  # File, directory, and identifiable git sources are local/non-registry.
        name = entry.get("name", key.rsplit("node_modules/", 1)[1])
        if name:
            found.add((name, entry["version"]))
    return found


def internal_groups(env=os.environ):
    """Group prefixes from INTERNAL_GROUPS, comma- or space-separated."""
    return tuple(p for p in re.split(r"[\s,]+", env.get("INTERNAL_GROUPS", "")) if p)


def is_internal(group, prefixes):
    return any(group == p or group.startswith(p + ".") for p in prefixes)


def project_groups(pom):
    """groupIds declared by the project's own poms (the aggregator and every
    module below it). Only an explicit <project><groupId> counts: a module
    without one inherits it, and the parent's groupId may be a public one
    (e.g. a Spring Boot parent)."""
    groups = set()
    skip = {"target", "node_modules"}
    for dirpath, dirnames, filenames in os.walk(Path(pom).parent):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
        if "pom.xml" not in filenames:
            continue
        try:
            root = ET.parse(os.path.join(dirpath, "pom.xml")).getroot()
        except ET.ParseError:
            continue
        for tag in (f"{POM_NS}groupId", "groupId"):
            el = root.find(tag)
            if el is not None and el.text and el.text.strip():
                groups.add(el.text.strip())
                break
    return groups


def parse_maven_list(text, internal=()):
    """Parse `dependency:list` output into {(group, artifact, version)},
    dropping groups under any prefix in `internal`."""
    found = set()
    for line in text.splitlines():
        # Keep the coordinate only: drop "-- module x" and "(optional)" suffixes.
        tokens = ANSI.sub(" ", line).split()
        if not tokens:
            continue
        parts = tokens[0].split(":")
        if len(parts) == 5:  # g:a:type:version:scope
            group, artifact, version = parts[0], parts[1], parts[3]
        elif len(parts) == 6:  # g:a:type:classifier:version:scope
            group, artifact, version = parts[0], parts[1], parts[4]
        else:
            continue  # headers, "none", blank lines
        if is_internal(group, internal):
            continue
        found.add((group, artifact, version))
    return found


def run_maven(pom, plugin_version=DEPENDENCY_PLUGIN):
    """The only place mvn is called. Environment passes through on purpose:
    MAVEN_ARGS carries the settings file that points at the registry mirror."""
    cmd = [
        "mvn", "-B", "-Dstyle.color=never", "-f", str(pom),
        # Parents pin older plugin releases (or pin through this property)
        # that the mirror may quarantine; a fully qualified goal overrides both.
        f"-Dmaven-dependency-plugin.version={plugin_version}",
        # Running the compile phase lets the reactor resolve sibling modules
        # (internal, never published); nothing is actually compiled.
        "-Dmaven.main.skip=true", "-Dmaven.resources.skip=true", "compile",
        f"org.apache.maven.plugins:maven-dependency-plugin:{plugin_version}:list",
        "-DincludeScope=test", "-DexcludeTransitive=false",
    ]
    # Read from stdout: with several modules, -DoutputFile keeps only the last
    # one (appendOutput is ignored). Maven's output can echo repository URLs,
    # so it is never shown.
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"mvn failed (exit {result.returncode}) for {pom}")
    return maven_stdout_dependencies(result.stdout)


def maven_stdout_dependencies(stdout):
    """Keep the indented dependency lines of `dependency:list` log output."""
    lines = []
    for line in stdout.splitlines():
        line = ANSI.sub("", line)
        if line.startswith("[INFO]    "):
            lines.append(line[len("[INFO]"):])
    return "\n".join(lines)


def parse_sources(text, root):
    """Turn sources.local content into manifest paths."""
    paths = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            paths.append(Path(root, os.path.expanduser(line)))  # absolute wins
    return paths


def detect_kind(path):
    name = Path(path).name
    if name == "uv.lock":
        return "uv"
    if fnmatch.fnmatch(name, "requirements*.txt"):
        return "requirements"
    if name == "package-lock.json":
        return "npm"
    if name == "pom.xml":
        return "maven"
    raise ValueError(
        f"unknown manifest type for {name!r}: expected uv.lock, "
        "requirements*.txt, package-lock.json or pom.xml"
    )


def format_lines(kind, entries):
    if kind == "pypi":
        lines = (f"{n}=={v}" for n, v in entries)
    elif kind == "maven":
        lines = (f"{g}:{a}:{v}" for g, a, v in entries)
    else:
        lines = (f"{n}@{v}" for n, v in entries)
    return sorted(set(lines))


def write_list(path, lines):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines))


def collect(paths, maven=True, internal=()):
    """Read every manifest; return {"pypi": set, "maven": set, "npm": set}."""
    result = {"pypi": set(), "maven": set(), "npm": set()}
    for path in paths:
        kind = detect_kind(path)
        if not Path(path).is_file():
            raise FileNotFoundError(f"manifest not found: {path}")
        if kind == "maven":
            if maven:
                drop = tuple(internal) + tuple(project_groups(path))
                result["maven"] |= parse_maven_list(run_maven(path), drop)
            continue
        text = Path(path).read_text()
        if kind == "uv":
            result["pypi"] |= parse_uv_lock(text)
        elif kind == "requirements":
            result["pypi"] |= parse_requirements(text)
        else:
            result["npm"] |= parse_package_lock(text)
    return result


def sync(paths, outdir=REPO, maven=True, internal=()):
    entries = collect(paths, maven, internal)
    counts = {}
    for kind, rel in LIST_FILES.items():
        lines = format_lines(kind, entries[kind])
        write_list(Path(outdir, rel), lines)
        counts[kind] = len(lines)
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sources", default=str(REPO / "sources.local"))
    parser.add_argument("--root", default=os.getcwd())
    parser.add_argument("--no-maven", action="store_true")
    args = parser.parse_args(argv)

    try:
        text = Path(args.sources).read_text()
    except OSError as e:
        sys.exit(f"cannot read sources file: {e.strerror}")
    paths = parse_sources(text, os.path.expanduser(args.root))
    try:
        counts = sync(paths, maven=not args.no_maven, internal=internal_groups())
    except (ValueError, OSError, RuntimeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as e:
        sys.exit(f"error: {e}")

    print(f"python: {counts['pypi']} packages")
    print(f"java:   {counts['maven']} artifacts")
    print(f"npm:    {counts['npm']} packages")


if __name__ == "__main__":
    main()
