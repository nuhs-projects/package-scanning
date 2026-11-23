"""Turn the library lists into synthetic manifests that `snyk test` can scan.

    python3 scripts/snyk_manifests.py [--root DIR] --out DIR
                                      [--ecosystems java,python,npm]

Reads java/dependencies.txt (group:artifact:version), python/requirements.txt
(name==version) and npm/packages.txt (name@version) under --root (default: the
repo root) and writes one directory per manifest under --out, plus
OUT/manifests.txt. Only the listed versions are tested: no transitive
dependencies are resolved or recorded.

A library with N versions spreads over N manifests: manifest k (1-based)
holds the k-th version, in list order, of every library that has at least k
versions. Output is deterministic (entries sorted by name).

Files written:

* Maven, OUT/java-<k>/pom.xml: com.example:catalogue-java-<k>:0, packaging
  pom, one <dependency> per entry with a wildcard exclusion, so Maven resolves
  the listed artifact only. <repositories> come from public-repos.txt (ids
  public-1, public-2, ...). Artifacts that are pom-only (artifactId ending in
  -bom, -dependencies or -parent, or listed in POM_ONLY) get <type>pom</type>.
* Python, OUT/python-<k>/pyproject.toml and poetry.lock: every package is a
  top-level dependency pinned exactly, and the lock has one [[package]] per
  entry with no dependencies between them. snyk-poetry-lockfile-parser reads
  both files statically (no pip, no poetry): it takes the dependency names
  from [tool.poetry.dependencies], the versions from poetry.lock, and matches
  names case-insensitively with - and _ equivalent. Names are written
  normalised (lowercase, runs of - _ . become -).
* npm, OUT/npm-<k>/package.json and package-lock.json (lockfileVersion 3):
  the root entry "" plus node_modules/<name> entries with version and
  resolved; no integrity (snyk-nodejs-lockfile-parser does not need it) and
  no dependencies between packages.

manifests.txt has one tab-separated line per manifest:

    <name>  <path for snyk --file, relative to OUT>  <entries>  <extra snyk args>

e.g. "java-1<TAB>java-1/pom.xml<TAB>270<TAB>". The path is pom.xml for Maven,
poetry.lock for Python (Snyk CLI maps poetry.lock to the poetry package
manager, so no --package-manager is needed) and package-lock.json for npm.
The fourth column is extra snyk arguments; it is empty today but always
present, so the workflow can split on tabs and pass it through unquoted.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from xml.sax.saxutils import escape

ECOSYSTEMS = ("java", "python", "npm")
LISTS = {
    "java": "java/dependencies.txt",
    "python": "python/requirements.txt",
    "npm": "npm/packages.txt",
}
POM_ONLY_SUFFIXES = ("-bom", "-dependencies", "-parent")
# Pom-only artifacts that the suffix rule does not catch, as group:artifact.
POM_ONLY = frozenset()
PYTHON_RANGE = "^3.8"


def parse_line(eco, line):
    """(name, version) of one list line, as scan.parse_line does."""
    if eco == "python":
        name, _, version = line.partition("==")
    elif eco == "java":
        name, _, version = line.rpartition(":")
    else:
        name, _, version = line.rpartition("@")
    return name, version


def read_list(root, eco):
    """Entries [(name, version)] in list order; blank lines and # skipped."""
    entries = []
    with open(os.path.join(root, LISTS[eco])) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(parse_line(eco, line))
    return entries


def split_versions(entries, key=lambda name: name):
    """Manifest k holds the k-th version of every library that has one.

    Returns a list of manifests, each a list of (name, version) sorted by
    name. Repeated identical entries count once.
    """
    versions = {}
    for name, version in entries:
        vs = versions.setdefault(key(name), (name, []))[1]
        if version not in vs:
            vs.append(version)
    manifests = []
    for name, vs in sorted(versions.values()):
        for k, version in enumerate(vs):
            while len(manifests) <= k:
                manifests.append([])
            manifests[k].append((name, version))
    return manifests


def read_repos(root):
    repos = []
    path = os.path.join(root, "public-repos.txt")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    repos.append(line)
    return repos


def is_pom_only(name):
    _, _, artifact = name.partition(":")
    return name in POM_ONLY or artifact.endswith(POM_ONLY_SUFFIXES)


def pom_xml(k, entries, repos):
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<project xmlns="http://maven.apache.org/POM/4.0.0">',
           "  <modelVersion>4.0.0</modelVersion>",
           "  <groupId>com.example</groupId>",
           f"  <artifactId>catalogue-java-{k}</artifactId>",
           "  <version>0</version>",
           "  <packaging>pom</packaging>"]
    if repos:
        out.append("  <repositories>")
        for i, url in enumerate(repos, 1):
            out += ["    <repository>",
                    f"      <id>public-{i}</id>",
                    f"      <url>{escape(url)}</url>",
                    "    </repository>"]
        out.append("  </repositories>")
    out.append("  <dependencies>")
    for name, version in entries:
        group, _, artifact = name.partition(":")
        out += ["    <dependency>",
                f"      <groupId>{escape(group)}</groupId>",
                f"      <artifactId>{escape(artifact)}</artifactId>",
                f"      <version>{escape(version)}</version>"]
        if is_pom_only(name):
            out.append("      <type>pom</type>")
        out += ["      <exclusions>",
                "        <exclusion>",
                "          <groupId>*</groupId>",
                "          <artifactId>*</artifactId>",
                "        </exclusion>",
                "      </exclusions>",
                "    </dependency>"]
    out += ["  </dependencies>", "</project>", ""]
    return "\n".join(out)


def normalise_py(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def toml_str(s):
    return json.dumps(s)  # JSON string escapes are valid TOML basic strings


def pyproject_toml(k, entries):
    out = ["[tool.poetry]",
           f"name = {toml_str(f'catalogue-python-{k}')}",
           'version = "0"',
           'description = ""',
           "authors = []",
           "",
           "[tool.poetry.dependencies]",
           f"python = {toml_str(PYTHON_RANGE)}"]
    for name, version in entries:
        out.append(f"{toml_str(normalise_py(name))} = {toml_str('==' + version)}")
    out += ["", "[build-system]",
            'requires = ["poetry-core"]',
            'build-backend = "poetry.core.masonry.api"', ""]
    return "\n".join(out)


def poetry_lock(entries):
    out = []
    for name, version in entries:
        out += ["[[package]]",
                f"name = {toml_str(normalise_py(name))}",
                f"version = {toml_str(version)}",
                'description = ""',
                "optional = false",
                'python-versions = "*"',
                "files = []",
                ""]
    digest = hashlib.sha256(
        "\n".join(f"{n}=={v}" for n, v in entries).encode()).hexdigest()
    out += ["[metadata]",
            'lock-version = "2.0"',
            f"python-versions = {toml_str(PYTHON_RANGE)}",
            f"content-hash = {toml_str(digest)}", ""]
    return "\n".join(out)


def npm_files(k, entries):
    deps = {name: version for name, version in entries}
    root = f"catalogue-npm-{k}"
    package = {"name": root, "version": "0.0.0", "dependencies": deps}
    packages = {"": {"name": root, "version": "0.0.0", "dependencies": deps}}
    for name, version in entries:
        base = name.rpartition("/")[2]
        packages["node_modules/" + name] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz",
        }
    lock = {"name": root, "version": "0.0.0", "lockfileVersion": 3,
            "requires": True, "packages": packages}
    dump = lambda obj: json.dumps(obj, indent=2) + "\n"  # noqa: E731
    return dump(package), dump(lock)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def generate(root, out, ecosystems=ECOSYSTEMS):
    """Write the manifests; returns the manifests.txt rows."""
    rows = []
    for eco in ecosystems:
        entries = read_list(root, eco)
        key = normalise_py if eco == "python" else (lambda name: name)
        for k, group in enumerate(split_versions(entries, key), 1):
            name = f"{eco}-{k}"
            if eco == "java":
                write(os.path.join(out, name, "pom.xml"),
                      pom_xml(k, group, read_repos(root)))
                target = "pom.xml"
            elif eco == "python":
                write(os.path.join(out, name, "pyproject.toml"),
                      pyproject_toml(k, group))
                write(os.path.join(out, name, "poetry.lock"), poetry_lock(group))
                target = "poetry.lock"
            else:
                package, lock = npm_files(k, group)
                write(os.path.join(out, name, "package.json"), package)
                write(os.path.join(out, name, "package-lock.json"), lock)
                target = "package-lock.json"
            rows.append((name, f"{name}/{target}", len(group), ""))
    write(os.path.join(out, "manifests.txt"),
          "".join("\t".join(map(str, row)) + "\n" for row in rows))
    return rows


def main(argv=None):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=here)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ecosystems", default=",".join(ECOSYSTEMS))
    args = ap.parse_args(argv)
    ecosystems = [e for e in args.ecosystems.replace(" ", ",").split(",") if e]
    bad = [e for e in ecosystems if e not in ECOSYSTEMS]
    if bad:
        ap.error(f"unknown ecosystem: {', '.join(bad)}")
    rows = generate(args.root, args.out, ecosystems)
    print(f"wrote {len(rows)} manifests to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
