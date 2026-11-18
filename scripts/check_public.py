#!/usr/bin/env python3
"""PR check: every library in the lists is published in a public registry.

    python3 scripts/check_public.py [--root DIR] [--timeout SECONDS] [--strict]

Check publication directly with public registries so the catalogue can be
validated without a list of internal names.

For each list entry:

    PyPI    GET  https://pypi.org/pypi/<name>/<version>/json
    npm     GET  https://registry.npmjs.org/<name>/<version>
    Maven   HEAD <repo>/<group/path>/<artifact>/<version>/<artifact>-<version>.pom
            for each repository in public-repos.txt (Maven Central plus any
            other public repository the project uses)

A version missing from all applicable registries is reported as "not
published" and the script exits 1. Inconclusive responses are reported as
"unknown" and fail the check when --strict is set.

Public repositories are listed in public-repos.txt, one base URL per line.
"""

import argparse
import concurrent.futures
import http.client
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 20
WORKERS = 16

PYPI_INDEX = "https://pypi.org/pypi"
NPM_REGISTRY = "https://registry.npmjs.org"
CENTRAL = "https://repo1.maven.org/maven2"


def read_repos(path):
    """Base URLs of the public Maven repositories, from public-repos.txt."""
    repos = []
    if Path(path).exists():
        for line in Path(path).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                repos.append(line.rstrip("/"))
    if not repos:
        repos.append(CENTRAL)
    return repos


def get(url, timeout, *, read_body=False):
    """Return (status, body). status is 0 when the request could not be made."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read() if read_body else b""
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (OSError, http.client.HTTPException):
        return 0, b""


def head(url, timeout):
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code
    except (OSError, http.client.HTTPException):
        return 0


def publication_status(status):
    """Only explicit absence establishes that a version is not published."""
    if status == 200:
        return "published"
    if status in (404, 410):
        return "not published"
    return "unknown"


def pypi_status(name, version, timeout):
    url = f"{PYPI_INDEX}/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    status, _ = get(url, timeout)
    return publication_status(status)


def npm_status(name, version, timeout):
    url = f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@/')}/{urllib.parse.quote(version, safe='')}"
    status, body = get(url, timeout, read_body=True)
    if status != 200:
        return publication_status(status)
    try:
        metadata = json.loads(body)
    except ValueError:
        return "unknown"
    if not isinstance(metadata, dict) or not isinstance(metadata.get("version"), str):
        return "unknown"
    # The version endpoint also accepts tags such as "latest".
    return "published" if metadata["version"] == version else "not published"


def maven_status(group, artifact, version, repos, timeout):
    path = "/".join(group.split(".")) + f"/{artifact}/{version}/{artifact}-{version}.pom"
    unknown = False
    for repo in repos:
        status = head(f"{repo}/{path}", timeout)
        if status == 200:
            return "published"
        if publication_status(status) == "unknown":
            unknown = True
    return "unknown" if unknown else "not published"


def entries(root):
    """(ecosystem, name, version) for every list entry."""
    out = []
    pypi = Path(root) / "python/requirements.txt"
    if pypi.exists():
        for line in pypi.read_text().splitlines():
            if "==" in line:
                name, version = line.split("==", 1)
                out.append(("PyPI", name, version))
    java = Path(root) / "java/dependencies.txt"
    if java.exists():
        for line in java.read_text().splitlines():
            parts = line.split(":")
            if len(parts) == 3:
                out.append(("Maven", parts[0] + ":" + parts[1], parts[2]))
    npm = Path(root) / "npm/packages.txt"
    if npm.exists():
        for line in npm.read_text().splitlines():
            if "@" in line:
                name, version = line.rsplit("@", 1)
                out.append(("npm", name, version))
    return out


def check_one(item, repos, timeout):
    ecosystem, name, version = item
    if ecosystem == "PyPI":
        status = pypi_status(name, version, timeout)
    elif ecosystem == "npm":
        status = npm_status(name, version, timeout)
    else:
        group, artifact = name.split(":", 1)
        status = maven_status(group, artifact, version, repos, timeout)
    return ecosystem, name, version, status


def check(root=ROOT, repos=None, timeout=TIMEOUT):
    """Return a list of (ecosystem, name, version, status) problems."""
    repos = repos if repos is not None else read_repos(ROOT / "public-repos.txt")
    items = entries(root)
    problems = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(check_one, item, repos, timeout) for item in items]
        for future in concurrent.futures.as_completed(futures):
            ecosystem, name, version, status = future.result()
            if status != "published":
                problems.append((ecosystem, name, version, status))
    problems.sort()
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--timeout", type=float, default=TIMEOUT)
    parser.add_argument("--strict", action="store_true", help="fail when publication cannot be verified")
    args = parser.parse_args(argv)

    problems = check(Path(args.root), timeout=args.timeout)
    for ecosystem, name, version, status in problems:
        print(f"{ecosystem} {name}:{version}: {status}")
    unknown = sum(1 for p in problems if p[3] == "unknown")
    missing = len(problems) - unknown
    print(f"{missing} not published, {unknown} could not be checked")
    return 1 if missing or (args.strict and unknown) else 0


if __name__ == "__main__":
    sys.exit(main())
