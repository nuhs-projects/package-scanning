#!/usr/bin/env python3
"""Is each requested version installable from the package registry?

Run locally, in an environment that holds the registry settings (GitHub
Actions cannot reach the registry):

    python3 scripts/check_registry.py [--report reports/report.json]
    python3 scripts/check_registry.py --constraints

For every finding in report.json this requests the target version from the
registry and records one of:

    available    200
    quarantined  403 (the registry blocks the version by policy)
    not cached   404
    error        anything else, or the request failed

It sets "registry" on each finding in report.json, replaces the "Registry availability"
section of report.md, and adds the purls of quarantined versions to
quarantine/known.txt. `--constraints` prints a uv `constraint-dependencies`
line for each PyPI version in known.txt and does no network access.

Configuration comes from the environment only:

    PyPI   UV_DEFAULT_INDEX ("name=URL" or URL), UV_INDEX_<NAME>_USERNAME/_PASSWORD
    Maven  the settings file named by `-s FILE` in MAVEN_ARGS: first <mirror>
           (else <repository>) <url>, and the matching <server> credentials
    npm    the file named by NPM_CONFIG_USERCONFIG: registry=, _auth=/_authToken=

Credentials are sent only as an Authorization header and are never printed.
Output is package, version and status: no URLs.
"""

import argparse
import base64
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 30
HEADING = "## Registry availability"
MAX_MD = 60000

AVAILABLE = "available"
QUARANTINED = "quarantined"
NOT_CACHED = "not cached"
ERROR = "error"


# --- status ---------------------------------------------------------------

def classify(code):
    """Map an HTTP status to an availability status."""
    return {200: AVAILABLE, 403: QUARANTINED, 404: NOT_CACHED}.get(code, ERROR)


# --- URL builders ---------------------------------------------------------

def normalise_pypi(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_url(index, name):
    """Simple index page of one project (PEP 503)."""
    return f"{index.rstrip('/')}/{normalise_pypi(name)}/"


def maven_url(repo, package, version):
    """The .pom of one version: the smallest file every artifact has."""
    group, artifact = package.split(":", 1)
    path = group.replace(".", "/")
    return f"{repo.rstrip('/')}/{path}/{artifact}/{version}/{artifact}-{version}.pom"


def npm_url(registry, name):
    """Package metadata; the slash of a scoped name is encoded."""
    return f"{registry.rstrip('/')}/{urllib.parse.quote(name, safe='@').replace('/', '%2F')}"


# --- HTTP -----------------------------------------------------------------

def basic_auth(user, password):
    if user is None:
        return None
    token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
    return f"Basic {token}"


def http(url, auth=None, method="GET"):
    """Return (status, body). Status 0 means the request failed.

    The exception text is dropped on purpose: it can contain the URL.
    """
    req = urllib.request.Request(url, method=method)
    if auth:
        # Unredirected: KeepAuthSameOrigin decides whether a redirect keeps it.
        req.add_unredirected_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read() if method == "GET" else b""
            return resp.status, body
    except urllib.error.HTTPError as err:
        return err.code, b""
    except (urllib.error.URLError, OSError, ValueError):
        return 0, b""


def origin(url):
    """(scheme, host, port) with the default port filled in."""
    parts = urllib.parse.urlsplit(url)
    port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme, (parts.hostname or "").lower(), port


def same_origin(a, b):
    """Credentials go only to the same scheme, host and port."""
    return origin(a) == origin(b)


class KeepAuthSameOrigin(urllib.request.HTTPRedirectHandler):
    """Re-add Authorization on a redirect only when the origin is unchanged."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        auth = req.get_header("Authorization")
        if new is not None and auth and same_origin(req.full_url, newurl):
            new.add_unredirected_header("Authorization", auth)
        return new


# --- per-ecosystem checks ---------------------------------------------------

_SDIST_EXT = re.compile(r"\.(tar\.gz|tar\.bz2|tar\.xz|zip|egg)$")


def pypi_file_version(filename, normname):
    """Version of a wheel or sdist file name belonging to `normname`, or None."""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) >= 2 and normalise_pypi(parts[0]) == normname:
            return parts[1].lower()
        return None
    base = _SDIST_EXT.sub("", filename)
    if base == filename:
        return None
    for i, ch in enumerate(base):
        if ch == "-" and normalise_pypi(base[:i]) == normname:
            return base[i + 1:].lower()
    return None


def pypi_links(html, page_url, name):
    """Absolute links on a simple index page that are files of `name`."""
    normname = normalise_pypi(name)
    found = []
    for href in re.findall(r'href="([^"]+)"', html):
        clean = href.split("#", 1)[0].split("?", 1)[0]
        filename = urllib.parse.unquote(clean.rsplit("/", 1)[-1])
        version = pypi_file_version(filename, normname)
        if version is not None:
            found.append((version, urllib.parse.urljoin(page_url, clean)))
    return found


def check_pypi(index, auth, name, version):
    page = pypi_url(index, name)
    code, body = http(page, auth)
    if code != 200:
        return classify(code)
    links = [url for v, url in pypi_links(body.decode("utf-8", "replace"), page, name)
             if v == version.lower()]
    if not links:
        return NOT_CACHED
    # A quarantined file is listed but refuses the download.
    file_url = links[0]
    code, _ = http(file_url, auth if same_origin(page, file_url) else None, "HEAD")
    return classify(code)


def check_maven(repo, auth, package, version):
    code, _ = http(maven_url(repo, package, version), auth, "HEAD")
    return classify(code)


def check_npm(registry, auth, name, version):
    code, body = http(npm_url(registry, name), auth)
    if code != 200:
        return classify(code)
    try:
        meta = json.loads(body)
    except ValueError:
        return ERROR
    info = (meta.get("versions") or {}).get(version)
    if info is None:
        return NOT_CACHED
    tarball = (info.get("dist") or {}).get("tarball")
    if not tarball:
        return AVAILABLE
    # The metadata can be served while the tarball is quarantined.
    code, _ = http(tarball, auth if same_origin(registry, tarball) else None, "HEAD")
    return classify(code)


# --- configuration ----------------------------------------------------------

def pypi_config(env):
    value = env.get("UV_DEFAULT_INDEX", "")
    if not value:
        return None
    name, sep, url = value.partition("=")
    if not sep or "://" in name:
        name, url = "", value
    auth = None
    if name:
        key = re.sub(r"[^A-Z0-9]", "_", name.upper())
        user = env.get(f"UV_INDEX_{key}_USERNAME")
        if user is not None:
            auth = basic_auth(user, env.get(f"UV_INDEX_{key}_PASSWORD"))
    return url, auth


def local(tag):
    return tag.rsplit("}", 1)[-1]


def child_text(element, name):
    for child in element:
        if local(child.tag) == name:
            return (child.text or "").strip()
    return None


def expand(value, pattern, env):
    """Replace ${...} references with environment values (empty if unset)."""
    if value is None:
        return None
    return re.sub(pattern, lambda m: env.get(m.group(1), ""), value)


def expand_path(path):
    return os.path.expandvars(os.path.expanduser(path))


def parse_settings(path, env=None):
    """Return (repo URL, Authorization header) from a Maven settings file."""
    env = os.environ if env is None else env

    def text(element, name):
        return expand(child_text(element, name), r"\$\{env\.([^}]+)\}", env)

    root = ET.parse(path).getroot()
    elements = list(root.iter())
    chosen = None
    for kind in ("mirror", "repository"):
        for el in elements:
            if local(el.tag) == kind and text(el, "url"):
                chosen = el
                break
        if chosen is not None:
            break
    if chosen is None:
        return None
    servers = {child_text(el, "id"): el for el in elements if local(el.tag) == "server"}
    # No server with the repository's id means no credentials, not someone else's.
    server = servers.get(child_text(chosen, "id"))
    auth = None
    if server is not None:
        auth = basic_auth(text(server, "username"), text(server, "password"))
    return text(chosen, "url"), auth


def settings_file(maven_args):
    args = shlex.split(maven_args or "")
    for i, arg in enumerate(args):
        if arg in ("-s", "--settings") and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--settings="):
            return arg.split("=", 1)[1]
        if arg.startswith("-s") and len(arg) > 2 and not arg.startswith("--"):
            return arg[2:]
    return None


def maven_config(env):
    path = settings_file(env.get("MAVEN_ARGS"))
    if not path:
        return None
    try:
        return parse_settings(expand_path(path), env)
    except (OSError, ET.ParseError):
        return None


def npm_config(env):
    path = env.get("NPM_CONFIG_USERCONFIG")
    if not path:
        return None
    try:
        lines = Path(expand_path(path)).read_text().splitlines()
    except OSError:
        return None
    registry = auth = None
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if not sep or key.startswith(("#", ";")):
            continue
        key, value = key.strip(), value.strip().strip("\"'")
        value = expand(value, r"\$\{([^}]+)\}", env)
        if key == "registry":
            registry = value
        elif key.endswith("_auth") and not auth:
            auth = f"Basic {value}"
        elif key.endswith("_authToken") and not auth:
            auth = f"Bearer {value}"
    return (registry, auth) if registry else None


# --- purls and the known list ----------------------------------------------

def request_parts(finding):
    """(name, version) of the request in the form each checker takes."""
    return finding["package"], finding["request"]


def to_purl(finding):
    eco, package, version = finding["ecosystem"], finding["package"], finding["request"]
    if eco == "PyPI":
        return f"pkg:pypi/{normalise_pypi(package)}@{version}"
    if eco == "Maven":
        group, artifact = package.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{version}"
    if eco == "npm":
        return f"pkg:npm/{urllib.parse.quote(package, safe='/')}@{version}"
    raise ValueError(eco)


def merge_known(path, purls):
    path = Path(path)
    current = set(path.read_text().split()) if path.exists() else set()
    merged = sorted(current | set(purls))
    path.write_text("".join(f"{p}\n" for p in merged))
    return len(merged) - len(current)


def constraints(known_text):
    """uv constraint-dependencies lines for the PyPI purls in known.txt."""
    lines = []
    for purl in sorted(known_text.split()):
        m = re.match(r"^pkg:pypi/([^@]+)@(.+)$", purl)
        if m:
            lines.append(f'"{m.group(1)}!={m.group(2)}",')
    return lines


# --- report -----------------------------------------------------------------

def request_line(finding):
    eco, package, version = finding["ecosystem"], finding["package"], finding["request"]
    return {"PyPI": f"{package}=={version}", "Maven": f"{package}:{version}",
            "npm": f"{package}@{version}"}[eco]


def registry_section(findings, keep=None):
    """The section for the first `keep` findings (all by default)."""
    rows = [f for f in findings if f.get("request")]
    shown = rows if keep is None else rows[:keep]
    out = [HEADING, "", "| Package | Request | Registry |", "| ------- | ------- | --- |"]
    for f in shown:
        out.append(f"| {f['package']} | {f['request']} | {f.get('registry', '')} |")
    if len(shown) < len(rows):
        out.append(f"... {len(rows) - len(shown)} more, see report.json")
    missing = [request_line(f) for f in shown if f.get("registry") != AVAILABLE]
    out += ["", "Still to request (not available):", "", "```"]
    out += missing or ["(none)"]
    out += ["```", ""]
    return "\n".join(out)


def update_markdown(path, findings):
    path = Path(path)
    text = path.read_text() if path.exists() else ""
    head = text.split(HEADING, 1)[0].rstrip("\n")
    prefix = head + "\n\n" if head else ""
    count = len([f for f in findings if f.get("request")])
    # GitHub rejects an issue body over 65536 characters; stay well under.
    for keep in range(count, -1, -1):
        section = registry_section(findings, keep)
        if len(prefix) + len(section) <= MAX_MD:
            break
    path.write_text(prefix + section)


def check_finding(finding, config):
    eco = finding["ecosystem"]
    cfg = config.get(eco)
    if cfg is None:
        return ERROR
    url, auth = cfg
    name, version = request_parts(finding)
    if eco == "PyPI":
        return check_pypi(url, auth, name, version)
    if eco == "Maven":
        return check_maven(url, auth, name, version)
    if eco == "npm":
        return check_npm(url, auth, name, version)
    return ERROR


def run(report_path, known_path, env):
    report_path = Path(report_path)
    report = json.loads(report_path.read_text())
    config = {"PyPI": pypi_config(env), "Maven": maven_config(env), "npm": npm_config(env)}
    for eco, cfg in config.items():
        if cfg is None and any(f["ecosystem"] == eco for f in report["findings"]):
            print(f"no {eco} configuration in the environment", file=sys.stderr)
    quarantined = []
    for f in report["findings"]:
        if not f.get("request"):
            continue
        f["registry"] = check_finding(f, config)
        print(f"{f['package']} {f['request']}: {f['registry']}")
        if f["registry"] == QUARANTINED:
            quarantined.append(to_purl(f))
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    update_markdown(report_path.with_suffix(".md"), report["findings"])
    if quarantined:
        merge_known(known_path, quarantined)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--report", default=str(ROOT / "reports" / "report.json"))
    parser.add_argument("--constraints", action="store_true",
                        help="print uv constraint-dependencies lines from quarantine/known.txt")
    args = parser.parse_args()
    urllib.request.install_opener(urllib.request.build_opener(KeepAuthSameOrigin))
    known = ROOT / "quarantine" / "known.txt"
    if args.constraints:
        for line in constraints(known.read_text() if known.exists() else ""):
            print(line)
        return 0
    run(args.report, known, os.environ)
    return 0


if __name__ == "__main__":
    sys.exit(main())
