"""Scan the library lists against OSV and write one consolidated report.

    python3 scripts/scan.py [--previous PREV_report.json] [--out DIR]
                            [--root DIR] [--offline-vulns DIR] [--snyk DIR]

Reads python/requirements.txt, java/dependencies.txt and npm/packages.txt
under --root (default: the repo root), asks OSV (POST /v1/querybatch, then
GET /v1/vulns/{id} per unique id) which versions in use are affected, and
writes report.json and report.md to --out (default: <root>/reports). Exit
status is 0 even when findings exist; the workflow decides what to do.

--previous   report.json of the last run; each finding becomes "new" or
             "open", and packages that dropped out are listed as resolved.
--offline-vulns DIR
             Read DIR/querybatch.json and DIR/vulns/<id>.json instead of the
             network (tests, debugging). querybatch.json is either the OSV
             response ({"results": [...]}, one entry per query in list order:
             python, java, npm) or a {purl: [ids]} map.
--snyk DIR   Also merge Snyk results: every DIR/*.json is the output of
             `snyk test --json-file-output` for one manifest (an object, or a
             list of objects). A missing or empty DIR, an error object
             (no `vulnerabilities`) or malformed data fails the scan.

Snyk (optional, next to OSV):

* Each Snyk vulnerability becomes an OSV-shaped record (id = Snyk id,
  aliases = CVE + GHSA ids, summary = title, CVSSv3 vector, severity label,
  affected package with ranges parsed from `semver.vulnerable` plus the
  tested version in `versions`), so alias grouping, fix selection and
  severity work unchanged. An OSV record with the same id wins.
* Only vulnerabilities of a library (ecosystem, name, version) that is in the
  lists are kept; transitive dependencies are dropped. The same Snyk id found
  in several manifests is merged into one record.
* Ranges: Maven/pip interval notation ([a,b), [a,b], [a]), operator style
  (>=a <b, <b, <=b, with || alternatives, used by npm and pip). If a range
  cannot be parsed, the tested version is affected and the fix is the lowest
  `fixedIn` above it.
* report.json gets "sources" (["OSV"] or ["OSV", "Snyk"]); report.md names
  them in its header.

Consolidation, per package (not per CVE):

* Advisories are grouped by alias: an OSV id and every id it lists as an
  alias (CVE, GHSA, PYSEC, ...) are one group, and groups that share any id
  merge. A group is shown CVE first, then GHSA, then the rest.
* For each version in use and each advisory, the fixed version is the `fixed`
  event closing the range that contains that version (so an advisory with
  ranges 0..2.15.0, 2.16..2.17.1 and 3.0..3.0.2 yields the right fix for each
  version). If the range has no fixed event (last_affected, limit, open
  ended, or only a `versions` list) the lowest fixed event above the version
  in any range of the advisory provides a candidate; if there is none the
  advisory is "no fix yet" for that version.
  When several ids of one group disagree, the highest fix wins.
* Request (target version) is a listed version or a fixed event at or above
  the versions in use that clears every fixable advisory, including later
  affected ranges. If there is no such target, those advisories are listed
  as no fix. The report flags requests that move to a later major.
* Advisories with no fix for a version in use go to no_fix. A package with
  both kinds appears in findings (fixable ones) and in no_fix (the rest).
* Severity = CVSS v3.x base score computed from the vector (CVSS v4 and
  missing vectors fall back to database_specific.severity); package severity
  is the highest of its advisories.
* Maven artifacts in groups managed by the Spring Boot BOM get a note when
  spring-boot is in the list; the BOM itself is not fetched.

Version ordering is implemented here per ecosystem (stdlib only): PEP 440
subset for PyPI, Maven ComparableVersion semantics, and semver 2.0 for npm.
"""

import argparse
import functools
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

OSV = "https://api.osv.dev"
USER_AGENT = "package-scanning"
TIMEOUT = 30
RETRIES = 3
BATCH = 1000
MD_LIMIT = 60000

LISTS = (
    ("PyPI", "python/requirements.txt"),
    ("Maven", "java/dependencies.txt"),
    ("npm", "npm/packages.txt"),
)

SEV_RANK = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
DB_SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium",
               "MEDIUM": "Medium", "LOW": "Low"}

# Approximation of what spring-boot-dependencies manages.
SPRING_GROUPS = (
    "org.springframework", "org.apache.tomcat.embed", "com.fasterxml.jackson",
    "io.netty", "ch.qos.logback", "org.yaml", "org.apache.logging.log4j",
    "io.projectreactor", "org.hibernate", "io.micrometer", "org.thymeleaf",
    "net.minidev", "com.nimbusds",
)
SPRING_BOOT = "org.springframework.boot:spring-boot"


# --- version ordering ------------------------------------------------------

def _sign(x):
    return (x > 0) - (x < 0)


def _cmp(a, b):
    return _sign((a > b) - (a < b))


PEP440 = re.compile(
    r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
    r"(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d*))?"
    r"(?:-(\d+)|([-_.]?(?:post|rev|r)[-_.]?(\d*)))?"
    r"([-_.]?dev[-_.]?(\d*))?(?:\+.*)?$")
PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1,
             "c": 2, "rc": 2, "pre": 2, "preview": 2}


def pypi_key(v):
    m = PEP440.match(v.strip().lower())
    if not m:
        return None
    epoch, rel, pre, pre_n, post_implicit, post_word, post_n, dev_word, dev_n = m.groups()
    release = tuple(int(x) for x in rel.split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    post = None
    if post_implicit is not None:
        post = int(post_implicit)
    elif post_word is not None:
        post = int(post_n or 0)
    dev = int(dev_n or 0) if dev_word is not None else None
    if pre is None and post is None and dev is not None:
        pre_key = (-1, 0)  # 1.0.dev1 sorts before 1.0a1
    elif pre is None:
        pre_key = (3, 0)
    else:
        pre_key = (PRE_ORDER[pre], int(pre_n or 0))
    return (int(epoch or 0), release, pre_key,
            -1 if post is None else post,
            10 ** 18 if dev is None else dev)


QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
QUAL_ALIAS = {"cr": "rc", "ga": "", "final": "", "release": ""}
SHORT_ALIAS = {"a": "alpha", "b": "beta", "m": "milestone"}


def _is_null(x):
    return x == [] or (isinstance(x, (int, str)) and x in (0, ""))


def _normalize(lst):
    for item in lst:
        if isinstance(item, list):
            _normalize(item)
    while lst and _is_null(lst[-1]):
        lst.pop()


def maven_tokens(v):
    """ComparableVersion item tree: ints, qualifier strings and nested lists.
    '-' and digit/letter switches open a sub-list (after dropping trailing
    zeros), so 1.0.0-alpha-1 == 1-alpha-1 and 1-1 < 1.1 (a number beats a
    list). Trailing null items are stripped, so 1.0 == 1 == 1.0-ga."""
    root = cur = []

    def open_sub():
        nonlocal cur
        while cur and cur[-1] in (0, ""):
            cur.pop()
        new = []
        cur.append(new)
        cur = new

    for dash_idx, part in enumerate(v.lower().strip().split("-")):
        if dash_idx:
            open_sub()
        for dot_part in part.split("."):
            runs = re.findall(r"\d+|\D+", dot_part)
            for i, run in enumerate(runs):
                if i:
                    open_sub()
                if run.isdigit():
                    cur.append(int(run))
                    continue
                if i + 1 < len(runs):
                    run = SHORT_ALIAS.get(run, run)
                cur.append(QUAL_ALIAS.get(run, run))
    _normalize(root)
    return root


def _qual_key(s):
    if s in QUALIFIERS:
        return (0, QUALIFIERS.index(s), "")
    return (1, 0, s)


def _maven_item_cmp(a, b):
    if a is None and b is None:
        return 0
    if a is None:
        return -_maven_item_cmp(b, None)
    if isinstance(a, list):
        if isinstance(b, int):
            return -1
        if isinstance(b, str):
            return 1
        b = [] if b is None else b
        for i in range(max(len(a), len(b))):
            c = _maven_item_cmp(a[i] if i < len(a) else None,
                                b[i] if i < len(b) else None)
            if c:
                return c
        return 0
    if isinstance(a, int):
        if b is None:
            return _sign(a)
        return _cmp(a, b) if isinstance(b, int) else 1
    if b is None:
        return _cmp(_qual_key(a), _qual_key(""))
    if isinstance(b, str):
        return _cmp(_qual_key(a), _qual_key(b))
    return -1


def maven_cmp(a, b):
    return _maven_item_cmp(maven_tokens(a), maven_tokens(b))


def semver_parse(v):
    v = v.strip().lstrip("v").split("+", 1)[0]
    rel, _, pre = v.partition("-")
    try:
        nums = [int(x) for x in rel.split(".")]
    except ValueError:
        return None
    nums += [0] * (3 - len(nums))
    return tuple(nums), (pre.split(".") if pre else None)


def _pre_id_cmp(a, b):
    an, bn = a.isdigit(), b.isdigit()
    if an and bn:
        return _cmp(int(a), int(b))
    if an:
        return -1
    if bn:
        return 1
    return _cmp(a, b)


def semver_cmp(a, b):
    pa, pb = semver_parse(a), semver_parse(b)
    if pa is None or pb is None:
        return maven_cmp(a, b)
    if pa[0] != pb[0]:
        return _cmp(pa[0], pb[0])
    if pa[1] is None or pb[1] is None:
        return _cmp(pa[1] is None, pb[1] is None)
    for x, y in zip(pa[1], pb[1]):
        c = _pre_id_cmp(x, y)
        if c:
            return c
    return _cmp(len(pa[1]), len(pb[1]))


def pypi_cmp(a, b):
    ka, kb = pypi_key(a), pypi_key(b)
    if ka is None or kb is None:
        return maven_cmp(a, b)
    return _cmp(ka, kb)


def compare(eco, a, b):
    if eco == "PyPI":
        return pypi_cmp(a, b)
    if eco == "npm":
        return semver_cmp(a, b)
    return maven_cmp(a, b)


def sort_versions(eco, versions):
    return sorted(set(versions), key=functools.cmp_to_key(
        lambda a, b: compare(eco, a, b) or _cmp(a, b)))


def vmax(eco, versions):
    return sort_versions(eco, versions)[-1]


def major(v):
    m = re.search(r"\d+", v)
    return int(m.group()) if m else 0


# --- affected ranges -------------------------------------------------------

def norm_name(eco, name):
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name


def matching_entries(vuln, eco, name):
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        if (pkg.get("ecosystem", "").split(":")[0] == eco
                and norm_name(eco, pkg.get("name", "")) == norm_name(eco, name)):
            yield aff


def intervals(eco, events):
    """Turn OSV events into (introduced, kind, end) with kind in
    fixed/last/limit/None, after sorting events by version."""
    def key(ev):
        k, v = next(iter(ev.items()))
        return v
    evs = sorted(events, key=functools.cmp_to_key(
        lambda a, b: 0 if key(a) == key(b) else
        (-1 if key(a) == "0" else 1 if key(b) == "0" else
         compare(eco, key(a), key(b)))))
    out, intro = [], None
    for ev in evs:
        kind, v = next(iter(ev.items()))
        if kind == "introduced":
            if intro is None:
                intro = v
        elif kind in ("fixed", "last_affected", "limit"):
            out.append((intro if intro is not None else "0",
                        {"fixed": "fixed", "last_affected": "last",
                         "limit": "limit"}[kind], v))
            intro = None
    if intro is not None:
        out.append((intro, None, None))
    return out


def contains(eco, interval, version):
    intro, kind, end = interval
    if intro != "0" and compare(eco, version, intro) < 0:
        return False
    if kind in ("fixed", "limit"):
        return compare(eco, version, end) < 0
    if kind == "last":
        return compare(eco, version, end) <= 0
    return True


def fix_for(vuln, eco, name, version):
    """(affected, fixed) for one advisory and one version in use."""
    affected, cands, later = False, [], []
    for aff in matching_entries(vuln, eco, name):
        hit = False
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for iv in intervals(eco, rng.get("events", [])):
                if contains(eco, iv, version):
                    affected = hit = True
                    cands.append(iv[2] if iv[1] == "fixed" else None)
                if iv[1] == "fixed" and compare(eco, iv[2], version) > 0:
                    later.append(iv[2])
        if not hit and version in aff.get("versions", []):
            affected = True
            cands.append(None)
    later_min = sort_versions(eco, later)[0] if later else None
    if not affected:
        return False, later_min
    fixed = [c for c in cands if c]
    if None in cands:
        if later_min is None:
            return True, None
        fixed.append(later_min)
    return True, vmax(eco, fixed) if fixed else None


# --- severity --------------------------------------------------------------

CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope else 0.62,
              "H": 0.5 if scope else 0.27}[m["PR"]]
        iss = 1 - ((1 - CVSS3["CIA"][m["C"]]) * (1 - CVSS3["CIA"][m["I"]])
                   * (1 - CVSS3["CIA"][m["A"]]))
        expl = 8.22 * CVSS3["AV"][m["AV"]] * CVSS3["AC"][m["AC"]] * pr \
            * CVSS3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope
              else 6.42 * iss)
    if impact <= 0:
        return 0.0
    total = impact + expl
    return roundup(min((1.08 if scope else 1) * total, 10))


def score_label(score):
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low" if score > 0 else "Unknown"


def vuln_severity(vuln):
    """(score or None, label)."""
    for s in vuln.get("severity", []):
        raw = str(s.get("score", ""))
        score = None
        if raw.startswith("CVSS:3"):
            score = cvss3_score(raw)
        elif not raw.startswith("CVSS:4") and ":" not in raw:
            try:
                score = float(raw)
            except ValueError:
                pass
        if score is not None:
            return score, score_label(score)
    label = DB_SEVERITY.get(
        str((vuln.get("database_specific") or {}).get("severity", "")).upper())
    return None, label or "Unknown"


def worse(a, b):
    """Higher of two (score, label) pairs."""
    ka = (SEV_RANK[a[1]], a[0] if a[0] is not None else -1)
    kb = (SEV_RANK[b[1]], b[0] if b[0] is not None else -1)
    return a if ka >= kb else b


# --- consolidation ---------------------------------------------------------

def label_order(i):
    return (0 if i.startswith("CVE-") else 1 if i.startswith("GHSA-") else 2, i)


class Groups:
    """Union-find over advisory ids so an id and its aliases are one group."""

    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def spring_note(name, boot_version):
    group = name.split(":")[0]
    if (boot_version and group != "org.springframework.boot"
            and any(group == g or group.startswith(g + ".")
                    for g in SPRING_GROUPS)):
        return (f"managed by Spring Boot {boot_version}; "
                "a newer Spring Boot patch may bring the fix")
    return ""


def consolidate_package(eco, name, by_version, vulns, boot_version=None):
    """Return (finding or None, no_fix or None) for one package.
    by_version: {version: [advisory ids]}."""
    groups = Groups()
    labels, sev = {}, {}
    # Offline fixtures may omit records. Keep their IDs in "no fix yet".
    for ids in by_version.values():
        for vid in ids:
            for alias in vulns.get(vid, {}).get("aliases", []):
                groups.union(vid, alias)
    for ids in by_version.values():
        for vid in ids:
            root = groups.find(vid)
            v = vulns.get(vid, {})
            labels.setdefault(root, set()).update([vid, *v.get("aliases", [])])
            sev[root] = worse(sev.get(root, (None, "Unknown")),
                              vuln_severity(v))

    fixable, unfixable = {}, {}  # version -> {root: fixed}, version -> {root}
    for version, ids in by_version.items():
        per_group = {}
        for vid in ids:
            fixed = fix_for(vulns[vid], eco, name, version)[1] if vid in vulns else None
            per_group.setdefault(groups.find(vid), []).append(fixed)
        for root, fixes in per_group.items():
            fixes = [f for f in fixes if f]
            if fixes:
                fixable.setdefault(version, {})[root] = vmax(eco, fixes)
            else:
                unfixable.setdefault(version, set()).add(root)

    # A fix for one installed version can fall in a later affected interval
    # of another advisory. Check candidate fixed events against every record
    # in the fixable groups before recommending one.
    if fixable:
        roots = {r for d in fixable.values() for r in d}
        ids = dict.fromkeys(vid for hits in by_version.values() for vid in hits)
        records = [vulns[vid] for vid in ids if vid in vulns and groups.find(vid) in roots]
        highest_in_use = vmax(eco, by_version)
        candidates = {highest_in_use}
        for v in records:
            for aff in matching_entries(v, eco, name):
                for rng in aff.get("ranges", []):
                    if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                        candidates.update(iv[2] for iv in intervals(eco, rng.get("events", []))
                                          if iv[1] == "fixed")
        minimum = vmax(eco, [highest_in_use] +
                       [f for d in fixable.values() for f in d.values()])
        request = next((c for c in sort_versions(eco, candidates)
                        if compare(eco, c, minimum) >= 0 and
                        all(not fix_for(v, eco, name, c)[0] for v in records)), None)
        if request is None:
            for version, fixes in fixable.items():
                unfixable.setdefault(version, set()).update(fixes)
            fixable = {}

    def describe(roots):
        ordered = sorted(roots, key=lambda r: (
            -SEV_RANK[sev[r][1]], -(sev[r][0] or 0), min(labels[r], key=label_order)))
        adv, top = [], (None, "Unknown")
        for r in ordered:
            adv += [i for i in sorted(labels[r], key=label_order) if i not in adv]
            top = worse(top, sev[r])
        return adv, top

    finding = no_fix = None
    if fixable:
        versions = sort_versions(eco, fixable)
        roots = {r for d in fixable.values() for r in d}
        notes = []
        top_major = major(highest_in_use)
        if major(request) > top_major:
            notes.append(f"update moves beyond {top_major}.x")
        if eco == "Maven" and boot_version:
            notes.append(spring_note(name, boot_version))
        adv, top = describe(roots)
        finding = {
            "ecosystem": eco, "package": name, "in_use": versions,
            "request": request, "note": "; ".join(n for n in notes if n),
            "severity": top[1], "cvss": top[0], "advisories": adv,
        }
    if unfixable:
        roots = set().union(*unfixable.values())
        adv, top = describe(roots)
        no_fix = {"ecosystem": eco, "package": name,
                  "in_use": sort_versions(eco, unfixable),
                  "severity": top[1], "cvss": top[0], "advisories": adv}
    return finding, no_fix


def sort_key(item):
    return (-SEV_RANK[item["severity"]], item["ecosystem"], item["package"])


def consolidate(hits, vulns, boot_version=None):
    """hits: {(ecosystem, package, version): [advisory ids]}."""
    packages = {}
    for (eco, name, version), ids in hits.items():
        packages.setdefault((eco, name), {})[version] = ids
    findings, no_fix = [], []
    for (eco, name), by_version in packages.items():
        if not any(by_version.values()):
            continue
        f, n = consolidate_package(eco, name, by_version, vulns, boot_version)
        if f:
            findings.append(f)
        if n:
            no_fix.append(n)
    return sorted(findings, key=sort_key), sorted(no_fix, key=sort_key)


def diff(findings, previous, no_fix=()):
    """Set status on findings; return the resolved list. A package that
    left findings but is now in no_fix is not resolved."""
    prev = {(f["ecosystem"], f["package"]): f
            for f in (previous or {}).get("findings", [])}
    for f in findings:
        f["status"] = "open" if (f["ecosystem"], f["package"]) in prev else "new"
    now = {(f["ecosystem"], f["package"]) for f in [*findings, *no_fix]}
    return [{"ecosystem": e, "package": p, "request": prev[(e, p)].get("request", "")}
            for (e, p) in sorted(prev) if (e, p) not in now]


def build_report(findings, no_fix, resolved, generated=None, sources=("OSV",)):
    return {
        "generated": generated or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": list(sources),
        "findings": findings, "no_fix": no_fix, "resolved": resolved,
        "counts": {"findings": len(findings),
                   "new": sum(f["status"] == "new" for f in findings),
                   "no_fix": len(no_fix), "resolved": len(resolved)},
    }


# --- report.md -------------------------------------------------------------

def request_line(eco, package, version):
    if eco == "PyPI":
        return f"{package}=={version}"
    return f"{package}@{version}" if eco == "npm" else f"{package}:{version}"


def advisory_label(i):
    """Snyk-only ids have no CVE/GHSA to search for: link the Snyk page."""
    if i.startswith("SNYK-"):
        return f"[{i}](https://security.snyk.io/vuln/{i})"
    return i


def advisories_cell(adv, limit=3):
    shown = ", ".join(advisory_label(i) for i in adv[:limit])
    return shown + (f" +{len(adv) - limit}" if len(adv) > limit else "")


def render_md(report, adv_limit=3, drop=0, extra=None):
    """drop: table rows removed from the bottom (lowest severity; they stay
    in the request list). extra: max items in the no-fix/resolved lists."""
    c = report["counts"]
    out = ["# Package update request", "",
           f"Generated {report['generated']} from "
           f"{' + '.join(report.get('sources', ['OSV']))}. {c['findings']} package(s) to "
           f"request ({c['new']} new), {c['no_fix']} with no fix yet, "
           f"{c['resolved']} resolved since last run.", ""]
    findings = report["findings"]
    if not findings:
        out += ["No fixable vulnerabilities.", ""]
    else:
        # Before the tables so it survives any truncation.
        out += ["## Request list", "", "```"]
        out += [request_line(f["ecosystem"], f["package"], f["request"])
                for f in findings]
        out += ["```", ""]
    shown = findings[:len(findings) - drop]
    for eco, _ in LISTS:
        rows = [f for f in shown if f["ecosystem"] == eco]
        if not rows:
            continue
        out += [f"## {eco}", "",
                "| Package | In use | Request | Severity | Advisories | Status |",
                "| ------- | ------ | ------- | -------- | ---------- | ------ |"]
        for f in rows:
            out.append(f"| {f['package']} | {', '.join(f['in_use'])} | {f['request']} "
                       f"| {f['severity']} | {advisories_cell(f['advisories'], adv_limit)} "
                       f"| {f['status']} |")
        out.append("")
        notes = [f"- {f['package']}: {f['note']}" for f in rows if f["note"]]
        if notes:
            out += ["Notes:", "", *notes, ""]
    if drop:
        out += [f"... {drop} more rows, see report.json", ""]

    def section(title, lines):
        out.extend(["", title, ""])
        if not lines:
            out.append("None.")
            return
        keep = lines if extra is None else lines[:extra]
        out.extend(keep)
        if len(keep) < len(lines):
            out.append(f"... {len(lines) - len(keep)} more, see report.json")

    section("## No fix yet", [
        f"- {n['ecosystem']} {n['package']} {', '.join(n['in_use'])} "
        f"({n['severity']}): {advisories_cell(n['advisories'], adv_limit)}"
        for n in report["no_fix"]])
    section("## Resolved since last run", [
        f"- {r['ecosystem']} {r['package']} (was {r['request']})"
        for r in report["resolved"]])
    return "\n".join(out) + "\n"


def render_md_capped(report):
    """Stay under MD_LIMIT without cutting mid-table: shorten advisories,
    then drop table rows from the bottom, then shorten the trailing lists."""
    for limit in (3, 1):
        md = render_md(report, limit)
        if len(md) <= MD_LIMIT:
            return md
    lo, hi = 0, len(report["findings"])
    while lo < hi:  # smallest number of dropped rows that fits
        mid = (lo + hi) // 2
        if len(render_md(report, 1, mid)) <= MD_LIMIT:
            hi = mid
        else:
            lo = mid + 1
    extra = max(len(report["no_fix"]), len(report["resolved"]))
    md = render_md(report, 1, lo)
    while len(md) > MD_LIMIT and extra > 0:
        extra //= 2
        md = render_md(report, 1, len(report["findings"]), extra)
    return md


# --- lists, OSV access -----------------------------------------------------

def purl(eco, name, version):
    v = urllib.parse.quote(version, safe="")
    if eco == "PyPI":
        return f"pkg:pypi/{urllib.parse.quote(name)}@{v}"
    if eco == "npm":
        return f"pkg:npm/{urllib.parse.quote(name)}@{v}"
    group, artifact = name.split(":", 1)
    return f"pkg:maven/{urllib.parse.quote(group)}/{urllib.parse.quote(artifact)}@{v}"


def parse_line(eco, line):
    if eco == "PyPI":
        name, _, version = line.partition("==")
    elif eco == "Maven":
        name, _, version = line.rpartition(":")
    else:
        name, _, version = line.rpartition("@")
    return name, version


def read_lists(root):
    entries = []
    for eco, rel in LISTS:
        path = os.path.join(root, rel)
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    name, version = parse_line(eco, line)
                    entries.append((eco, name, version))
    return entries


def http_json(url, body=None):
    """GET, or POST when body is given. None on 404."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": USER_AGENT}
    if data:
        headers["Content-Type"] = "application/json"
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code < 500 or attempt == RETRIES:
                raise
        except (OSError, ValueError):
            # URLError, timeouts (also while reading) and truncated JSON.
            if attempt == RETRIES:
                raise
        time.sleep(2 ** attempt)


def query_online(purls):
    """{purl: [ids]} via querybatch, following next_page_token per query."""
    def results(response, expected):
        if not isinstance(response, dict) or not isinstance(response.get("results"), list):
            raise ValueError("malformed OSV batch response")
        rows = response["results"]
        if len(rows) != expected:
            raise ValueError("incomplete OSV batch response")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("vulns", []), list):
                raise ValueError("malformed OSV batch result")
            if any(not isinstance(v, dict) or not isinstance(v.get("id"), str)
                   or not v["id"] for v in row.get("vulns", [])):
                raise ValueError("malformed OSV advisory reference")
            token = row.get("next_page_token")
            if token is not None and (not isinstance(token, str) or not token):
                raise ValueError("malformed OSV page token")
        return rows

    found = {}
    for start in range(0, len(purls), BATCH):
        chunk = purls[start:start + BATCH]
        resp = http_json(f"{OSV}/v1/querybatch",
                         {"queries": [{"package": {"purl": p}} for p in chunk]})
        for p, res in zip(chunk, results(resp, len(chunk))):
            ids = [v["id"] for v in res.get("vulns", [])]
            token = res.get("next_page_token")
            seen = set()
            while token:
                if token in seen:
                    raise ValueError("repeated OSV page token")
                seen.add(token)
                page = results(http_json(f"{OSV}/v1/querybatch", {"queries": [
                    {"package": {"purl": p}, "page_token": token}]}), 1)[0]
                ids += [v["id"] for v in page.get("vulns", [])]
                token = page.get("next_page_token")
            found[p] = ids
    return found


def query_offline(purls, directory):
    with open(os.path.join(directory, "querybatch.json")) as f:
        data = json.load(f)
    if "results" in data:
        return {p: [v["id"] for v in r.get("vulns", [])]
                for p, r in zip(purls, data["results"])}
    return {p: data.get(p, []) for p in purls}


def fetch_vulns(ids, offline=None):
    def one(vid):
        if offline:
            path = os.path.join(offline, "vulns", f"{vid}.json")
            if not os.path.isfile(path):
                return vid, None
            with open(path) as f:
                return vid, json.load(f)
        record = http_json(f"{OSV}/v1/vulns/{urllib.parse.quote(vid)}")
        if (not isinstance(record, dict) or record.get("id") != vid
                or not isinstance(record.get("affected"), list) or not record["affected"]):
            raise ValueError(f"missing or malformed OSV advisory: {vid}")
        return vid, record
    with ThreadPoolExecutor(8) as pool:
        results = dict(pool.map(one, sorted(ids)))
    for vid, v in results.items():
        if not v:
            print(f"warning: no data for {vid}", file=sys.stderr)
    return {k: v for k, v in results.items() if v}


def spring_boot_version(entries):
    versions = [v for e, n, v in entries if e == "Maven" and n == SPRING_BOOT]
    return vmax("Maven", versions) if versions else None


# --- Snyk ------------------------------------------------------------------

SNYK_ECOSYSTEMS = {"maven": "Maven", "pip": "PyPI", "poetry": "PyPI",
                   "npm": "npm", "yarn": "npm"}
SNYK_INTERVAL = re.compile(r"[\[(][^\[\]()]*[\])]")
SNYK_OPERATOR = re.compile(r"^(>=|<=|>|<|=)?\s*([^\s<>=,*]+)$")


def _snyk_alternatives(spec):
    """Split semver.vulnerable (string or list) into alternatives."""
    items = spec if isinstance(spec, list) else [spec]
    out = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError("unparseable")
        text = item.strip()
        if text[:1] in "[(":
            found = SNYK_INTERVAL.findall(text)
            if not found or re.sub(r"[\s,]", "", SNYK_INTERVAL.sub("", text)):
                raise ValueError("unparseable")
            out += found
        else:
            out += [a for a in (x.strip() for x in text.split("||")) if a]
    if not out:
        raise ValueError("unparseable")
    return out


def _snyk_alternative_events(alt):
    """(events, exact version or None) for one alternative."""
    if alt[0] in "[(":
        body = alt[1:-1]
        if "," not in body:
            if alt[0] != "[" or alt[-1] != "]" or not body.strip():
                raise ValueError("unparseable")
            return None, body.strip()
        lo, hi = (x.strip() for x in body.split(",", 1))
        # An exclusive lower bound "(a," is treated as introduced a (slightly
        # wider than Snyk; the tested version is listed in `versions` anyway).
        events = [{"introduced": lo or "0"}]
        if hi:
            events.append({"fixed": hi} if alt[-1] == ")" else {"last_affected": hi})
        return events, None
    lo, hi, exact = None, None, None
    for token in alt.replace(",", " ").split():
        m = SNYK_OPERATOR.match(token)
        if not m:
            raise ValueError("unparseable")
        op, ver = m.groups()
        if not ver[0].isdigit() or re.search(r"(^|\.)[xX]$", ver):
            raise ValueError("unparseable")
        if op in (None, "="):
            if exact is not None:
                raise ValueError("unparseable")
            exact = ver
        elif op in (">=", ">"):  # ">a" is treated as introduced a
            lo = ver
        else:
            hi = (ver, "fixed" if op == "<" else "last_affected")
    if exact is not None and (lo or hi):
        raise ValueError("unparseable")
    if exact is not None:
        return None, exact
    if lo is None and hi is None:
        raise ValueError("unparseable")
    events = [{"introduced": lo or "0"}]
    if hi:
        events.append({hi[1]: hi[0]})
    return events, None


def snyk_ranges(eco, spec, version, fixed_in=()):
    """(ranges, versions) in OSV shape for one Snyk vulnerability."""
    versions = [version]
    try:
        ranges = []
        for alt in _snyk_alternatives(spec):
            events, exact = _snyk_alternative_events(alt)
            if exact:
                versions.append(exact)
            else:
                ranges.append({"type": "ECOSYSTEM", "events": events})
        return ranges, list(dict.fromkeys(versions))
    except ValueError:
        above = [v for v in fixed_in if isinstance(v, str)
                 and compare(eco, v, version) > 0]
        events = [{"introduced": version}]
        if above:
            events.append({"fixed": sort_versions(eco, above)[0]})
        return [{"type": "ECOSYSTEM", "events": events}], versions


def snyk_record(v, eco):
    """OSV-shaped record for one Snyk vulnerability."""
    ids = v.get("identifiers") or {}
    aliases = [a for k in ("CVE", "GHSA") for a in (ids.get(k) or [])
               if isinstance(a, str)]
    semver = v.get("semver") or {}
    fixed_in = v.get("fixedIn") or []
    ranges, versions = snyk_ranges(eco, semver.get("vulnerable"), v["version"],
                                   fixed_in if isinstance(fixed_in, list) else [])
    rec = {"id": v["id"], "aliases": list(dict.fromkeys(aliases)),
           "summary": v.get("title", ""),
           "affected": [{"package": {"ecosystem": eco, "name": v["packageName"]},
                         "ranges": ranges, "versions": versions}]}
    if isinstance(v.get("CVSSv3"), str) and v["CVSSv3"]:
        rec["severity"] = [{"type": "CVSS_V3", "score": v["CVSSv3"]}]
    if isinstance(v.get("severity"), str):
        rec["database_specific"] = {"severity": v["severity"].upper()}
    return rec


def _merge_snyk(into, rec):
    for aff in rec["affected"]:
        key = (aff["package"]["ecosystem"], norm_name(aff["package"]["ecosystem"],
                                                       aff["package"]["name"]))
        for old in into["affected"]:
            p = old["package"]
            if (p["ecosystem"], norm_name(p["ecosystem"], p["name"])) == key:
                for r in aff["ranges"]:
                    if r not in old["ranges"]:
                        old["ranges"].append(r)
                old["versions"] = list(dict.fromkeys(old["versions"] + aff["versions"]))
                break
        else:
            into["affected"].append(aff)
    into["aliases"] = list(dict.fromkeys(into["aliases"] + rec["aliases"]))


def load_snyk(directory, entries):
    """(hits, vulns) from DIR/*.json, restricted to (and keyed by) the list
    entries. Raises on a missing/empty directory, error output or bad data."""
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Snyk directory not found: {directory}")
    files = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    if not files:
        raise ValueError(f"no Snyk results (*.json) in {directory}")
    index = {(e, norm_name(e, n), v): (e, n, v) for e, n, v in entries}
    hits, vulns = {}, {}
    for fname in files:
        with open(os.path.join(directory, fname)) as f:
            try:
                data = json.load(f)
            except ValueError as err:
                raise ValueError(f"{fname}: not valid JSON: {err}") from None
        for doc in data if isinstance(data, list) else [data]:
            if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
                msg = doc.get("error") if isinstance(doc, dict) else None
                raise ValueError(f"{fname}: Snyk error or malformed output"
                                 + (f": {msg}" if isinstance(msg, str) else ""))
            top = doc.get("packageManager")
            for v in doc["vulnerabilities"]:
                if (not isinstance(v, dict) or not isinstance(v.get("id"), str)
                        or not isinstance(v.get("packageName"), str)
                        or not isinstance(v.get("version"), str)):
                    raise ValueError(f"{fname}: malformed Snyk vulnerability")
                pm = v.get("packageManager") or top
                eco = SNYK_ECOSYSTEMS.get(pm) if isinstance(pm, str) else None
                if not eco:
                    raise ValueError(f"{fname}: unknown Snyk packageManager {pm!r}")
                entry = index.get((eco, norm_name(eco, v["packageName"]), v["version"]))
                if entry is None:
                    continue  # transitive dependency
                rec = snyk_record(v, eco)
                if rec["id"] in vulns:
                    _merge_snyk(vulns[rec["id"]], rec)
                else:
                    vulns[rec["id"]] = rec
                if rec["id"] not in hits.setdefault(entry, []):
                    hits[entry].append(rec["id"])
    return hits, vulns


def scan(entries, offline=None, snyk=None):
    purls = {e: purl(*e) for e in entries}
    unique = list(dict.fromkeys(purls.values()))  # list order, deduped
    by_purl = query_offline(unique, offline) if offline else query_online(unique)
    hits = {e: by_purl.get(p, []) for e, p in purls.items()}
    vulns = fetch_vulns({i for ids in hits.values() for i in ids}, offline)
    if snyk:
        s_hits, s_vulns = load_snyk(snyk, entries)
        for vid, rec in s_vulns.items():
            vulns.setdefault(vid, rec)  # an OSV record with the same id wins
        for entry, ids in s_hits.items():
            hits[entry] += [i for i in ids if i not in hits[entry]]
    return consolidate(hits, vulns, spring_boot_version(entries))


def main(argv=None):
    root_default = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--previous", help="report.json of the previous run")
    ap.add_argument("--out", help="output directory (default: <root>/reports)")
    ap.add_argument("--root", default=root_default, help="repo root holding the lists")
    ap.add_argument("--offline-vulns", help="read OSV data from this directory")
    ap.add_argument("--snyk", help="directory of `snyk test --json-file-output` files")
    args = ap.parse_args(argv)

    previous = None
    if args.previous and os.path.isfile(args.previous):
        with open(args.previous) as f:
            previous = json.load(f)

    entries = read_lists(args.root)
    findings, no_fix = scan(entries, args.offline_vulns, args.snyk)
    resolved = diff(findings, previous, no_fix)
    report = build_report(findings, no_fix, resolved,
                          sources=["OSV", "Snyk"] if args.snyk else ["OSV"])

    out = args.out or os.path.join(args.root, "reports")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    with open(os.path.join(out, "report.md"), "w") as f:
        f.write(render_md_capped(report))
    c = report["counts"]
    print(f"scanned {len(entries)} libraries: {c['findings']} to request "
          f"({c['new']} new), {c['no_fix']} no fix, {c['resolved']} resolved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
