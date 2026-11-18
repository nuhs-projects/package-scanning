import contextlib
import functools
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import scan  # noqa: E402


def ordered(eco, versions):
    """True if versions are strictly ascending."""
    return all(scan.compare(eco, a, b) < 0 for a, b in zip(versions, versions[1:]))


def vuln(vid, ranges=None, aliases=(), name="demo", eco="PyPI", versions=None,
         severity=None, db_severity=None):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if ranges is not None:
        aff["ranges"] = [{"type": "ECOSYSTEM", "events": ev} for ev in ranges]
    if versions is not None:
        aff["versions"] = versions
    v = {"id": vid, "aliases": list(aliases), "affected": [aff]}
    if severity:
        v["severity"] = [{"type": "CVSS_V3", "score": severity}]
    if db_severity:
        v["database_specific"] = {"severity": db_severity}
    return v


def rng(*pairs):
    return [{k: v} for k, v in pairs]


class VersionOrdering(unittest.TestCase):
    def test_pep440(self):
        self.assertTrue(ordered("PyPI", [
            "1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
            "1.0.post1", "1.0.post2", "1.0.1", "1.1", "2.0", "1!0.1"]))
        self.assertTrue(ordered("PyPI", ["1.0.a1.dev1", "1.0a1", "1.0a1.post1"]))
        self.assertTrue(ordered("PyPI", ["1.0rc1.dev0", "1.0rc1"]))

    def test_pep440_equal(self):
        self.assertEqual(scan.compare("PyPI", "1.0", "1.0.0"), 0)
        self.assertEqual(scan.compare("PyPI", "1.0+local.1", "1.0"), 0)
        self.assertEqual(scan.compare("PyPI", "1.0-1", "1.0.post1"), 0)
        self.assertEqual(scan.compare("PyPI", "1.0c1", "1.0rc1"), 0)
        self.assertTrue(scan.compare("PyPI", "2.10", "2.9") > 0)

    def test_maven(self):
        self.assertTrue(ordered("Maven", [
            "1.0-alpha-1", "1.0-beta-1", "1.0-milestone-1", "1.0-rc-1",
            "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1", "1.1"]))
        self.assertTrue(ordered("Maven", ["2.0.0.RELEASE", "2.0.1"]))
        self.assertTrue(ordered("Maven", ["1.0-a1", "1.0-b1", "1.0-m1", "1.0-cr1"]))
        self.assertTrue(ordered("Maven", ["1.2.3", "1.2.3-jre", "1.2.4"]))
        self.assertTrue(ordered("Maven", ["9.4.50.v20221201", "9.4.51.v20230217",
                                          "9.4.52"]))
        self.assertTrue(ordered("Maven", ["10.1.9", "10.1.40", "10.1.100"]))

    def test_maven_equal(self):
        for a, b in (("1.0", "1.0.0"), ("1", "1.0.0"), ("1.0-ga", "1.0"),
                     ("1.0-final", "1.0"), ("2.0.0.RELEASE", "2.0.0"),
                     ("1.0.0-alpha-1", "1-alpha-1"), ("1.0-cr1", "1.0-rc1")):
            self.assertEqual(scan.compare("Maven", a, b), 0, (a, b))

    def test_maven_dash_is_sublist(self):
        self.assertTrue(ordered("Maven", ["1-1", "1.1"]))
        self.assertTrue(ordered("Maven", ["1.0-sp1", "1.0.1"]))

    def test_maven_unknown_qualifier_after_known(self):
        self.assertTrue(ordered("Maven", ["1.0-sp1", "1.0-foo", "1.0-zzz"]))

    def test_semver(self):
        self.assertTrue(ordered("npm", [
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
            "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1",
            "1.10.0", "2.0.0"]))
        self.assertEqual(scan.compare("npm", "1.0.0+build.1", "1.0.0"), 0)
        self.assertTrue(scan.compare("npm", "1.0.0-alpha", "1.0.0-1") > 0)


class AffectedRanges(unittest.TestCase):
    def multi(self):
        return vuln("GHSA-multi", eco="Maven", name="com.example:lib", ranges=[rng(
            ("introduced", "0"), ("fixed", "2.15.0"),
            ("introduced", "2.16.0"), ("fixed", "2.17.1"),
            ("introduced", "3.0.0"), ("fixed", "3.0.2"))])

    def fix(self, v, version):
        return scan.fix_for(v, "Maven", "com.example:lib", version)

    def test_multi_range_picks_containing_range(self):
        # One range per events list is the OSV norm, but a single list holding
        # several introduced/fixed pairs must work too.
        v = self.multi()
        self.assertEqual(self.fix(v, "2.14.0"), (True, "2.15.0"))
        self.assertEqual(self.fix(v, "2.16.0"), (True, "2.17.1"))
        self.assertEqual(self.fix(v, "2.17.0"), (True, "2.17.1"))
        self.assertEqual(self.fix(v, "3.0.1"), (True, "3.0.2"))
        affected, _ = self.fix(v, "2.15.5")
        self.assertFalse(affected)
        self.assertFalse(self.fix(v, "3.0.2")[0])

    def test_separate_ranges(self):
        v = vuln("X", eco="Maven", name="com.example:lib", ranges=[
            rng(("introduced", "0"), ("fixed", "2.15.0")),
            rng(("introduced", "2.16.0"), ("fixed", "2.17.1"))])
        self.assertEqual(self.fix(v, "2.16.3"), (True, "2.17.1"))
        self.assertEqual(self.fix(v, "1.0"), (True, "2.15.0"))

    def test_last_affected(self):
        v = vuln("X", ranges=[rng(("introduced", "0"), ("last_affected", "1.5"))])
        self.assertEqual(scan.fix_for(v, "PyPI", "demo", "1.5"), (True, None))
        self.assertFalse(scan.fix_for(v, "PyPI", "demo", "1.5.1")[0])

    def test_last_affected_uses_later_fix_if_any(self):
        v = vuln("X", ranges=[rng(("introduced", "0"), ("last_affected", "1.5"),
                                  ("introduced", "2.0"), ("fixed", "2.0.5"))])
        self.assertEqual(scan.fix_for(v, "PyPI", "demo", "1.2"), (True, "2.0.5"))

    def test_versions_list_match(self):
        v = vuln("X", versions=["1.0", "1.1"])
        self.assertEqual(scan.fix_for(v, "PyPI", "demo", "1.1"), (True, None))
        self.assertFalse(scan.fix_for(v, "PyPI", "demo", "1.2")[0])

    def test_package_matching(self):
        v = vuln("X", name="My_Pkg", ranges=[rng(("introduced", "0"), ("fixed", "2"))])
        self.assertTrue(scan.fix_for(v, "PyPI", "my-pkg", "1")[0])
        self.assertFalse(scan.fix_for(v, "PyPI", "other", "1")[0])
        self.assertFalse(scan.fix_for(v, "npm", "my-pkg", "1")[0])


class Severity(unittest.TestCase):
    def test_cvss31(self):
        self.assertEqual(scan.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(scan.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"), 7.2)
        self.assertEqual(scan.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertEqual(scan.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)

    def test_labels(self):
        self.assertEqual(scan.score_label(9.0), "Critical")
        self.assertEqual(scan.score_label(7.0), "High")
        self.assertEqual(scan.score_label(4.0), "Medium")
        self.assertEqual(scan.score_label(0.1), "Low")

    def test_vuln_severity(self):
        v = vuln("X", severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(scan.vuln_severity(v), (9.8, "Critical"))
        v4 = vuln("X", severity="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                  db_severity="MODERATE")
        self.assertEqual(scan.vuln_severity(v4), (None, "Medium"))
        self.assertEqual(scan.vuln_severity(vuln("X", db_severity="HIGH")), (None, "High"))
        self.assertEqual(scan.vuln_severity(vuln("X")), (None, "Unknown"))


FIX2 = rng(("introduced", "0"), ("fixed", "2.0.0"))


class Consolidate(unittest.TestCase):
    def run_one(self, hits, vulns, boot=None):
        return scan.consolidate(hits, vulns, boot)

    def test_alias_dedupe_and_order(self):
        vulns = {
            "GHSA-aaaa-bbbb-cccc": vuln("GHSA-aaaa-bbbb-cccc", [FIX2],
                                        aliases=["CVE-2024-1", "PYSEC-2024-9"]),
            "PYSEC-2024-9": vuln("PYSEC-2024-9", [FIX2], aliases=["CVE-2024-1"]),
        }
        hits = {("PyPI", "demo", "1.0"): ["GHSA-aaaa-bbbb-cccc", "PYSEC-2024-9"]}
        findings, no_fix = self.run_one(hits, vulns)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["advisories"],
                         ["CVE-2024-1", "GHSA-aaaa-bbbb-cccc", "PYSEC-2024-9"])
        self.assertEqual(no_fix, [])

    def test_shared_alias_merges(self):
        vulns = {"A-1": vuln("A-1", [FIX2], aliases=["CVE-1"]),
                 "B-1": vuln("B-1", [FIX2], aliases=["CVE-1"])}
        findings, _ = self.run_one({("PyPI", "demo", "1.0"): ["A-1", "B-1"]}, vulns)
        self.assertEqual(findings[0]["advisories"], ["CVE-1", "A-1", "B-1"])

    def test_request_is_max_across_advisories_and_versions(self):
        vulns = {
            "V1": vuln("V1", [rng(("introduced", "0"), ("fixed", "1.4"))]),
            "V2": vuln("V2", [rng(("introduced", "0"), ("fixed", "1.9"))]),
            "V3": vuln("V3", [rng(("introduced", "0"), ("fixed", "1.6"))]),
        }
        hits = {("PyPI", "demo", "1.2"): ["V1", "V2"],
                ("PyPI", "demo", "1.5"): ["V2", "V3"]}
        f, _ = self.run_one(hits, vulns)
        self.assertEqual(f[0]["request"], "1.9")
        self.assertEqual(f[0]["in_use"], ["1.2", "1.5"])
        self.assertEqual(f[0]["note"], "")

    def test_request_skips_reintroduced_range(self):
        vulns = {
            "A": vuln("A", [rng(("introduced", "0"), ("fixed", "1.2"),
                                 ("introduced", "1.3"), ("fixed", "1.5"))]),
            "B": vuln("B", [rng(("introduced", "0"), ("fixed", "1.4"))]),
        }
        findings, no_fix = self.run_one({("PyPI", "demo", "1.0"): ["A", "B"]}, vulns)
        self.assertEqual(findings[0]["request"], "1.5")
        self.assertEqual(no_fix, [])

    def test_no_valid_fixed_event_is_not_recommended(self):
        vulns = {
            "A": vuln("A", [rng(("introduced", "0"), ("fixed", "1.2"),
                                 ("introduced", "1.3"))]),
            "B": vuln("B", [rng(("introduced", "0"), ("fixed", "1.4"))]),
        }
        findings, no_fix = self.run_one({("PyPI", "demo", "1.0"): ["A", "B"]}, vulns)
        self.assertEqual(findings, [])
        self.assertEqual(no_fix[0]["advisories"], ["A", "B"])

    def test_request_does_not_downgrade_other_installed_version(self):
        vulns = {"A": vuln("A", [rng(("introduced", "0"), ("fixed", "1.2"),
                                      ("introduced", "2.0"), ("fixed", "2.1"))])}
        findings, _ = self.run_one({("PyPI", "demo", "1.0"): ["A"],
                                    ("PyPI", "demo", "2.0"): ["A"]}, vulns)
        self.assertEqual(findings[0]["request"], "2.1")

    def test_clean_installed_version_sets_target_floor(self):
        vulns = {"A": vuln("A", [rng(("introduced", "0"), ("fixed", "1.2"),
                                      ("introduced", "2.0"), ("fixed", "2.1"))])}
        findings, _ = self.run_one({("PyPI", "demo", "1.0"): ["A"],
                                    ("PyPI", "demo", "1.9"): []}, vulns)
        self.assertEqual(findings[0]["request"], "1.9")

    def test_multi_range_end_to_end(self):
        v = vuln("V", eco="Maven", name="com.example:lib", ranges=[
            rng(("introduced", "0"), ("fixed", "2.15.0")),
            rng(("introduced", "2.16.0"), ("fixed", "2.17.1")),
            rng(("introduced", "3.0.0"), ("fixed", "3.0.2"))])
        hits = {("Maven", "com.example:lib", "2.16.1"): ["V"]}
        f, _ = self.run_one(hits, {"V": v})
        self.assertEqual(f[0]["request"], "2.17.1")

    def test_next_major_note(self):
        vulns = {"V": vuln("V", [rng(("introduced", "0"), ("fixed", "2.0.1"))])}
        f, _ = self.run_one({("PyPI", "demo", "1.5"): ["V"]}, vulns)
        self.assertEqual(f[0]["request"], "2.0.1")
        self.assertEqual(f[0]["note"], "update moves beyond 1.x")

    def test_no_fix_split(self):
        vulns = {
            "FIXABLE": vuln("FIXABLE", [FIX2], aliases=["CVE-1"]),
            "NOFIX": vuln("NOFIX", [rng(("introduced", "0"))], aliases=["CVE-2"],
                          db_severity="HIGH"),
        }
        hits = {("PyPI", "demo", "1.0"): ["FIXABLE", "NOFIX"],
                ("PyPI", "solo", "1.0"): ["SOLO"]}
        vulns["SOLO"] = vuln("SOLO", [rng(("introduced", "0"))], name="solo")
        findings, no_fix = self.run_one(hits, vulns)
        self.assertEqual([f["package"] for f in findings], ["demo"])
        self.assertEqual(findings[0]["advisories"], ["CVE-1", "FIXABLE"])
        self.assertEqual({n["package"] for n in no_fix}, {"demo", "solo"})
        demo = next(n for n in no_fix if n["package"] == "demo")
        self.assertEqual(demo["advisories"], ["CVE-2", "NOFIX"])
        self.assertEqual(demo["severity"], "High")
        self.assertEqual(demo["in_use"], ["1.0"])

    def test_sort_by_severity_then_package(self):
        crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vulns = {
            "C": vuln("C", [FIX2], name="zzz", severity=crit),
            "L": vuln("L", [FIX2], name="aaa", db_severity="LOW"),
            "M": vuln("M", [FIX2], name="bbb", db_severity="MODERATE"),
        }
        hits = {("PyPI", "zzz", "1"): ["C"], ("PyPI", "aaa", "1"): ["L"],
                ("PyPI", "bbb", "1"): ["M"]}
        f, _ = self.run_one(hits, vulns)
        self.assertEqual([x["package"] for x in f], ["zzz", "bbb", "aaa"])
        self.assertEqual(f[0]["cvss"], 9.8)
        self.assertEqual(f[1]["severity"], "Medium")

    def test_package_severity_is_max(self):
        vulns = {"A": vuln("A", [FIX2], db_severity="LOW"),
                 "B": vuln("B", [FIX2], db_severity="CRITICAL")}
        f, _ = self.run_one({("PyPI", "demo", "1"): ["A", "B"]}, vulns)
        self.assertEqual(f[0]["severity"], "Critical")

    def test_spring_boot_note(self):
        name = "org.apache.tomcat.embed:tomcat-embed-core"
        v = vuln("V", eco="Maven", name=name,
                 ranges=[rng(("introduced", "0"), ("fixed", "10.1.44"))])
        f, _ = self.run_one({("Maven", name, "10.1.40"): ["V"]}, {"V": v}, boot="3.4.1")
        self.assertIn("managed by Spring Boot 3.4.1", f[0]["note"])
        f, _ = self.run_one({("Maven", name, "10.1.40"): ["V"]}, {"V": v}, boot=None)
        self.assertEqual(f[0]["note"], "")
        other = vuln("W", eco="Maven", name="com.example:lib",
                     ranges=[rng(("introduced", "0"), ("fixed", "1.5"))])
        f, _ = self.run_one({("Maven", "com.example:lib", "1"): ["W"]}, {"W": other},
                            boot="3.4.1")
        self.assertEqual(f[0]["note"], "")

    def test_spring_boot_version_from_entries(self):
        entries = [("Maven", "org.springframework.boot:spring-boot", "3.4.1"),
                   ("Maven", "org.springframework.boot:spring-boot", "3.3.0")]
        self.assertEqual(scan.spring_boot_version(entries), "3.4.1")


class Diff(unittest.TestCase):
    def finding(self, pkg, request="2.0"):
        return {"ecosystem": "PyPI", "package": pkg, "in_use": ["1"], "request": request,
                "note": "", "severity": "High", "cvss": None, "advisories": ["CVE-1"]}

    def test_statuses_and_resolved(self):
        previous = {"findings": [self.finding("old"), self.finding("stay", "3.1")]}
        now = [self.finding("stay"), self.finding("fresh")]
        resolved = scan.diff(now, previous)
        self.assertEqual({f["package"]: f["status"] for f in now},
                         {"stay": "open", "fresh": "new"})
        self.assertEqual(resolved, [{"ecosystem": "PyPI", "package": "old", "request": "2.0"}])

    def test_moved_to_no_fix_is_not_resolved(self):
        previous = {"findings": [self.finding("moved"), self.finding("gone")]}
        no_fix = [{"ecosystem": "PyPI", "package": "moved"}]
        resolved = scan.diff([], previous, no_fix)
        self.assertEqual([r["package"] for r in resolved], ["gone"])

    def test_no_previous(self):
        now = [self.finding("a")]
        self.assertEqual(scan.diff(now, None), [])
        self.assertEqual(now[0]["status"], "new")


class Report(unittest.TestCase):
    def sample(self):
        findings = [
            {"ecosystem": "Maven", "package": "com.example:lib", "in_use": ["1.0"],
             "request": "1.1", "note": "managed by Spring Boot 3.4.1; a newer Spring Boot "
             "patch may bring the fix", "severity": "Critical", "cvss": 9.8,
             "advisories": ["CVE-1", "GHSA-a", "CVE-2", "CVE-3", "CVE-4"], "status": "new"},
            {"ecosystem": "PyPI", "package": "demo", "in_use": ["1.0", "1.1"],
             "request": "1.2", "note": "", "severity": "High", "cvss": None,
             "advisories": ["CVE-9"], "status": "open"},
            {"ecosystem": "npm", "package": "@s/pkg", "in_use": ["1.0.0"],
             "request": "1.0.1", "note": "", "severity": "Low", "cvss": 3.1,
             "advisories": ["GHSA-z"], "status": "new"},
        ]
        no_fix = [{"ecosystem": "PyPI", "package": "stuck", "in_use": ["0.1"],
                   "severity": "Medium", "cvss": None, "advisories": ["CVE-7"]}]
        resolved = [{"ecosystem": "npm", "package": "gone", "request": "2.0.0"}]
        return scan.build_report(findings, no_fix, resolved, "2026-11-18T00:00:00Z")

    def test_counts(self):
        self.assertEqual(self.sample()["counts"],
                         {"findings": 3, "new": 2, "no_fix": 1, "resolved": 1})

    def test_markdown_shape(self):
        md = scan.render_md(self.sample())
        self.assertTrue(md.startswith("# Package update request"))
        self.assertIn("| Package | In use | Request | Severity | Advisories | Status |", md)
        self.assertIn("| com.example:lib | 1.0 | 1.1 | Critical | CVE-1, GHSA-a, CVE-2 +2 | new |", md)
        self.assertIn("| demo | 1.0, 1.1 | 1.2 | High | CVE-9 | open |", md)
        self.assertLess(md.index("## Request list"), md.index("## No fix yet"))
        self.assertLess(md.index("## No fix yet"), md.index("## Resolved since last run"))
        self.assertIn("- PyPI stuck 0.1 (Medium): CVE-7", md)
        self.assertIn("- npm gone (was 2.0.0)", md)
        self.assertIn("managed by Spring Boot 3.4.1", md)

    def test_request_list_order_and_formats(self):
        md = scan.render_md(self.sample())
        block = md.split("```")[1].strip().splitlines()
        self.assertEqual(block, ["com.example:lib:1.1", "demo==1.2", "@s/pkg@1.0.1"])

    def test_empty_report(self):
        md = scan.render_md(scan.build_report([], [], [], "t"))
        self.assertIn("No fixable vulnerabilities.", md)
        self.assertNotIn("## Request list", md)

    def test_size_cap(self):
        findings = [{"ecosystem": "PyPI", "package": f"p{i}", "in_use": ["1"],
                     "request": "2", "note": "", "severity": "High", "cvss": None,
                     "advisories": [f"CVE-2024-{i}-{j}" for j in range(10)],
                     "status": "new"} for i in range(3000)]
        md = scan.render_md_capped(scan.build_report(findings, [], [], "t"))
        self.assertLessEqual(len(md), scan.MD_LIMIT)


class CapAndNetwork(unittest.TestCase):
    def big(self, n=3000):
        findings = [{"ecosystem": "PyPI", "package": f"p{i:05d}", "in_use": ["1"],
                     "request": "2", "note": "", "severity": "Critical" if i < 5 else "Low",
                     "cvss": None, "advisories": [f"CVE-2024-{i}-{j}" for j in range(10)],
                     "status": "new"} for i in range(n)]
        no_fix = [{"ecosystem": "PyPI", "package": "stuck", "in_use": ["0.1"],
                   "severity": "Medium", "cvss": None, "advisories": ["CVE-7"]}]
        return scan.build_report(findings, no_fix, [], "t")

    def test_cap_drops_rows_from_bottom(self):
        md = scan.render_md_capped(self.big())
        self.assertLessEqual(len(md), scan.MD_LIMIT)
        self.assertTrue(md.endswith("\n"))
        self.assertIn("more rows, see report.json", md)
        self.assertLess(md.index("## Request list"), md.index("## PyPI"))
        self.assertIn("p00000==2", md.split("```")[1])
        self.assertIn("p02999==2", md.split("```")[1])  # request list is whole
        self.assertIn("| p00000 |", md)       # highest severity kept
        self.assertNotIn("| p02999 |", md)    # lowest severity dropped
        self.assertIn("- PyPI stuck 0.1 (Medium): CVE-7", md)
        self.assertIn("## Resolved since last run", md)
        table = md.split("## PyPI")[1].split("\n\n")[1]
        self.assertTrue(all(line.startswith("|") and line.endswith("|")
                            for line in table.splitlines()))

    def test_retry_on_timeout_and_bad_json(self):
        calls = []

        class Resp:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return self.body

        def fake(req, timeout=None):
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError("slow")
            if len(calls) == 2:
                return Resp(b"{trunc")
            return Resp(b'{"ok": 1}')

        orig_open, orig_sleep = scan.urllib.request.urlopen, scan.time.sleep
        scan.urllib.request.urlopen, scan.time.sleep = fake, lambda s: None
        try:
            self.assertEqual(scan.http_json("https://example.invalid/x"), {"ok": 1})
            self.assertEqual(len(calls), 3)
            calls.clear()
            orig = scan.RETRIES
            scan.RETRIES = 0
            try:
                with self.assertRaises(TimeoutError):
                    scan.http_json("https://example.invalid/x")
            finally:
                scan.RETRIES = orig
        finally:
            scan.urllib.request.urlopen, scan.time.sleep = orig_open, orig_sleep

    def test_missing_vuln_goes_to_no_fix(self):
        hits = {("PyPI", "demo", "1.0"): ["GONE-1"]}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            vulns = scan.fetch_vulns({"GONE-1"}, tempfile.gettempdir() + "/nonexistent-osv")
        self.assertIn("GONE-1", err.getvalue())
        findings, no_fix = scan.consolidate(hits, vulns)
        self.assertEqual(findings, [])
        self.assertEqual(no_fix[0]["package"], "demo")
        self.assertEqual(no_fix[0]["severity"], "Unknown")
        self.assertEqual(no_fix[0]["advisories"], ["GONE-1"])

    def test_empty_vuln_record_goes_to_no_fix(self):
        f, n = scan.consolidate({("PyPI", "demo", "1.0"): ["E-1"]}, {"E-1": {}})
        self.assertEqual((f, n[0]["advisories"]), ([], ["E-1"]))

    def test_online_rejects_incomplete_and_malformed_batches(self):
        for response in (None, {}, {"results": []}, {"results": [None]},
                         {"results": [{"vulns": [{}]}]},
                         {"results": [{"next_page_token": 7}]}):
            with self.subTest(response=response), mock.patch.object(scan, "http_json", return_value=response):
                with self.assertRaises(ValueError):
                    scan.query_online(["pkg:pypi/demo@1"])

    def test_online_rejects_incomplete_followup_page(self):
        with mock.patch.object(scan, "http_json", side_effect=[
                {"results": [{"next_page_token": "next"}]}, {"results": []}]):
            with self.assertRaises(ValueError):
                scan.query_online(["pkg:pypi/demo@1"])

    def test_online_rejects_missing_or_empty_advisory(self):
        for response in (None, {}, {"id": "OTHER"}, {"id": "V"}, {"id": "V", "affected": []}):
            with self.subTest(response=response), mock.patch.object(scan, "http_json", return_value=response):
                with self.assertRaises(ValueError):
                    scan.fetch_vulns({"V"})

    def test_missing_catalogue_fails_before_report(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileNotFoundError):
                scan.main(["--root", root])
            self.assertFalse(os.path.exists(os.path.join(root, "reports")))

    def test_query_order_is_list_order(self):
        entries = [("PyPI", "zeta", "1.0"), ("PyPI", "alpha", "1.0"),
                   ("PyPI", "zeta", "1.0")]
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "vulns"))
            with open(os.path.join(tmp, "vulns", "V.json"), "w") as f:
                json.dump(vuln("V", [FIX2], name="zeta"), f)
            with open(os.path.join(tmp, "querybatch.json"), "w") as f:
                json.dump({"results": [{"vulns": [{"id": "V"}]}, {}]}, f)
            findings, _ = scan.scan(entries, tmp)
        self.assertEqual([f["package"] for f in findings], ["zeta"])


class Lists(unittest.TestCase):
    def test_purls(self):
        self.assertEqual(scan.purl("PyPI", "pandas", "3.0.5"), "pkg:pypi/pandas@3.0.5")
        self.assertEqual(scan.purl("Maven", "org.apache.tomcat.embed:tomcat-embed-core", "10.1.40"),
                         "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.40")
        self.assertEqual(scan.purl("npm", "@playwright/test", "1.49.0"),
                         "pkg:npm/%40playwright/test@1.49.0")

    def test_parse_lines(self):
        self.assertEqual(scan.parse_line("PyPI", "requests==2.32.3"), ("requests", "2.32.3"))
        self.assertEqual(scan.parse_line("Maven", "g:a:1.0"), ("g:a", "1.0"))
        self.assertEqual(scan.parse_line("npm", "@playwright/test@1.49.0"),
                         ("@playwright/test", "1.49.0"))
        self.assertEqual(scan.parse_line("npm", "ms@2.1.3"), ("ms", "2.1.3"))


class EndToEnd(unittest.TestCase):
    def test_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "root")
            for rel, text in {
                "python/requirements.txt": "demo-app==1.0\nfine==1.0\n",
                "java/dependencies.txt": "com.example:lib:2.16.1\n"
                                         "org.springframework.boot:spring-boot:3.4.1\n"
                                         "org.springframework:spring-web:6.1.0\n",
                "npm/packages.txt": "@scope/pkg@1.0.0\n",
            }.items():
                os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
                with open(os.path.join(root, rel), "w") as f:
                    f.write(text)

            off = os.path.join(tmp, "osv")
            os.makedirs(os.path.join(off, "vulns"))
            vulns = {
                "GHSA-1111-2222-3333": vuln(
                    "GHSA-1111-2222-3333", [FIX2], name="demo-app",
                    aliases=["CVE-2024-0001", "PYSEC-2024-1"],
                    severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                "PYSEC-2024-1": vuln("PYSEC-2024-1", [FIX2], name="demo-app",
                                     aliases=["CVE-2024-0001", "GHSA-1111-2222-3333"]),
                "GHSA-multi": vuln("GHSA-multi", eco="Maven", name="com.example:lib", ranges=[
                    rng(("introduced", "0"), ("fixed", "2.15.0")),
                    rng(("introduced", "2.16.0"), ("fixed", "2.17.1"))],
                    db_severity="HIGH"),
                "GHSA-spring": vuln("GHSA-spring", eco="Maven",
                                    name="org.springframework:spring-web",
                                    ranges=[rng(("introduced", "6.1.0"), ("fixed", "6.1.5"))],
                                    db_severity="MODERATE"),
                "GHSA-npm": vuln("GHSA-npm", eco="npm", name="@scope/pkg",
                                 ranges=[rng(("introduced", "0"))], db_severity="LOW"),
            }
            for vid, v in vulns.items():
                with open(os.path.join(off, "vulns", f"{vid}.json"), "w") as f:
                    json.dump(v, f)
            by_purl = {
                "pkg:pypi/demo-app@1.0": ["GHSA-1111-2222-3333", "PYSEC-2024-1"],
                "pkg:maven/com.example/lib@2.16.1": ["GHSA-multi"],
                "pkg:maven/org.springframework/spring-web@6.1.0": ["GHSA-spring"],
                "pkg:npm/%40scope/pkg@1.0.0": ["GHSA-npm"],
            }
            with open(os.path.join(off, "querybatch.json"), "w") as f:
                json.dump(by_purl, f)

            prev = os.path.join(tmp, "prev.json")
            with open(prev, "w") as f:
                json.dump({"findings": [
                    {"ecosystem": "PyPI", "package": "demo-app", "request": "1.5"},
                    {"ecosystem": "PyPI", "package": "gone", "request": "9.9"}]}, f)

            out = os.path.join(tmp, "out")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = scan.main(["--root", root, "--out", out, "--previous", prev,
                                "--offline-vulns", off])
            self.assertEqual(rc, 0)
            with open(os.path.join(out, "report.json")) as f:
                report = json.load(f)
            with open(os.path.join(out, "report.md")) as f:
                md = f.read()

        by_pkg = {f["package"]: f for f in report["findings"]}
        self.assertEqual(set(by_pkg), {"demo-app", "com.example:lib",
                                       "org.springframework:spring-web"})
        demo = by_pkg["demo-app"]
        self.assertEqual((demo["request"], demo["status"], demo["severity"], demo["cvss"]),
                         ("2.0.0", "open", "Critical", 9.8))
        self.assertEqual(demo["advisories"],
                         ["CVE-2024-0001", "GHSA-1111-2222-3333", "PYSEC-2024-1"])
        self.assertEqual(by_pkg["com.example:lib"]["request"], "2.17.1")
        self.assertEqual(by_pkg["com.example:lib"]["status"], "new")
        self.assertIn("managed by Spring Boot 3.4.1", by_pkg["org.springframework:spring-web"]["note"])
        self.assertEqual([n["package"] for n in report["no_fix"]], ["@scope/pkg"])
        self.assertEqual(report["resolved"],
                         [{"ecosystem": "PyPI", "package": "gone", "request": "9.9"}])
        self.assertEqual(report["counts"],
                         {"findings": 3, "new": 2, "no_fix": 1, "resolved": 1})
        self.assertEqual([f["severity"] for f in report["findings"]],
                         ["Critical", "High", "Medium"])
        self.assertIn("## Maven", md)
        self.assertIn("com.example:lib:2.17.1", md)
        self.assertLess(len(md), scan.MD_LIMIT)


if __name__ == "__main__":
    unittest.main()
