import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import sync  # noqa: E402

UV_LOCK = """
version = 1

[[package]]
name = "Requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "typing_extensions"
version = "4.12.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "demo-app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "demo-virtual"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "demo-dir"
version = "0.1.0"
source = { directory = "../x" }

[[package]]
name = "demo-git"
version = "1.0.0"
source = { git = "https://example.com/demo.git" }
"""

REQUIREMENTS = """\
# comment
-r base.txt
--index-url https://example.invalid/simple
Flask_Cors==4.0.0  # trailing comment
requests[socks]==2.32.3 ; python_version >= "3.9"
numpy==1.26.4 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
unpinned>=1.0
loose
wild==1.*
"""

MAVEN_LIST = """
The following files have been resolved:
   org.foo:bar:jar:1.2.3:compile
   io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100:runtime
   org.foo:bar:jar:1.2.3:test
   org.foo:bar:jar:1.2.4:test
   com.example.corp.demo:internal:jar:1.0:compile
   com.example.corp:root:jar:1.0:compile
   org.mod:thing:jar:2.0:compile -- module org.mod.thing [auto]
   org.opt:extra:jar:1.1:runtime (optional)
   org.color:tint:jar:3.0:test\x1b[36m -- module tint\x1b[0;1;33m (auto)\x1b[m
   com.example.corpx:keep:jar:1.0:compile
   none
"""


class NormaliseTest(unittest.TestCase):
    def test_pep503(self):
        self.assertEqual(sync.normalise_pypi("Foo_Bar.baz--Qux"), "foo-bar-baz-qux")
        self.assertEqual(sync.normalise_pypi("requests"), "requests")


class UvLockTest(unittest.TestCase):
    def test_registry_only(self):
        self.assertEqual(
            sync.parse_uv_lock(UV_LOCK),
            {("requests", "2.32.3"), ("typing-extensions", "4.12.2")},
        )


class RequirementsTest(unittest.TestCase):
    def test_pins_only(self):
        self.assertEqual(
            sync.parse_requirements(REQUIREMENTS),
            {("flask-cors", "4.0.0"), ("requests", "2.32.3"), ("numpy", "1.26.4")},
        )


class PackageLockTest(unittest.TestCase):
    def test_entries(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-e2e", "version": "1.0.0"},
                "node_modules/ms": {"version": "2.1.3"},
                "node_modules/@playwright/test": {"version": "1.49.0", "dev": True},
                "node_modules/a/node_modules/ms": {"version": "2.0.0"},
                "node_modules/a/node_modules/@s/b": {"version": "3.0.0"},
                "node_modules/linked": {"resolved": "../demo", "link": True},
                "node_modules/nover": {},
                "node_modules/alias": {"name": "real-name", "version": "1.0.0"},
                "packages/ws": {"name": "demo-workspace", "version": "0.0.1"},
                "node_modules/local": {"version": "1.0.0", "resolved": "file:../local"},
                "node_modules/dir": {"version": "1.0.0", "resolved": "../dir"},
                "node_modules/git": {"version": "1.0.0", "resolved": "git+https://example.invalid/demo.git"},
                "node_modules/git-https": {"version": "1.0.0", "resolved": "https://github.com/example/demo.git"},
                "node_modules/public": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/public/-/public-1.0.0.tgz"},
            },
        }
        self.assertEqual(
            sync.parse_package_lock(json.dumps(lock)),
            {
                ("ms", "2.1.3"),
                ("@playwright/test", "1.49.0"),
                ("ms", "2.0.0"),
                ("@s/b", "3.0.0"),
                ("real-name", "1.0.0"),
                ("public", "1.0.0"),
            },
        )


class MavenTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            sync.parse_maven_list(MAVEN_LIST, ("com.example.corp",)),
            {
                ("org.foo", "bar", "1.2.3"),
                ("org.foo", "bar", "1.2.4"),
                ("io.netty", "netty-transport-native-epoll", "4.1.100"),
                ("org.mod", "thing", "2.0"),
                ("com.example.corpx", "keep", "1.0"),
                ("org.opt", "extra", "1.1"),
                ("org.color", "tint", "3.0"),
            },
        )

    def test_stdout_filter(self):
        stdout = (
            "[INFO] --- dependency:3.7.0:list (default-cli) @ demo ---\n"
            "[INFO] \n"
            "[INFO] The following files have been resolved:\n"
            "[INFO]    org.foo:bar:jar:1.2.3:compile -- module bar\n"
            "[INFO]    none\n"
            "[INFO] Downloading from central: https://example.invalid/x\n"
        )
        self.assertEqual(
            sync.parse_maven_list(sync.maven_stdout_dependencies(stdout)),
            {("org.foo", "bar", "1.2.3")},
        )

    def test_no_prefixes_keeps_all(self):
        groups = {g for g, _, _ in sync.parse_maven_list(MAVEN_LIST)}
        self.assertIn("com.example.corp", groups)

    def test_internal_groups_env(self):
        self.assertEqual(sync.internal_groups({"INTERNAL_GROUPS": "com.a,org.b"}), ("com.a", "org.b"))
        self.assertEqual(sync.internal_groups({}), ())

    def test_project_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ns = 'xmlns="http://maven.apache.org/POM/4.0.0"'
            (root / "pom.xml").write_text(
                f"<project {ns}><parent><groupId>org.springframework.boot</groupId></parent>"
                "<groupId>com.example.app</groupId></project>")
            (root / "mod").mkdir()
            (root / "mod/pom.xml").write_text(
                f"<project {ns}><parent><groupId>com.example.app</groupId></parent>"
                "<artifactId>mod</artifactId></project>")
            (root / "other").mkdir()
            (root / "other/pom.xml").write_text("<project><groupId>org.example.other</groupId></project>")
            (root / "target").mkdir()
            (root / "target/pom.xml").write_text("<project><groupId>ignored.group</groupId></project>")
            self.assertEqual(sync.project_groups(root / "pom.xml"), {"com.example.app", "org.example.other"})

    def test_dedupe_and_sort(self):
        lines = sync.format_lines("maven", sync.parse_maven_list(MAVEN_LIST, ("com.example.corp",)))
        self.assertEqual(lines, sorted(set(lines)))
        self.assertEqual(lines.count("org.foo:bar:1.2.3"), 1)
        self.assertFalse(any(l.startswith("com.example.corp.") or l.startswith("com.example.corp:") for l in lines))


class FormatTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(sync.format_lines("pypi", {("b", "1"), ("a", "2")}), ["a==2", "b==1"])
        self.assertEqual(
            sync.format_lines("npm", {("@s/x", "1.0.0"), ("ms", "2.1.3")}),
            ["@s/x@1.0.0", "ms@2.1.3"],
        )


class SourcesTest(unittest.TestCase):
    def test_parse(self):
        text = "# header\n\nproj/uv.lock  # note\n/abs/pom.xml\n   \n"
        self.assertEqual(
            sync.parse_sources(text, "/root"),
            [Path("/root/proj/uv.lock"), Path("/abs/pom.xml")],
        )

    def test_kind(self):
        self.assertEqual(sync.detect_kind("a/uv.lock"), "uv")
        self.assertEqual(sync.detect_kind("a/requirements-dev.txt"), "requirements")
        self.assertEqual(sync.detect_kind("a/package-lock.json"), "npm")
        self.assertEqual(sync.detect_kind("a/pom.xml"), "maven")

    def test_unknown(self):
        with self.assertRaisesRegex(ValueError, "unknown manifest type"):
            sync.detect_kind("a/Pipfile.lock")


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_writes_three_lists(self):
        proj = self.root / "demo-app"
        proj.mkdir()
        (proj / "uv.lock").write_text(UV_LOCK)
        (proj / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/ms": {"version": "2.1.3"}}})
        )
        (proj / "pom.xml").write_text("<project/>")
        out = self.root / "out"
        with mock.patch.object(sync, "run_maven", return_value=MAVEN_LIST):
            counts = sync.sync(
                [proj / "uv.lock", proj / "package-lock.json", proj / "pom.xml"], out,
                internal=("com.example.corp",),
            )
        self.assertEqual(counts, {"pypi": 2, "maven": 7, "npm": 1})
        self.assertEqual(
            (out / "python/requirements.txt").read_text(),
            "requests==2.32.3\ntyping-extensions==4.12.2\n",
        )
        self.assertEqual((out / "npm/packages.txt").read_text(), "ms@2.1.3\n")
        self.assertTrue((out / "java/dependencies.txt").read_text().endswith("\n"))
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["java", "npm", "python"])

    def test_empty_list_is_empty_file(self):
        out = self.root / "out"
        sync.sync([], out)
        for rel in sync.LIST_FILES.values():
            self.assertEqual((out / rel).read_text(), "")

    def test_no_maven_skips_mvn(self):
        pom = self.root / "pom.xml"
        pom.write_text("<project/>")
        with mock.patch.object(sync, "run_maven") as run:
            sync.sync([pom], self.root / "out", maven=False)
        run.assert_not_called()

    def test_unknown_manifest_errors(self):
        bad = self.root / "Pipfile.lock"
        bad.write_text("{}")
        with self.assertRaises(ValueError):
            sync.sync([bad], self.root / "out")

    def test_missing_manifest_errors(self):
        with self.assertRaises(FileNotFoundError):
            sync.sync([self.root / "uv.lock"], self.root / "out")


if __name__ == "__main__":
    unittest.main()
