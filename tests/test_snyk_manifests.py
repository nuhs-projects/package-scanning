import contextlib
import io
import json
import os
import sys
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import snyk_manifests as sm  # noqa: E402

NS = {"m": "http://maven.apache.org/POM/4.0.0"}

JAVA = """\
# comment
com.example:demo-lib:1.0
com.example:demo-lib:2.0
com.example:demo-lib:3.0
org.ow2.asm:asm:9.7.1
org.ow2.asm:asm:9.8
com.example:demo-bom:1.5

com.example:a&b:1.0
"""
PYTHON = """\
Demo_Pkg==1.0
Demo_Pkg==2.0
other==0.1
"""
NPM = """\
@demo/scoped@1.2.3
plain@4.5.6
"""
REPOS = "# public\nhttps://repo.example.org/maven2\nhttps://other.example.org/r?a=1&b=2\n"


def run(root, out, *extra):
    with contextlib.redirect_stdout(io.StringIO()):
        return sm.main(["--root", root, "--out", out, *extra])


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = os.path.join(tmp.name, "root")
        self.out = os.path.join(tmp.name, "out")
        for rel, text in (("java/dependencies.txt", JAVA),
                          ("python/requirements.txt", PYTHON),
                          ("npm/packages.txt", NPM),
                          ("public-repos.txt", REPOS)):
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            Path(p).write_text(text)
        self.assertEqual(run(self.root, self.out), 0)

    def read(self, rel):
        return Path(self.out, rel).read_text()


class Splitting(unittest.TestCase):
    def test_split_3_2_1(self):
        entries = [("a", "1"), ("a", "2"), ("a", "3"), ("b", "1"), ("b", "2"),
                   ("c", "1")]
        self.assertEqual(sm.split_versions(entries), [
            [("a", "1"), ("b", "1"), ("c", "1")],
            [("a", "2"), ("b", "2")],
            [("a", "3")]])

    def test_repeated_entry_counts_once(self):
        self.assertEqual(sm.split_versions([("a", "1"), ("a", "1")]),
                         [[("a", "1")]])

    def test_parse_scoped_npm(self):
        self.assertEqual(sm.parse_line("npm", "@a/b@1.0"), ("@a/b", "1.0"))


class Layout(Base):
    def test_manifests_txt(self):
        rows = [r.split("\t") for r in self.read("manifests.txt").splitlines()]
        self.assertEqual(rows, [
            ["java-1", "java-1/pom.xml", "4", ""],
            ["java-2", "java-2/pom.xml", "2", ""],
            ["java-3", "java-3/pom.xml", "1", ""],
            ["python-1", "python-1/poetry.lock", "2", ""],
            ["python-2", "python-2/poetry.lock", "1", ""],
            ["npm-1", "npm-1/package-lock.json", "2", ""]])
        for _, path, _, _ in rows:
            self.assertTrue(os.path.exists(os.path.join(self.out, path)))

    def test_ecosystem_filter(self):
        out = self.out + "-npm"
        run(self.root, out, "--ecosystems", "npm")
        self.assertEqual(Path(out, "manifests.txt").read_text(),
                         "npm-1\tnpm-1/package-lock.json\t2\t\n")
        self.assertFalse(os.path.exists(os.path.join(out, "java-1")))

    def test_deterministic(self):
        other = self.out + "-again"
        run(self.root, other)
        for dirpath, _, files in os.walk(self.out):
            for f in files:
                a = Path(dirpath, f)
                b = Path(other, a.relative_to(self.out))
                self.assertEqual(a.read_bytes(), b.read_bytes(), str(a))


class Pom(Base):
    def test_pom(self):
        root = ET.fromstring(self.read("java-1/pom.xml"))
        text = lambda path: root.find(path, NS).text  # noqa: E731
        self.assertEqual(text("m:groupId"), "com.example")
        self.assertEqual(text("m:artifactId"), "catalogue-java-1")
        self.assertEqual(text("m:version"), "0")
        self.assertEqual(text("m:packaging"), "pom")
        deps = root.findall("m:dependencies/m:dependency", NS)
        got = [(d.find("m:groupId", NS).text, d.find("m:artifactId", NS).text,
                d.find("m:version", NS).text) for d in deps]
        self.assertEqual(got, [("com.example", "a&b", "1.0"),
                               ("com.example", "demo-bom", "1.5"),
                               ("com.example", "demo-lib", "1.0"),
                               ("org.ow2.asm", "asm", "9.7.1")])
        for d in deps:
            ex = d.findall("m:exclusions/m:exclusion", NS)
            self.assertEqual(len(ex), 1)
            self.assertEqual(ex[0].find("m:groupId", NS).text, "*")
            self.assertEqual(ex[0].find("m:artifactId", NS).text, "*")

    def test_pom_type_only_for_pom_artifacts(self):
        root = ET.fromstring(self.read("java-1/pom.xml"))
        types = {d.find("m:artifactId", NS).text:
                 getattr(d.find("m:type", NS), "text", None)
                 for d in root.findall("m:dependencies/m:dependency", NS)}
        self.assertEqual(types, {"a&b": None, "demo-bom": "pom",
                                 "demo-lib": None, "asm": None})

    def test_repositories_and_escaping(self):
        text = self.read("java-1/pom.xml")
        root = ET.fromstring(text)
        repos = [(r.find("m:id", NS).text, r.find("m:url", NS).text)
                 for r in root.findall("m:repositories/m:repository", NS)]
        self.assertEqual(repos, [
            ("public-1", "https://repo.example.org/maven2"),
            ("public-2", "https://other.example.org/r?a=1&b=2")])
        self.assertIn("a&amp;b", text)
        self.assertNotIn("<artifactId>a&b<", text)

    def test_later_manifests(self):
        root = ET.fromstring(self.read("java-3/pom.xml"))
        v = [d.find("m:version", NS).text
             for d in root.findall("m:dependencies/m:dependency", NS)]
        self.assertEqual(v, ["3.0"])


class Python(Base):
    def test_files_parse_with_exact_pins(self):
        pyproject = tomllib.loads(self.read("python-1/pyproject.toml"))
        deps = pyproject["tool"]["poetry"]["dependencies"]
        self.assertEqual(deps, {"python": "^3.8", "demo-pkg": "==1.0",
                                "other": "==0.1"})
        self.assertTrue(pyproject["tool"]["poetry"]["name"])
        self.assertTrue(pyproject["tool"]["poetry"]["version"])
        lock = tomllib.loads(self.read("python-1/poetry.lock"))
        self.assertEqual([(p["name"], p["version"]) for p in lock["package"]],
                         [("demo-pkg", "1.0"), ("other", "0.1")])
        for p in lock["package"]:
            self.assertEqual(p["files"], [])
            self.assertIs(p["optional"], False)
            self.assertNotIn("dependencies", p)
        self.assertEqual(lock["metadata"]["lock-version"], "2.0")
        self.assertIn("content-hash", lock["metadata"])
        self.assertIn("python-versions", lock["metadata"])

    def test_second_manifest(self):
        deps = tomllib.loads(self.read("python-2/pyproject.toml"))
        self.assertEqual(deps["tool"]["poetry"]["dependencies"]["demo-pkg"],
                         "==2.0")


class Npm(Base):
    def test_package_json_and_lock(self):
        pkg = json.loads(self.read("npm-1/package.json"))
        self.assertEqual(pkg["name"], "catalogue-npm-1")
        self.assertEqual(pkg["version"], "0.0.0")
        self.assertEqual(pkg["dependencies"],
                         {"@demo/scoped": "1.2.3", "plain": "4.5.6"})
        lock = json.loads(self.read("npm-1/package-lock.json"))
        self.assertEqual(lock["lockfileVersion"], 3)
        packages = lock["packages"]
        self.assertEqual(packages[""]["dependencies"], pkg["dependencies"])
        self.assertEqual(packages["node_modules/@demo/scoped"], {
            "version": "1.2.3",
            "resolved": "https://registry.npmjs.org/@demo/scoped/-/scoped-1.2.3.tgz"})
        self.assertEqual(packages["node_modules/plain"]["version"], "4.5.6")
        self.assertEqual(len(packages), 3)


if __name__ == "__main__":
    unittest.main()
