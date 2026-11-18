import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_lists  # noqa: E402


def run(name, lines, internal=()):
    return check_lists.check_lines(name, lines, check_lists.LISTS[name], internal)


class CheckLines(unittest.TestCase):
    def test_good_lists(self):
        self.assertEqual(run("python/requirements.txt", ["a-b==1.0", "requests==2.32.3"]), [])
        self.assertEqual(run("java/dependencies.txt", ["com.example:lib:1.2.3"]), [])
        self.assertEqual(run("npm/packages.txt", ["@scope/pkg@1.0.0", "ms@2.1.3"]), [])

    def test_bad_format(self):
        self.assertTrue(run("python/requirements.txt", ["Requests==1.0"]))
        self.assertTrue(run("python/requirements.txt", ["requests>=1.0"]))
        self.assertTrue(run("java/dependencies.txt", ["a:b"]))
        self.assertTrue(run("npm/packages.txt", ["ms"]))

    def test_unsorted(self):
        problems = run("python/requirements.txt", ["b==1", "a==1"])
        self.assertEqual(len(problems), 1)
        self.assertIn("not sorted", problems[0])

    def test_duplicate(self):
        problems = run("npm/packages.txt", ["ms@1.0.0", "ms@1.0.0"])
        self.assertEqual(len(problems), 1)
        self.assertIn("duplicate", problems[0])

    def test_internal_artifact(self):
        internal = ("com.example.corp",)
        problems = run("java/dependencies.txt", ["com.example.corp.core:lib:1.0"], internal)
        self.assertEqual(len(problems), 1)
        self.assertIn("internal", problems[0])
        self.assertEqual(run("java/dependencies.txt", ["com.example.corpx:lib:1.0"], internal), [])
        self.assertEqual(run("java/dependencies.txt", ["com.example.corp.core:lib:1.0"]), [])

    def test_internal_groups_env(self):
        env = {"INTERNAL_GROUPS": "com.a, org.b  net.c"}
        self.assertEqual(check_lists.internal_groups(env), ("com.a", "org.b", "net.c"))
        self.assertEqual(check_lists.internal_groups({}), ())


class CheckRoot(unittest.TestCase):
    def test_absent_files_are_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(check_lists.check_root(tmp), [])

    def test_missing_trailing_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "npm").mkdir()
            (Path(tmp) / "npm/packages.txt").write_text("ms@1.0.0")
            self.assertEqual(len(check_lists.check_root(tmp)), 1)

    def test_reports_bad_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "python").mkdir()
            (Path(tmp) / "python/requirements.txt").write_text("ok==1\nBad==2\n")
            self.assertEqual(len(check_root_problems(tmp)), 1)


def check_root_problems(tmp):
    return check_lists.check_root(tmp)


if __name__ == "__main__":
    unittest.main()
