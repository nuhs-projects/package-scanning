import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_public  # noqa: E402


class ReadReposTest(unittest.TestCase):
    def test_reads_and_strips_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "public-repos.txt"
            path.write_text("# comment\nhttps://a.example/maven2\n\nhttps://b.example/repo/\n")
            self.assertEqual(
                check_public.read_repos(path),
                ["https://a.example/maven2", "https://b.example/repo"],
            )

    def test_missing_file_falls_back_to_central(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                check_public.read_repos(Path(tmp) / "nope.txt"), [check_public.CENTRAL]
            )


class EntriesTest(unittest.TestCase):
    def test_reads_three_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "python").mkdir()
            (root / "java").mkdir()
            (root / "npm").mkdir()
            (root / "python/requirements.txt").write_text("requests==2.32.3\n")
            (root / "java/dependencies.txt").write_text("org.foo:bar:1.2.3\n")
            (root / "npm/packages.txt").write_text("@scope/pkg@1.0.0\n")
            self.assertEqual(
                check_public.entries(root),
                [
                    ("PyPI", "requests", "2.32.3"),
                    ("Maven", "org.foo:bar", "1.2.3"),
                    ("npm", "@scope/pkg", "1.0.0"),
                ],
            )

    def test_absent_lists_are_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(check_public.entries(Path(tmp)), [])


class StatusTest(unittest.TestCase):
    def test_exact_versions_and_statuses(self):
        for func, name, url in (
            (check_public.pypi_status, "demo-package", "https://pypi.org/pypi/demo-package/1.2.3/json"),
            (check_public.npm_status, "@demo/pkg", "https://registry.npmjs.org/@demo/pkg/1.2.3"),
        ):
            for code, expected in ((200, "published"), (404, "not published"),
                                   (410, "not published"), (0, "unknown"),
                                   (429, "unknown"), (500, "unknown"), (403, "unknown")):
                with self.subTest(name=name, code=code):
                    with mock.patch.object(
                        check_public, "get", return_value=(code, b'{"version":"1.2.3"}')
                    ) as get:
                        self.assertEqual(func(name, "1.2.3", 1), expected)
                        if func is check_public.npm_status:
                            get.assert_called_once_with(url, 1, read_body=True)
                        else:
                            get.assert_called_once_with(url, 1)

    def test_npm_dist_tag_is_not_an_exact_version(self):
        with mock.patch.object(check_public, "get", return_value=(200, b'{"version":"1.2.3"}')):
            self.assertEqual(check_public.npm_status("demo-package", "latest", 1), "not published")
        with mock.patch.object(check_public, "get", return_value=(200, b"{}")):
            self.assertEqual(check_public.npm_status("demo-package", "1.2.3", 1), "unknown")

    def test_maven_tries_every_repo(self):
        repos = ["https://a.example/m2", "https://b.example/m2"]
        with mock.patch.object(check_public, "head", return_value=404):
            self.assertEqual(check_public.maven_status("org.foo", "bar", "1.0", repos, 1),
                             "not published")
        with mock.patch.object(check_public, "head", return_value=200) as head:
            self.assertEqual(check_public.maven_status("org.foo", "bar", "1.0", repos, 1),
                             "published")
            self.assertEqual(head.call_count, 1)
        with mock.patch.object(check_public, "head", side_effect=[404, 429]):
            self.assertEqual(check_public.maven_status("org.foo", "bar", "1.0", repos, 1),
                             "unknown")
        with mock.patch.object(check_public, "head", return_value=0):
            self.assertEqual(check_public.maven_status("org.foo", "bar", "1.0", repos, 1),
                             "unknown")


class CheckTest(unittest.TestCase):
    def test_strict_fails_on_unknown(self):
        with mock.patch.object(check_public, "check", return_value=[("PyPI", "demo", "1", "unknown")]):
            self.assertEqual(check_public.main([]), 0)
            self.assertEqual(check_public.main(["--strict"]), 1)

    def test_check_one_uses_version(self):
        with mock.patch.object(check_public, "pypi_status", return_value="published") as status:
            check_public.check_one(("PyPI", "demo", "1.2"), [], 3)
            status.assert_called_once_with("demo", "1.2", 3)
        with mock.patch.object(check_public, "npm_status", return_value="published") as status:
            check_public.check_one(("npm", "demo", "1.2"), [], 3)
            status.assert_called_once_with("demo", "1.2", 3)
    def test_reports_only_non_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "java").mkdir()
            (root / "java/dependencies.txt").write_text("org.foo:bar:1.0\n")
            with mock.patch.object(check_public, "check_one",
                                   return_value=("Maven", "org.foo:bar", "1.0", "not published")):
                problems = check_public.check(root, repos=["https://a.example/m2"])
            self.assertEqual(len(problems), 1)
            self.assertEqual(problems[0][3], "not published")


if __name__ == "__main__":
    unittest.main()
