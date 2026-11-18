import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_registry  # noqa: E402


class Resp:
    def __init__(self, status=200, body=b""):
        self.status, self._body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def fake_urlopen(routes):
    """routes: {(method, url): Resp | int | Exception}. Records requests."""
    seen = []

    def urlopen(req, timeout=None):
        seen.append(req)
        outcome = routes.get((req.get_method(), req.full_url), 404)
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, int):
            raise urllib.error.HTTPError(req.full_url, outcome, "x", {}, None)
        return outcome

    urlopen.seen = seen
    return urlopen


def patched(routes):
    return mock.patch.object(check_registry.urllib.request, "urlopen", fake_urlopen(routes))


class Urls(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(check_registry.classify(200), "available")
        self.assertEqual(check_registry.classify(403), "quarantined")
        self.assertEqual(check_registry.classify(404), "not cached")
        self.assertEqual(check_registry.classify(500), "error")
        self.assertEqual(check_registry.classify(0), "error")

    def test_pypi_url_normalises(self):
        self.assertEqual(check_registry.pypi_url("https://idx.example/simple/", "Foo_Bar.baz"),
                         "https://idx.example/simple/foo-bar-baz/")

    def test_maven_url(self):
        self.assertEqual(
            check_registry.maven_url("https://repo.example/m/", "com.example.sub:lib", "1.2"),
            "https://repo.example/m/com/example/sub/lib/1.2/lib-1.2.pom")

    def test_npm_url_scoped(self):
        self.assertEqual(check_registry.npm_url("https://reg.example/", "ms"), "https://reg.example/ms")
        self.assertEqual(check_registry.npm_url("https://reg.example", "@scope/pkg"),
                         "https://reg.example/@scope%2Fpkg")

    def test_basic_auth(self):
        self.assertEqual(check_registry.basic_auth("u", "p"), "Basic dTpw")
        self.assertIsNone(check_registry.basic_auth(None, "p"))


PAGE = '''<a href="../../files/demo_lib-1.0-py3-none-any.whl#sha256=abc">x</a>
<a href="https://idx.example/files/demo-lib-1.0.1.tar.gz">y</a>
<a href="/files/other-1.0.tar.gz">z</a>'''


class Pypi(unittest.TestCase):
    index = "https://idx.example/simple"
    page = "https://idx.example/simple/demo-lib/"

    def test_file_version(self):
        f = check_registry.pypi_file_version
        self.assertEqual(f("demo_lib-1.0-py3-none-any.whl", "demo-lib"), "1.0")
        self.assertEqual(f("demo-lib-1.0.1.tar.gz", "demo-lib"), "1.0.1")
        self.assertIsNone(f("other-1.0.tar.gz", "demo-lib"))

    def test_available(self):
        routes = {("GET", self.page): Resp(200, PAGE.encode()),
                  ("HEAD", "https://idx.example/files/demo_lib-1.0-py3-none-any.whl"): Resp(200)}
        with patched(routes):
            self.assertEqual(check_registry.check_pypi(self.index, "Basic x", "demo_lib", "1.0"), "available")

    def test_version_absent_is_not_cached(self):
        with patched({("GET", self.page): Resp(200, PAGE.encode())}):
            self.assertEqual(check_registry.check_pypi(self.index, None, "demo-lib", "1"), "not cached")

    def test_prefix_version_does_not_match(self):
        with patched({("GET", self.page): Resp(200, PAGE.encode())}):
            self.assertEqual(check_registry.check_pypi(self.index, None, "demo-lib", "1.0.1x"), "not cached")

    def test_file_403_is_quarantined(self):
        routes = {("GET", self.page): Resp(200, PAGE.encode()),
                  ("HEAD", "https://idx.example/files/demo_lib-1.0-py3-none-any.whl"): 403}
        with patched(routes):
            self.assertEqual(check_registry.check_pypi(self.index, None, "demo-lib", "1.0"), "quarantined")

    def test_page_codes(self):
        for code, status in ((403, "quarantined"), (404, "not cached"), (502, "error")):
            with patched({("GET", self.page): code}):
                self.assertEqual(check_registry.check_pypi(self.index, None, "demo-lib", "1.0"), status)


class MavenNpm(unittest.TestCase):
    def test_maven(self):
        url = "https://repo.example/com/example/lib/1.0/lib-1.0.pom"
        for outcome, status in ((Resp(200), "available"), (403, "quarantined"), (404, "not cached")):
            with patched({("HEAD", url): outcome}):
                self.assertEqual(check_registry.check_maven("https://repo.example", None, "com.example:lib", "1.0"), status)

    def test_network_failure_is_error(self):
        url = "https://repo.example/com/example/lib/1.0/lib-1.0.pom"
        with patched({("HEAD", url): urllib.error.URLError("secret-host")}):
            self.assertEqual(check_registry.check_maven("https://repo.example", None, "com.example:lib", "1.0"), "error")

    def meta(self, tarball="https://reg.example/ms/-/ms-1.0.0.tgz"):
        return Resp(200, json.dumps({"versions": {"1.0.0": {"dist": {"tarball": tarball}}}}).encode())

    def test_npm_available(self):
        routes = {("GET", "https://reg.example/ms"): self.meta(),
                  ("HEAD", "https://reg.example/ms/-/ms-1.0.0.tgz"): Resp(200)}
        with patched(routes) as _:
            self.assertEqual(check_registry.check_npm("https://reg.example", None, "ms", "1.0.0"), "available")

    def test_npm_tarball_quarantined(self):
        routes = {("GET", "https://reg.example/ms"): self.meta(),
                  ("HEAD", "https://reg.example/ms/-/ms-1.0.0.tgz"): 403}
        with patched(routes):
            self.assertEqual(check_registry.check_npm("https://reg.example", None, "ms", "1.0.0"), "quarantined")

    def test_npm_missing_version_and_metadata_403(self):
        with patched({("GET", "https://reg.example/ms"): self.meta()}):
            self.assertEqual(check_registry.check_npm("https://reg.example", None, "ms", "2.0.0"), "not cached")
        with patched({("GET", "https://reg.example/ms"): 403}):
            self.assertEqual(check_registry.check_npm("https://reg.example", None, "ms", "1.0.0"), "quarantined")

    def test_auth_header_not_forwarded_to_other_host(self):
        opener = fake_urlopen({("GET", "https://reg.example/ms"): self.meta("https://cdn.example/ms.tgz"),
                               ("HEAD", "https://cdn.example/ms.tgz"): Resp(200)})
        with mock.patch.object(check_registry.urllib.request, "urlopen", opener):
            check_registry.check_npm("https://reg.example", "Basic x", "ms", "1.0.0")
        self.assertEqual(opener.seen[0].get_header("Authorization"), "Basic x")
        self.assertIsNone(opener.seen[1].get_header("Authorization"))


class Hardening(unittest.TestCase):
    def test_origin_includes_scheme_and_port(self):
        self.assertTrue(check_registry.same_origin("https://a.example/x", "https://a.example:443/y"))
        self.assertFalse(check_registry.same_origin("https://a.example/x", "http://a.example/x"))
        self.assertFalse(check_registry.same_origin("https://a.example/x", "https://a.example:8443/x"))

    def redirect(self, target):
        req = check_registry.urllib.request.Request("https://a.example/x")
        req.add_unredirected_header("Authorization", "Basic x")
        handler = check_registry.KeepAuthSameOrigin()
        return handler.redirect_request(req, None, 302, "Found", {}, target)

    def test_redirect_keeps_auth_same_origin_only(self):
        self.assertEqual(self.redirect("https://a.example/y").get_header("Authorization"), "Basic x")
        self.assertIsNone(self.redirect("http://a.example/y").get_header("Authorization"))
        self.assertIsNone(self.redirect("https://b.example/y").get_header("Authorization"))

    def test_no_http_downgrade_for_file_links(self):
        page = "https://idx.example/simple/demo-lib/"
        html = '<a href="http://idx.example/files/demo-lib-1.0.tar.gz">x</a>'
        opener = fake_urlopen({("GET", page): Resp(200, html.encode()),
                               ("HEAD", "http://idx.example/files/demo-lib-1.0.tar.gz"): Resp(200)})
        with mock.patch.object(check_registry.urllib.request, "urlopen", opener):
            check_registry.check_pypi("https://idx.example/simple", "Basic x", "demo-lib", "1.0")
        self.assertIsNone(opener.seen[1].get_header("Authorization"))

    def test_settings_no_matching_server_means_no_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.xml"
            path.write_text(SETTINGS.replace("<id>proxy</id><username>", "<id>nope</id><username>"))
            url, auth = check_registry.parse_settings(path, {})
            self.assertEqual(url, "https://repo.example/maven")
            self.assertIsNone(auth)

    def test_settings_env_expansion(self):
        xml = SETTINGS.replace("https://repo.example/maven", "${env.REPO_URL}") \
                      .replace("<username>user", "<username>${env.U}").replace("<password>pass", "<password>${env.P}")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.xml"
            path.write_text(xml)
            url, auth = check_registry.parse_settings(path, {"REPO_URL": "https://r.example/m", "U": "u", "P": "p"})
            self.assertEqual((url, auth), ("https://r.example/m", "Basic dTpw"))

    def test_npmrc_env_expansion_and_path_expansion(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "npmrc"
            path.write_text("registry=${REG}\n_authToken=${TOK}\n")
            with mock.patch.dict("os.environ", {"CFGDIR": tmp}):
                cfg = check_registry.npm_config({"NPM_CONFIG_USERCONFIG": "$CFGDIR/npmrc", "REG": "https://r.example/", "TOK": "t"})
            self.assertEqual(cfg, ("https://r.example/", "Bearer t"))

    def test_settings_file_attached_form_and_expansion(self):
        self.assertEqual(check_registry.settings_file("-B -s/a/s.xml"), "/a/s.xml")
        with mock.patch.dict("os.environ", {"D": "/d"}):
            self.assertEqual(check_registry.expand_path("$D/s.xml"), "/d/s.xml")

    def test_markdown_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            path.write_text("# R\n" + "x" * 50000)
            findings = [{"ecosystem": "npm", "package": f"pkg{i}", "request": "1.0.0", "registry": "not cached"}
                        for i in range(2000)]
            check_registry.update_markdown(path, findings)
            text = path.read_text()
            self.assertLessEqual(len(text), 60000)
            self.assertIn("more, see report.json", text)


SETTINGS = """<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <servers>
    <server><id>other</id><username>x</username><password>y</password></server>
    <server><id>proxy</id><username>user</username><password>pass</password></server>
  </servers>
  <mirrors><mirror><id>proxy</id><url>https://repo.example/maven</url><mirrorOf>*</mirrorOf></mirror></mirrors>
</settings>"""


class Config(unittest.TestCase):
    def test_pypi_config(self):
        env = {"UV_DEFAULT_INDEX": "my-idx=https://idx.example/simple",
               "UV_INDEX_MY_IDX_USERNAME": "u", "UV_INDEX_MY_IDX_PASSWORD": "p"}
        self.assertEqual(check_registry.pypi_config(env), ("https://idx.example/simple", "Basic dTpw"))
        self.assertEqual(check_registry.pypi_config({"UV_DEFAULT_INDEX": "https://idx.example/s"}),
                         ("https://idx.example/s", None))
        self.assertIsNone(check_registry.pypi_config({}))

    def test_settings_file_arg(self):
        self.assertEqual(check_registry.settings_file("-B -s /a/s.xml --no-transfer-progress"), "/a/s.xml")
        self.assertEqual(check_registry.settings_file("--settings=/b.xml"), "/b.xml")
        self.assertIsNone(check_registry.settings_file("-B"))

    def test_parse_settings_with_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.xml"
            path.write_text(SETTINGS)
            url, auth = check_registry.parse_settings(path)
            self.assertEqual(url, "https://repo.example/maven")
            self.assertEqual(auth, check_registry.basic_auth("user", "pass"))
            self.assertEqual(check_registry.maven_config({"MAVEN_ARGS": f"-s {path}"}), (url, auth))

    def test_npm_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "npmrc"
            path.write_text("# c\nregistry=https://reg.example/npm/\n//reg.example/npm/:_auth=dTpw\n")
            self.assertEqual(check_registry.npm_config({"NPM_CONFIG_USERCONFIG": str(path)}),
                             ("https://reg.example/npm/", "Basic dTpw"))
        self.assertIsNone(check_registry.npm_config({}))


class Report(unittest.TestCase):
    def test_purls_and_constraints(self):
        f = {"ecosystem": "npm", "package": "@scope/pkg", "request": "1.0.0"}
        self.assertEqual(check_registry.to_purl(f), "pkg:npm/%40scope/pkg@1.0.0")
        f = {"ecosystem": "Maven", "package": "com.example:lib", "request": "1.0"}
        self.assertEqual(check_registry.to_purl(f), "pkg:maven/com.example/lib@1.0")
        known = "pkg:pypi/demo-lib@1.0\npkg:maven/com.example/lib@1.0\n"
        self.assertEqual(check_registry.constraints(known), ['"demo-lib!=1.0",'])

    def test_run_updates_files_without_leaking_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = {"findings": [
                {"ecosystem": "Maven", "package": "com.example:lib", "request": "1.0", "in_use": ["0.9"]},
                {"ecosystem": "Maven", "package": "com.example:two", "request": "2.0", "in_use": ["1.9"]},
            ]}
            (tmp / "report.json").write_text(json.dumps(report))
            (tmp / "report.md").write_text("# Report\n")
            (tmp / "known.txt").write_text("pkg:pypi/aa@1\n")
            settings = tmp / "s.xml"
            settings.write_text(SETTINGS)
            routes = {("HEAD", "https://repo.example/maven/com/example/lib/1.0/lib-1.0.pom"): Resp(200),
                      ("HEAD", "https://repo.example/maven/com/example/two/2.0/two-2.0.pom"): 403}
            out = mock.MagicMock()
            with patched(routes), mock.patch("sys.stdout", out):
                check_registry.run(tmp / "report.json", tmp / "known.txt", {"MAVEN_ARGS": f"-s {settings}"})
            printed = "".join(c.args[0] for c in out.write.call_args_list)
            self.assertNotIn("repo.example", printed)
            self.assertNotIn("pass", printed)
            data = json.loads((tmp / "report.json").read_text())
            self.assertEqual([f["registry"] for f in data["findings"]], ["available", "quarantined"])
            self.assertEqual((tmp / "known.txt").read_text(),
                             "pkg:maven/com.example/two@2.0\npkg:pypi/aa@1\n")
            md = (tmp / "report.md").read_text()
            self.assertIn("## Registry availability", md)
            self.assertIn("com.example:two:2.0", md)
            self.assertNotIn("com.example:lib:1.0", md.split("Still to request")[1])

    def test_markdown_section_is_replaced_not_duplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            path.write_text("# R\n")
            findings = [{"ecosystem": "npm", "package": "ms", "request": "1.0.0", "registry": "available"}]
            check_registry.update_markdown(path, findings)
            check_registry.update_markdown(path, findings)
            self.assertEqual(path.read_text().count("## Registry availability"), 1)


if __name__ == "__main__":
    unittest.main()
