import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uatu_tools import admin as uatu_admin  # noqa: E402
from uatu_tools import github  # noqa: E402
from telemetry_factory import base_config  # noqa: E402


class FakeApi:
    """Transporte HTTP simulado que registra las llamadas a la API de GitHub."""

    def __init__(self, existing=None, fail=None):
        self.calls = []
        self.existing = existing or []
        self.fail = fail

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if self.fail:
            return self.fail
        if method == "GET":
            return 200, self.existing
        return (200 if method == "PUT" else 201), dict(body, id=77)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = uatu_admin.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class RulesetTests(unittest.TestCase):
    def test_ruleset_blocks_deletion_and_force_push_only(self):
        rs = github.build_ruleset("uatu-audit")
        self.assertEqual(rs["conditions"]["ref_name"]["include"], ["refs/heads/uatu-audit/**"])
        self.assertEqual({r["type"] for r in rs["rules"]}, {"deletion", "non_fast_forward"})
        self.assertEqual(rs["bypass_actors"], [])
        self.assertEqual(rs["enforcement"], "active")
        self.assertNotIn("repository_name", rs["conditions"])
        org = github.build_ruleset("tele/", repository_patterns=["examen-*"])
        self.assertEqual(org["conditions"]["ref_name"]["include"], ["refs/heads/tele/**"])
        self.assertEqual(org["conditions"]["repository_name"]["include"], ["examen-*"])

    def test_apply_creates_or_updates_by_name(self):
        api = FakeApi()
        client = github.GitHubClient("tok", transport=api)
        action, _ = github.apply_ruleset(client, "repos/o/r", github.build_ruleset("uatu-audit"))
        self.assertEqual(action, "creado")
        self.assertEqual([c[0] for c in api.calls], ["GET", "POST"])
        self.assertIn("includes_parents=false", api.calls[0][1])
        self.assertEqual(api.calls[1][1], "https://api.github.com/repos/o/r/rulesets")
        self.assertEqual(api.calls[1][3]["Authorization"], "Bearer tok")

        api = FakeApi(existing=[{"id": 5, "name": "otra"}, {"id": 9, "name": github.RULESET_NAME}])
        action, _ = github.apply_ruleset(github.GitHubClient("tok", transport=api), "orgs/o", github.build_ruleset("x"))
        self.assertEqual(action, "actualizado")
        self.assertEqual(api.calls[1][:2], ("PUT", "https://api.github.com/orgs/o/rulesets/9"))
        self.assertNotIn("includes_parents", api.calls[0][1])

    def test_api_errors_are_explained(self):
        api = FakeApi(fail=(404, {"message": "Not Found"}))
        with self.assertRaisesRegex(github.GitHubError, "404.*permisos"):
            github.apply_ruleset(github.GitHubClient("tok", transport=api), "repos/o/r", github.build_ruleset("u"))

    def test_resolve_token(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "a", "GITHUB_TOKEN": "b"}):
            self.assertEqual(github.resolve_token(), "a")
        env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(github.shutil, "which", return_value="/bin/gh"):
            fake = lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="gho_x\n")  # noqa: E731
            self.assertEqual(github.resolve_token(runner=fake), "gho_x")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(github.shutil, "which", return_value=None):
            with self.assertRaises(github.GitHubError):
                github.resolve_token()


class ProtectBranchesCommandTests(unittest.TestCase):
    def test_dry_run_reads_prefix_from_config(self):
        cfg = base_config()
        cfg["git"]["telemetry_branch_prefix"] = "telemetria"
        path = os.path.join(tempfile.mkdtemp(), ".uatu.conf")
        json.dump(cfg, open(path, "w"))
        code, out, _ = run("protect-branches", "--repo", "o/r", "--config", path, "--dry-run")
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual(plan["endpoint"], "/repos/o/r/rulesets")
        self.assertEqual(plan["ruleset"]["conditions"]["ref_name"]["include"], ["refs/heads/telemetria/**"])

    def test_org_requires_repository_pattern(self):
        code, _, err = run("protect-branches", "--org", "o", "--config", "/no/existe", "--dry-run")
        self.assertEqual(code, 1)
        self.assertIn("--repo-pattern", err)
        code, out, _ = run("protect-branches", "--org", "o", "--repo-pattern", "examen-*", "--config", "/no/existe",
                           "--dry-run")
        self.assertEqual(json.loads(out)["ruleset"]["conditions"]["repository_name"]["include"], ["examen-*"])
        self.assertEqual(run("protect-branches", "--config", "/no/existe")[0], 1)

    def test_apply_uses_api(self):
        api = FakeApi()
        with mock.patch.object(uatu_admin, "resolve_token", return_value="tok"), \
                mock.patch.object(uatu_admin, "GitHubClient", lambda token: github.GitHubClient(token, transport=api)):
            code, out, _ = run("protect-branches", "--repo", "o/r", "--prefix", "uatu-audit", "--config", "/no/existe")
        self.assertEqual(code, 0)
        self.assertIn("creado", out)
        self.assertEqual(api.calls[-1][0], "POST")


class ActionsValuesTests(unittest.TestCase):
    def test_secret_value_travels_through_stdin(self):
        seen = {}

        def runner(cmd, **kwargs):
            seen["cmd"], seen["input"] = cmd, kwargs.get("input")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        github.set_actions_value("secret", "S", "valor-secreto", repo="o/r", runner=runner)
        self.assertEqual(seen["cmd"], ["gh", "secret", "set", "S", "--repo", "o/r"])
        self.assertEqual(seen["input"], "valor-secreto")
        self.assertNotIn("valor-secreto", " ".join(seen["cmd"]))

        github.set_actions_value("variable", "V", "x", org="o", visibility="private", runner=runner)
        self.assertEqual(seen["cmd"], ["gh", "variable", "set", "V", "--org", "o", "--visibility", "private"])

    def test_errors(self):
        ok = lambda cmd, **k: subprocess.CompletedProcess(cmd, 0)  # noqa: E731
        with self.assertRaises(github.GitHubError):
            github.set_actions_value("secret", "S", "v", runner=ok)
        with self.assertRaises(github.GitHubError):
            github.set_actions_value("secret", "S", "v", repo="o/r", org="o", runner=ok)
        bad = lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="HTTP 403")  # noqa: E731
        with self.assertRaisesRegex(github.GitHubError, "403"):
            github.set_actions_value("secret", "S", "v", repo="o/r", runner=bad)


if __name__ == "__main__":
    unittest.main()
