import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uatu_tools import github  # noqa: E402


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
