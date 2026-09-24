import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import uatu_admin  # noqa: E402
import uatu_audit as ua  # noqa: E402
from telemetry_factory import base_config  # noqa: E402


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = uatu_admin.main(list(argv))
    return code, out.getvalue()


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_full_teacher_workflow(self):
        code, out = run("root-keygen", "--out", self.dir, "--key-id", "uba-root-2026")
        self.assertEqual(code, 0)
        root = json.loads(out)
        self.assertEqual(oct(os.stat(root["private_key"]).st_mode & 0o777), "0o600")

        code, out = run("keygen", "--out", self.dir, "--key-id", "prof-lead-2026")
        teacher = json.loads(out)

        registry = os.path.join(self.dir, "keys.json")
        self.assertEqual(
            run("registry-add", "--registry", registry, "--key-id", "prof-lead-2026",
                "--verify-key", teacher["ed25519_verify_key"], "--encrypt-key", teacher["x25519_encryption_key"])[0],
            0,
        )
        self.assertEqual(run("registry-sign", "--registry", registry, "--root-key", root["private_key"],
                             "--root-key-id", "uba-root-2026")[0], 0)
        anchor = root["anchor"]["ed25519_public_key"]
        self.assertEqual(run("verify-registry", "--registry", registry, "--anchor-key", anchor)[0], 0)
        signed_registry = json.load(open(registry))
        self.assertEqual(signed_registry["root_key_id"], "uba-root-2026")

        # Alterar el registro invalida la firma raíz.
        signed_registry["teachers"]["prof-lead-2026"]["x25519_encryption_key"] = "00" * 32
        json.dump(signed_registry, open(registry, "w"))
        self.assertEqual(run("verify-registry", "--registry", registry, "--anchor-key", anchor)[0], 1)

        config = os.path.join(self.dir, ".uatu.conf")
        json.dump(base_config(), open(config, "w"))
        self.assertEqual(run("sign-config", "--config", config, "--key", teacher["signing_private_key"],
                             "--key-id", "prof-lead-2026")[0], 0)
        self.assertEqual(run("verify-config", "--config", config, "--verify-key", teacher["ed25519_verify_key"])[0], 0)

        cfg = json.load(open(config))
        self.assertEqual(len(cfg["crypto"]["signature"]), 128)
        cfg["monitoring"]["clipboard"]["enabled"] = False
        json.dump(cfg, open(config, "w"))
        self.assertEqual(run("verify-config", "--config", config, "--verify-key", teacher["ed25519_verify_key"])[0], 1)

    def test_signature_ignores_crypto_block_and_formatting(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        signed = uatu_admin.sign_config(base_config(), key)
        verify = key.public_key().public_bytes_raw().hex()
        self.assertTrue(ua.verify_ed25519(verify, signed["crypto"]["signature"], ua.canonical(ua.without(signed, "crypto"))))
        with self.assertRaises(ValueError):
            uatu_admin.sign_config({**base_config(), "crypto": {}}, key)

    def test_registry_add_rejects_malformed_keys(self):
        registry = os.path.join(self.dir, "keys.json")
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = run("registry-add", "--registry", registry, "--key-id", "x", "--verify-key", "zz",
                          "--encrypt-key", "00" * 32)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
