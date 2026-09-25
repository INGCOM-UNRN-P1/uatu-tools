import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uatu_tools import admin as uatu_admin  # noqa: E402
from uatu_tools import audit as ua  # noqa: E402
from uatu_tools.keystore import KeyStore, KeyStoreError, default_keys_dir  # noqa: E402
from telemetry_factory import base_config  # noqa: E402


def run(*argv, tty=False):
    out, err = io.StringIO(), io.StringIO()
    if tty:
        out.isatty = lambda: True  # simula una terminal interactiva
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = uatu_admin.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class KeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.join(tempfile.mkdtemp(), "keys")

    def test_default_location_respects_env(self):
        with mock.patch.dict(os.environ, {"UATU_KEYS_DIR": "/tmp/x"}):
            self.assertEqual(default_keys_dir(), "/tmp/x")
        env = {k: v for k, v in os.environ.items() if k != "UATU_KEYS_DIR"}
        env["XDG_CONFIG_HOME"] = "/cfg"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(default_keys_dir(), "/cfg/uatu/keys")
        env.pop("XDG_CONFIG_HOME")
        env["HOME"] = "/home/docente"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(default_keys_dir(), "/home/docente/.config/uatu/keys")

    def test_keygen_layout_and_permissions(self):
        code, out, err = run("--keys-dir", self.dir, "keygen", "--key-id", "prof-2026", "--name", "Prof. Demo")
        self.assertEqual(code, 0, err)
        info = json.loads(out)
        d = os.path.join(self.dir, "prof-2026")
        self.assertEqual(info["directory"], d)
        self.assertEqual(mode(self.dir), 0o700)
        self.assertEqual(mode(d), 0o700)
        self.assertEqual(mode(os.path.join(d, "signing.ed25519.pem")), 0o600)
        self.assertEqual(mode(os.path.join(d, "decryption.x25519.pem")), 0o600)
        meta = json.load(open(os.path.join(d, "key.json")))
        self.assertEqual(meta["kind"], "teacher")
        self.assertEqual(meta["ed25519_verify_key"], info["ed25519_verify_key"])
        self.assertEqual(meta["name"], "Prof. Demo")
        self.assertIn("registry-add", err)

        code, _, err = run("--keys-dir", self.dir, "keygen", "--key-id", "prof-2026")
        self.assertEqual(code, 1)
        self.assertIn("Ya existe", err)
        self.assertEqual(run("--keys-dir", self.dir, "keygen", "--key-id", "../fuera")[0], 1)

    def test_default_dir_via_environment(self):
        with mock.patch.dict(os.environ, {"UATU_KEYS_DIR": self.dir}):
            self.assertEqual(run("keygen", "--key-id", "p")[0], 0)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "p", "key.json")))

    def test_legacy_out_flag_is_alias_of_keys_dir(self):
        code, out, _ = run("root-keygen", "--out", self.dir, "--key-id", "raiz")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "raiz", "root.ed25519.pem")))
        self.assertEqual(json.loads(out)["anchor"]["key_id"], "raiz")

    def test_import_list_show(self):
        other = KeyStore(os.path.join(tempfile.mkdtemp(), "otro"))
        root = other.create_root("r")
        teacher = other.create_teacher("t")
        self.assertEqual(run("--keys-dir", self.dir, "keys", "import", "raiz", "--root", root.root_key_path)[0], 0)
        self.assertEqual(run("--keys-dir", self.dir, "keys", "import", "doc", "--signing", teacher.signing_key_path,
                             "--decryption", teacher.decryption_key_path, "--name", "Docente")[0], 0)
        store = KeyStore(self.dir)
        self.assertEqual(store.get("raiz").anchor["ed25519_public_key"], root.anchor["ed25519_public_key"])
        self.assertEqual(store.get("doc").verify_key, teacher.verify_key)

        # Tipos de clave cruzados se rechazan.
        code, _, err = run("--keys-dir", self.dir, "keys", "import", "mal", "--root", teacher.decryption_key_path)
        self.assertEqual(code, 1)
        self.assertIn("Ed25519", err)
        code, _, _ = run("--keys-dir", self.dir, "keys", "import", "mal2", "--signing", teacher.decryption_key_path,
                         "--decryption", teacher.signing_key_path)
        self.assertEqual(code, 1)
        self.assertEqual(run("--keys-dir", self.dir, "keys", "import", "mal3")[0], 1)

        code, out, _ = run("--keys-dir", self.dir, "keys", "list")
        self.assertIn("raiz", out)
        self.assertIn("docente", out)
        self.assertEqual(len(json.loads(run("--keys-dir", self.dir, "keys", "list", "--json")[1])), 2)
        shown = json.loads(run("--keys-dir", self.dir, "keys", "show", "doc")[1])
        self.assertTrue(shown["files"]["decryption_key"].endswith("decryption.x25519.pem"))
        self.assertEqual(run("--keys-dir", self.dir, "keys", "show", "nada")[0], 1)

    def test_kind_mismatch_is_reported(self):
        store = KeyStore(self.dir)
        store.create_root("r")
        with self.assertRaises(KeyStoreError):
            _ = store.get("r").verify_key


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.join(tempfile.mkdtemp(), "keys")
        self.store = KeyStore(self.dir)
        self.root = self.store.create_root("uni-root")
        self.root2 = self.store.create_root("uni-root-2")
        self.teacher = self.store.create_teacher("prof")

    def export(self, *args, tty=False):
        return run("--keys-dir", self.dir, "keys", "export", *args, tty=tty)

    def test_public_formats(self):
        self.assertEqual(json.loads(self.export("uni-root", "-f", "anchor")[1]), self.root.anchor)
        anchors = json.loads(self.export("uni-root", "uni-root-2", "-f", "trust-anchors")[1])
        self.assertEqual([a["key_id"] for a in anchors["anchors"]], ["uni-root", "uni-root-2"])
        self.assertEqual(self.export("prof", "-f", "verify-key")[1].strip(), self.teacher.verify_key)
        self.assertEqual(self.export("prof", "-f", "encrypt-key")[1].strip(), self.teacher.encrypt_key)
        entry = json.loads(self.export("prof", "-f", "registry-entry")[1])
        self.assertEqual(entry["prof"]["x25519_encryption_key"], self.teacher.encrypt_key)
        self.assertEqual(self.export("prof", "-f", "decryption-key-path")[1].strip(), self.teacher.decryption_key_path)
        self.assertEqual(json.loads(self.export("prof", "-f", "public")[1])["kind"], "teacher")

    def test_wrong_kind_or_multiple_keys(self):
        code, _, err = self.export("uni-root", "-f", "verify-key")
        self.assertEqual(code, 1)
        self.assertIn("no es una clave docente", err)
        self.assertEqual(self.export("prof", "uni-root", "-f", "anchor")[0], 1)

    def test_private_keys_are_guarded_on_terminals(self):
        code, out, err = self.export("prof", "-f", "decryption-key", tty=True)
        self.assertEqual(code, 1)
        self.assertIn("--show-secret", err)
        self.assertEqual(out, "")
        code, out, _ = self.export("prof", "-f", "decryption-key", "--show-secret", tty=True)
        self.assertEqual(code, 0)
        code, out, _ = self.export("prof", "-f", "decryption-key")  # redirigido: se permite
        self.assertEqual(code, 0)
        self.assertIn("BEGIN PRIVATE KEY", out)

    def test_out_file_permissions(self):
        target = os.path.join(tempfile.mkdtemp(), "priv.pem")
        self.assertEqual(self.export("prof", "-f", "decryption-key", "--out", target)[0], 0)
        self.assertEqual(mode(target), 0o600)
        self.assertIn("BEGIN PRIVATE KEY", open(target).read())

    def test_github_destinations(self):
        calls = []
        with mock.patch.object(uatu_admin, "set_actions_value", lambda *a, **k: calls.append((a, k))):
            self.assertEqual(self.export("prof", "-f", "verify-key", "--gh-variable", "V", "--repo", "o/r")[0], 0)
            self.assertEqual(self.export("prof", "-f", "decryption-key", "--gh-secret", "S", "--org", "o",
                                         "--visibility", "private")[0], 0)
            code, _, err = self.export("prof", "-f", "decryption-key", "--gh-variable", "V", "--repo", "o/r")
            self.assertEqual(code, 1)
            self.assertIn("no puede cargarse como variable", err)
            self.assertEqual(run("--keys-dir", self.dir, "keys", "setup-audit", "prof", "--repo", "o/examen")[0], 0)
            self.assertEqual(run("--keys-dir", self.dir, "keys", "setup-anchors", "uni-root", "--repo", "o/uatu")[0], 0)
        self.assertEqual(calls[0][0], ("variable", "V", self.teacher.verify_key))
        self.assertEqual(calls[0][1]["repo"], "o/r")
        self.assertEqual(calls[1][0][:2], ("secret", "S"))
        self.assertIn("BEGIN PRIVATE KEY", calls[1][0][2])
        self.assertEqual(calls[1][1], {"repo": None, "org": "o", "visibility": "private"})
        self.assertEqual([c[0][1] for c in calls[2:4]], ["UATU_TEACHER_PUBLIC_KEY", "UATU_TEACHER_PRIVATE_KEY"])
        self.assertEqual(calls[2][0][2], self.teacher.verify_key)
        self.assertEqual(calls[4][0][:2], ("variable", "UATU_TRUST_ANCHORS"))
        self.assertEqual(json.loads(calls[4][0][2]), {"anchors": [self.root.anchor]})

    def test_setup_anchors_file(self):
        target = os.path.join(tempfile.mkdtemp(), "trust-anchors.json")
        self.assertEqual(run("--keys-dir", self.dir, "keys", "setup-anchors", "uni-root", "uni-root-2", "--file", target)[0], 0)
        self.assertEqual(len(json.load(open(target))["anchors"]), 2)
        self.assertEqual(run("--keys-dir", self.dir, "keys", "setup-anchors", "uni-root")[0], 1)


class TeacherWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.dir = os.path.join(self.base, "keys")

    def a(self, *argv):
        return run("--keys-dir", self.dir, *argv)

    def test_full_workflow_using_the_store(self):
        self.assertEqual(self.a("root-keygen", "--key-id", "uba-root-2026")[0], 0)
        self.assertEqual(self.a("keygen", "--key-id", "prof-lead-2026")[0], 0)
        registry = os.path.join(self.base, "keys.json")
        self.assertEqual(self.a("registry-add", "--registry", registry, "--key-id", "prof-lead-2026")[0], 0)
        self.assertEqual(self.a("registry-sign", "--registry", registry, "--root-key-id", "uba-root-2026")[0], 0)
        self.assertEqual(self.a("verify-registry", "--registry", registry)[0], 0)
        reg = json.load(open(registry))
        self.assertEqual(reg["root_key_id"], "uba-root-2026")

        reg["teachers"]["prof-lead-2026"]["x25519_encryption_key"] = "00" * 32
        json.dump(reg, open(registry, "w"))
        self.assertEqual(self.a("verify-registry", "--registry", registry)[0], 1)

        config = os.path.join(self.base, ".uatu.conf")
        json.dump(base_config(), open(config, "w"))
        self.assertEqual(self.a("sign-config", "--config", config, "--key-id", "prof-lead-2026")[0], 0)
        self.assertEqual(self.a("verify-config", "--config", config)[0], 0)  # toma teacher_key_id del manifiesto
        cfg = json.load(open(config))
        self.assertEqual(len(cfg["crypto"]["signature"]), 128)
        self.assertEqual(self.a("sign-config", "--config", config)[0], 0)  # idem para firmar
        cfg["monitoring"]["clipboard"]["enabled"] = False
        json.dump(cfg, open(config, "w"))
        self.assertEqual(self.a("verify-config", "--config", config)[0], 1)

    def test_explicit_keys_still_supported(self):
        teacher = KeyStore(self.dir).create_teacher("t")
        registry = os.path.join(self.base, "keys.json")
        self.assertEqual(self.a("registry-add", "--registry", registry, "--key-id", "externo",
                                "--verify-key", teacher.verify_key, "--encrypt-key", teacher.encrypt_key)[0], 0)
        code, _, err = self.a("registry-add", "--registry", registry, "--key-id", "x", "--verify-key", "zz",
                              "--encrypt-key", "00" * 32)
        self.assertEqual(code, 1)
        self.assertIn("32 bytes", err)
        config = os.path.join(self.base, ".uatu.conf")
        json.dump(base_config(), open(config, "w"))
        self.assertEqual(self.a("sign-config", "--config", config, "--key", teacher.signing_key_path, "--key-id", "t")[0], 0)
        self.assertEqual(self.a("verify-config", "--config", config, "--verify-key", teacher.verify_key)[0], 0)

    def test_signature_ignores_crypto_block_and_formatting(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        signed = uatu_admin.sign_config(base_config(), key)
        verify = key.public_key().public_bytes_raw().hex()
        self.assertTrue(ua.verify_ed25519(verify, signed["crypto"]["signature"], ua.canonical(ua.without(signed, "crypto"))))
        with self.assertRaises(ValueError):
            uatu_admin.sign_config({**base_config(), "crypto": {}}, key)


if __name__ == "__main__":
    unittest.main()
