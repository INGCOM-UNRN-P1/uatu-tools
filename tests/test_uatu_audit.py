import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uatu_tools import audit as ua  # noqa: E402
from telemetry_factory import (  # noqa: E402
    DEADLINE,
    START,
    SessionFactory,
    TeacherKeys,
    base_config,
    git,
    make_exam_repo,
)

CLI = [sys.executable, "-m", "uatu_tools.audit"]


def audit(repo, teacher, decrypt=True, **kwargs):
    pem = teacher.write_decrypt_pem(tempfile.mkdtemp()) if decrypt else None
    auditor = ua.UatuAuditor(repo, teacher.verify_hex, pem, **kwargs)
    auditor.run()
    return auditor


def clean_session(repo, user="octocat", minutes=(1, 3, 5)):
    s = SessionFactory(repo, user=user)
    s.start(START + timedelta(minutes=minutes[0]))
    s.event("window_focus", {"focused": False, "unfocused_total_ms": 0}, START + timedelta(minutes=minutes[1]))
    s.event("window_focus", {"focused": True, "unfocused_ms": 5000, "unfocused_total_ms": 5000},
            START + timedelta(minutes=minutes[1], seconds=5))
    s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=minutes[2]))
    return s


class CanonicalTests(unittest.TestCase):
    def test_matches_extension_serialization(self):
        value = {"b": 1, "a": {"d": [3, {"z": True, "y": None}], "c": "x"}, "s": 'ñandú "q" \\ \n\t\u0001'}
        self.assertEqual(
            ua.canonical(value).decode("utf-8"),
            '{"a":{"c":"x","d":[3,{"y":null,"z":true}]},"b":1,"s":"ñandú \\"q\\" \\\\ \\n\\t\\u0001"}',
        )

    def test_genesis_concatenation(self):
        self.assertEqual(
            ua.genesis_hash("1" * 40, "2" * 64, "octocat", "3" * 64),
            ua.sha256_hex(("1" * 40 + "2" * 64 + "octocat" + "3" * 64).encode()),
        )


class AuditorTests(unittest.TestCase):
    def setUp(self):
        self.teacher = TeacherKeys()
        self.repo = make_exam_repo(self.teacher)

    def test_clean_session_is_ok(self):
        s = clean_session(self.repo)
        s.publish([2, 2])
        a = audit(self.repo, self.teacher)
        self.assertEqual(a.errors, [])
        self.assertEqual(a.warnings, [])
        self.assertEqual(a.exit_code(), 0)
        report = next(iter(a.sessions.values()))
        self.assertEqual(report.unfocused_ms, 5000)
        self.assertEqual(report.closed_reason, "deadline")

    def test_massive_paste_warns_and_decrypts(self):
        s = SessionFactory(self.repo)
        s.start()
        code = "void schedule(void) {\n  for (;;) { pick_next(); run(); }\n}\n" * 2
        s.paste(code, START + timedelta(minutes=3), self.teacher)
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertEqual(a.errors, [])
        self.assertEqual(a.exit_code(), 2)
        self.assertEqual(len(a.warnings), 1)
        self.assertIn("Pegado masivo", a.warnings[0])
        self.assertIn("void schedule(void) { ⏎", a.warnings[0])

    def test_paste_without_decrypt_key(self):
        s = SessionFactory(self.repo)
        s.start()
        s.paste("x" * 80, START + timedelta(minutes=3), self.teacher)
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        a = audit(self.repo, self.teacher, decrypt=False)
        self.assertIn("Descifrado omitido", a.warnings[0])

    def test_external_insertion_without_focus_warns_even_if_small(self):
        s = SessionFactory(self.repo)
        s.start()
        s.paste("int x = 42; /* ext */", START + timedelta(minutes=3), self.teacher,
                event_type="external_insertion", focused=False)
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertEqual(a.exit_code(), 2)
        self.assertIn("Inserción externa con el editor sin foco", a.warnings[0])

    def test_tampered_event_rewritten_in_history(self):
        s = clean_session(self.repo)
        s.publish()
        batch = json.loads(json.dumps(s.batches[0]))
        batch["events"][1]["data"]["focused"] = True
        s.commit_file("batches/batch-000000.json", json.dumps(batch).encode())
        a = audit(self.repo, self.teacher)
        self.assertEqual(a.exit_code(), 1)
        joined = "\n".join(a.errors)
        self.assertIn("Firma digital del estudiante inválida en seq 1", joined)
        self.assertIn("historia reescrita", joined)
        self.assertIn("Ruptura de hash-chain en seq 2", joined)

    def test_forged_config_breaks_signature_and_genesis(self):
        s = clean_session(self.repo)
        s.publish()
        path = os.path.join(self.repo, ".uatu.conf")
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["session"]["deadline_utc"] = "2026-09-24T20:00:00Z"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        a = audit(self.repo, self.teacher)
        joined = "\n".join(a.errors)
        self.assertIn("Firma docente en .uatu.conf INVÁLIDA", joined)
        self.assertIn("alteración de reglas", joined)

    def test_wrong_teacher_key(self):
        clean_session(self.repo).publish()
        a = audit(self.repo, TeacherKeys())
        self.assertIn("INVÁLIDA", a.errors[0])

    def test_genesis_mismatch_is_critical(self):
        s = SessionFactory(self.repo, config_sha256="f" * 64)
        s.start()
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=2))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("alteración de reglas" in e for e in a.errors))

    def test_event_before_start_is_critical_and_after_deadline_warns(self):
        s = SessionFactory(self.repo)
        s.start(START - timedelta(minutes=5))
        s.event("heartbeat", {"uptime_seconds": 1}, START - timedelta(minutes=4))
        s.event("session_end", {"reason": "deadline"}, DEADLINE + timedelta(minutes=10))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("antes de start_utc" in e for e in a.errors))
        self.assertTrue(any("posterioridad al deadline_utc" in w for w in a.warnings))

    def test_deadline_grace_and_recovered_end(self):
        s = SessionFactory(self.repo)
        s.start(DEADLINE - timedelta(minutes=2))
        s.event("session_end", {"reason": "deadline"}, DEADLINE + timedelta(seconds=5))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertEqual(a.exit_code(), 0, a.warnings)

        other = SessionFactory(self.repo, user="alumna")
        other.start(DEADLINE - timedelta(minutes=1))
        other.event("session_end", {"reason": "recovered"}, DEADLINE + timedelta(hours=5))
        other.publish()
        a = audit(self.repo, self.teacher, target_user="alumna")
        self.assertEqual(a.exit_code(), 0, a.warnings)

    def test_missing_batch_and_unsigned_batch(self):
        s = clean_session(self.repo)
        s.publish([1, 1, 2])
        # Borra el lote intermedio reescribiendo la rama sin él.
        git(self.repo, "update-ref", "-d", s.ref)
        s.batches = []
        s.commit_file("batches/batch-000000.json", json.dumps(s.build_batch(s.events[:1], 0)).encode())
        s.commit_file("batches/batch-000002.json", json.dumps(s.build_batch(s.events[2:], 2)).encode())
        a = audit(self.repo, self.teacher)
        joined = "\n".join(a.errors)
        self.assertIn("Lote faltante", joined)
        self.assertIn("Ruptura de hash-chain en seq 2", joined)

        repo2 = make_exam_repo(self.teacher)
        s2 = clean_session(repo2)
        s2.publish(sign_batches=False)
        a2 = audit(repo2, self.teacher)
        self.assertEqual(a2.errors, [])
        self.assertTrue(any("no tiene firma de lote" in w for w in a2.warnings))

    def test_forged_batch_signature(self):
        s = clean_session(self.repo)
        batch = s.build_batch(s.events, 0)
        batch["created_at_utc"] = "2026-09-24T13:59:59.000Z"
        s.commit_file("batches/batch-000000.json", json.dumps(batch).encode())
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("Firma del lote 0 inválida" in e for e in a.errors))

    def test_impersonation_branch_user_mismatch(self):
        s = clean_session(self.repo, user="octocat")
        s.ref = s.ref.replace("/octocat/", "/otra-persona/")
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("suplantación" in e for e in a.errors))

    def test_no_branches_is_critical(self):
        a = audit(self.repo, self.teacher)
        self.assertEqual(a.exit_code(), 1)
        self.assertIn("ausencia de registros", a.errors[0])

    def test_user_filter_and_consolidation(self):
        clean_session(self.repo, user="octocat", minutes=(1, 3, 5)).publish()
        clean_session(self.repo, user="octocat", minutes=(2, 4, 6)).publish()
        clean_session(self.repo, user="alumna").publish()
        a = audit(self.repo, self.teacher, target_user="octocat")
        self.assertEqual(len(a.sessions), 2)
        timeline = a.consolidate()
        self.assertEqual(list(timeline), ["octocat"])
        stamps = [t for t, _, _ in timeline["octocat"]]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(len(stamps), 8)

    def test_unclosed_session_and_silence_gap(self):
        s = SessionFactory(self.repo)
        s.start()
        s.event("heartbeat", {"uptime_seconds": 120}, START + timedelta(minutes=3))
        s.event("heartbeat", {"uptime_seconds": 3000}, START + timedelta(minutes=50))
        s.publish()
        a = audit(self.repo, self.teacher)
        joined = "\n".join(a.warnings)
        self.assertIn("Silencio de telemetría", joined)
        self.assertIn("no registra session_end", joined)
        self.assertEqual(a.exit_code(), 2)

    def test_disallowed_extension_and_config_change(self):
        s = SessionFactory(self.repo)
        s.start()
        s.event("disallowed_extension", {"extension_id": "github.copilot", "version": "1.0", "state": "active"},
                START + timedelta(minutes=2))
        s.event("config_changed", {"config_sha256": "0" * 64, "signature_valid": False}, START + timedelta(minutes=3))
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=4))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("github.copilot" in w for w in a.warnings))
        self.assertTrue(any("alterado o eliminado durante la sesión" in e for e in a.errors))

    def test_code_commit_outside_telemetry(self):
        clean_session(self.repo, minutes=(1, 3, 5)).publish()
        with open(os.path.join(self.repo, "main.c"), "a") as f:
            f.write("// solución\n")
        git(self.repo, "commit", "-qam", "solución", env={
            "GIT_COMMITTER_DATE": "2026-09-24T15:00:00Z", "GIT_AUTHOR_DATE": "2026-09-24T15:00:00Z"})
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("fuera de todo período con telemetría activa" in w for w in a.warnings))

    def test_decrypted_hash_mismatch_is_critical(self):
        s = SessionFactory(self.repo)
        s.start()
        ev = s.paste("a" * 60, START + timedelta(minutes=2), self.teacher)
        # Firma válida pero sha256_plaintext inconsistente con el sobre: se re-firma la cadena.
        s.events.pop()
        s.last_hash = ua.event_hash(s.events[-1])
        data = dict(ev["data"], sha256_plaintext="0" * 64)
        s.event("clipboard_paste", data, START + timedelta(minutes=2))
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=4))
        s.publish()
        a = audit(self.repo, self.teacher)
        self.assertTrue(any("no coincide con sha256_plaintext" in e for e in a.errors))


class KeyStoreResolutionTests(unittest.TestCase):
    """uatu-audit acepta claves del almacén de uatu-admin por identificador."""

    def setUp(self):
        from uatu_tools.keystore import KeyStore

        self.teacher = TeacherKeys()
        tmp = tempfile.mkdtemp()
        pem_dir = os.path.join(tmp, "pem")
        os.mkdir(pem_dir)
        sign_pem = os.path.join(pem_dir, "s.pem")
        with open(sign_pem, "wb") as f:
            from cryptography.hazmat.primitives import serialization as ser

            f.write(self.teacher.sign.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        self.keys_dir = os.path.join(tmp, "keys")
        KeyStore(self.keys_dir).import_teacher("prof-lead-2026", sign_pem, self.teacher.write_decrypt_pem(pem_dir))
        self.repo = make_exam_repo(self.teacher)
        s = SessionFactory(self.repo)
        s.start()
        s.paste("q" * 70, START + timedelta(minutes=2), self.teacher)
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=3))
        s.publish()
        self.out = os.path.join(tmp, "r.json")

    def main(self, *extra):
        env = {k: v for k, v in os.environ.items() if k != "UATU_TEACHER_PUBLIC_KEY"}
        with mock.patch.dict(os.environ, env, clear=True):
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = ua.main(["--repo", self.repo, "--keys-dir", self.keys_dir, "--md-out",
                                self.out + ".md", "--json-out", self.out, *extra])
        return code, json.load(open(self.out)) if os.path.exists(self.out) else None, err.getvalue()

    def test_key_id_resolves_public_and_private_keys(self):
        code, report, err = self.main("--key-id", "prof-lead-2026")
        self.assertEqual(code, 2, report)
        self.assertEqual(report["errors"], [])
        self.assertIn("qqqq", report["warnings"][0])  # descifrado con la privada del almacén
        self.assertIn("prof-lead-2026", err)

    def test_manifest_teacher_key_id_is_used_by_default(self):
        code, report, _ = self.main()
        self.assertEqual(code, 2)
        self.assertIn("qqqq", report["warnings"][0])

    def test_ids_in_teacher_and_decrypt_flags(self):
        code, report, _ = self.main("--teacher-key", "prof-lead-2026", "--decrypt-key", "prof-lead-2026")
        self.assertEqual(code, 2)
        self.assertIn("qqqq", report["warnings"][0])

    def test_without_keys_requires_teacher_key(self):
        empty = tempfile.mkdtemp()
        env = {k: v for k, v in os.environ.items() if k != "UATU_TEACHER_PUBLIC_KEY"}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ua.main(["--repo", self.repo, "--keys-dir", empty, "--md-out", self.out + ".md"]), 1)


class CliTests(unittest.TestCase):
    def test_cli_exit_codes_and_reports(self):
        teacher = TeacherKeys()
        repo = make_exam_repo(teacher)
        s = SessionFactory(repo)
        s.start()
        s.paste("z" * 120, START + timedelta(minutes=3), teacher)
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        out = tempfile.mkdtemp()
        md, js = os.path.join(out, "r.md"), os.path.join(out, "r.json")
        res = subprocess.run(
            [*CLI, "--repo", repo, "--teacher-key", teacher.verify_hex,
             "--decrypt-key", teacher.write_decrypt_pem(out), "--md-out", md, "--json-out", js],
            capture_output=True, text=True,
        )
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        report = open(md, encoding="utf-8").read()
        self.assertIn("# Reporte de Auditoría Uatu: ⚠️ ADVERTENCIAS", report)
        self.assertIn("Micro-Lotes Procesados:** 1", report)
        self.assertIn("Línea de Tiempo Consolidada", report)
        self.assertEqual(json.load(open(js))["status"], "warning")

        res = subprocess.run([*CLI, "--repo", repo, "--teacher-key", "00" * 32, "--md-out", md],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)

    def test_cli_requires_teacher_key(self):
        env = {k: v for k, v in os.environ.items() if k != "UATU_TEACHER_PUBLIC_KEY"}
        res = subprocess.run([*CLI, "--repo", "."], capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 1)


if __name__ == "__main__":
    unittest.main()
