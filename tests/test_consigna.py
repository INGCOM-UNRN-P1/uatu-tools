"""Liberación de la consigna con bloqueo de tiempo (Ola 9, Decisión 1): sellar, liberar a la hora
de GitHub y auditar la liberación."""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uatu_tools import admin as uatu_admin  # noqa: E402
from uatu_tools import audit as ua  # noqa: E402
from uatu_tools import consigna  # noqa: E402
from uatu_tools.github import GitHubClient  # noqa: E402
from telemetry_factory import START, SessionFactory, TeacherKeys, base_config, git, make_exam_repo  # noqa: E402

ARCHIVOS = {"enunciado.md": "# Parcial\nImplementá `invertir`.\n".encode(), "tests/base.c": b"int main(void){return 0;}\n"}


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = uatu_admin.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def escribir_carpeta(base, archivos=ARCHIVOS):
    for ruta, contenido in archivos.items():
        destino = os.path.join(base, *ruta.split("/"))
        os.makedirs(os.path.dirname(destino), exist_ok=True)
        with open(destino, "wb") as f:
            f.write(contenido)
    return base


class PaqueteTests(unittest.TestCase):
    def test_sellar_y_abrir(self):
        paquete, clave = consigna.sellar(ARCHIVOS)
        self.assertEqual(paquete["sha256"], consigna.hash_archivos(ARCHIVOS))
        self.assertNotIn("invertir", json.dumps(paquete))
        self.assertEqual(consigna.abrir(paquete, clave, paquete["sha256"]), ARCHIVOS)

    def test_clave_incorrecta_o_paquete_alterado(self):
        paquete, clave = consigna.sellar(ARCHIVOS)
        with self.assertRaises(consigna.ConsignaError):
            consigna.abrir(paquete, os.urandom(32))
        otro = dict(paquete, sha256="0" * 64)
        with self.assertRaises(consigna.ConsignaError):
            consigna.abrir(otro, clave)  # el hash es dato asociado del cifrado
        with self.assertRaises(consigna.ConsignaError):
            consigna.abrir(paquete, clave, "f" * 64)  # no es la consigna del .uatu.conf

    def test_hash_de_carpeta(self):
        d = escribir_carpeta(tempfile.mkdtemp())
        self.assertEqual(consigna.hash_archivos(consigna.leer_carpeta(d)), consigna.hash_archivos(ARCHIVOS))
        # Valor fijo: la extensión (TypeScript) calcula lo mismo (test/consigna.test.ts).
        self.assertEqual(consigna.hash_archivos({"a.txt": b"hola\n"}),
                         consigna.hash_archivos({"a.txt": "hola\n".encode()}))
        self.assertEqual(consigna.hash_archivos({"a.txt": b"hola\n"}),
                         "7859017c979648d0896746364a6308bc0a38c80316cb57447475e34bbc4aae85")


class FakeGitHub:
    """La API de Git de GitHub en memoria, para un repositorio con la rama main."""

    def __init__(self):
        self.objetos = {"c0": {"tree": {"sha": "t0"}}, "t0": {"tree": [{"path": "main.c", "type": "blob"}]}}
        self.ref = "c0"
        self.llamadas = []
        self.n = 0

    def __call__(self, method, url, body, headers):
        ruta = url.split("api.github.com", 1)[1]
        self.llamadas.append((method, ruta))
        self.n += 1
        if method == "GET" and ruta == "/repos/org/examen-ana":
            return 200, {"default_branch": "main"}
        if method == "GET" and ruta.startswith("/orgs/org/repos"):
            return 200, [{"name": "examen-ana", "full_name": "org/examen-ana"}, {"name": "otro", "full_name": "org/otro"}]
        if method == "GET" and ruta.endswith("/git/ref/heads/main"):
            return 200, {"object": {"sha": self.ref}}
        if method == "GET" and "/git/commits/" in ruta:
            return 200, self.objetos[ruta.rsplit("/", 1)[1]]
        if method == "GET" and "/git/trees/" in ruta:
            return 200, self.objetos[ruta.rsplit("/", 1)[1]]
        if method == "POST" and ruta.endswith("/git/blobs"):
            return 201, {"sha": f"b{self.n}"}
        if method == "POST" and ruta.endswith("/git/trees"):
            sha = f"t{self.n}"
            base = self.objetos[body["base_tree"]]["tree"]
            raices = {e["path"].split("/")[0] for e in body["tree"]}
            self.objetos[sha] = {"tree": base + [{"path": r, "type": "tree"} for r in sorted(raices)], "entradas": body["tree"]}
            return 201, {"sha": sha}
        if method == "POST" and ruta.endswith("/git/commits"):
            sha = f"c{self.n}"
            self.objetos[sha] = {"tree": {"sha": body["tree"]}, "message": body["message"], "body": body}
            return 201, {"sha": sha}
        if method == "PATCH" and ruta.endswith("/git/refs/heads/main"):
            self.ref = body["sha"]
            return 200, {}
        return 404, {"message": "Not Found"}


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.config = os.path.join(self.dir, ".uatu.conf")
        with open(self.config, "w") as f:
            json.dump(base_config(), f)
        self.carpeta = escribir_carpeta(os.path.join(self.dir, "consigna-fuente"))
        self.paquete = os.path.join(self.dir, "consigna.enc")
        self.keys = os.path.join(self.dir, "keys")
        self.assertEqual(run("--keys-dir", self.keys, "keygen", "--key-id", "prof-lead-2026")[0], 0)
        code, out, err = run("--keys-dir", self.keys, "consigna", "sellar", self.carpeta, "--config", self.config,
                             "--salida", self.paquete, "--key-id", "prof-lead-2026")
        self.assertEqual(code, 0, err)

    def test_sellar(self):
        cfg = json.load(open(self.config))
        self.assertEqual(cfg["consigna"], {"carpeta": "consigna", "sha256": consigna.hash_archivos(ARCHIVOS)})
        self.assertEqual(stat.S_IMODE(os.stat(self.paquete + ".clave").st_mode), 0o600)
        code, _, _ = run("--keys-dir", self.keys, "verify-config", "--config", self.config)
        self.assertEqual(code, 0)  # quedó firmado con el bloque consigna
        code, out, _ = run("consigna", "hash", self.carpeta, "--config", self.config)
        self.assertEqual(code, 0)
        self.assertIn("Coincide", out)

    def liberar(self, ahora, fake, *extra):
        cliente = GitHubClient("t", transport=fake)
        with mock.patch.object(uatu_admin, "GitHubClient", return_value=cliente), \
                mock.patch.dict(os.environ, {"GH_TOKEN": "t"}):
            return run("consigna", "liberar", "--org", "org", "--prefijo", "examen-", "--config", self.config,
                       "--paquete", self.paquete, "--clave", self.paquete + ".clave", "--ahora", ahora, *extra)

    def test_no_libera_ni_descifra_antes_de_hora(self):
        fake = FakeGitHub()
        with mock.patch.object(consigna, "abrir", side_effect=AssertionError("descifró antes de hora")):
            code, _, err = self.liberar("2026-09-24T12:59:00Z", fake)
        self.assertEqual(code, 3, err)
        self.assertIn("faltan 60 s", err)
        self.assertEqual(fake.llamadas, [])

    def test_libera_a_la_hora_y_es_idempotente(self):
        fake = FakeGitHub()
        code, out, err = self.liberar("2026-09-24T13:00:00Z", fake)
        self.assertEqual(code, 0, err)
        self.assertIn("✓ org/examen-ana: liberada", out)
        self.assertNotIn("org/otro", out)
        commit = fake.objetos[fake.ref]
        self.assertTrue(commit["message"].startswith("uatu: liberar consigna"))
        self.assertNotIn("committer", commit["body"])  # fecha del servidor
        rutas = sorted(e["path"] for e in fake.objetos[commit["tree"]["sha"]]["entradas"])
        self.assertEqual(rutas, ["consigna/enunciado.md", "consigna/tests/base.c"])

        code, out, _ = self.liberar("2026-09-24T13:05:00Z", fake)
        self.assertEqual(code, 0)
        self.assertIn("= org/examen-ana: ya_estaba", out)

    def test_esperar(self):
        relojes = iter(["2026-09-24T12:59:30Z", "2026-09-24T13:00:01Z"])
        dormidas = []
        cfg = json.load(open(self.config))
        from datetime import datetime, timezone

        ahora = consigna.esperar_inicio(
            cfg, lambda: datetime.strptime(next(relojes), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
            True, dormidas.append)
        self.assertEqual(dormidas, [30.0])
        self.assertEqual(ahora.minute, 0)


class AuditoriaTests(unittest.TestCase):
    def setUp(self):
        self.teacher = TeacherKeys()
        cfg = base_config()
        cfg["consigna"] = {"carpeta": "consigna", "sha256": consigna.hash_archivos(ARCHIVOS)}
        self.repo = make_exam_repo(self.teacher, cfg)

    def commit_consigna(self, fecha, archivos=ARCHIVOS, mensaje="uatu: liberar consigna (abc)"):
        escribir_carpeta(os.path.join(self.repo, "consigna"), archivos)
        git(self.repo, "add", "consigna")
        git(self.repo, "commit", "-q", "-m", mensaje,
            env={"GIT_COMMITTER_DATE": fecha, "GIT_AUTHOR_DATE": fecha})

    def auditar(self):
        s = SessionFactory(self.repo)
        s.start(START + timedelta(minutes=2))
        s.event("consigna_verificada", {"sha256_esperado": "x", "sha256_obtenido": "x", "coincide": True},
                START + timedelta(minutes=3))
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        auditor = ua.UatuAuditor(self.repo, self.teacher.verify_hex)
        auditor.run()
        return auditor

    def test_liberacion_correcta(self):
        self.commit_consigna("2026-09-24T13:00:05Z")
        a = self.auditar()
        self.assertEqual(a.errors, [])
        self.assertEqual(a.warnings, [])

    def test_liberada_antes_de_hora(self):
        self.commit_consigna("2026-09-24T12:30:00Z")
        self.assertTrue(any("antes de start_utc" in e for e in self.auditar().errors))

    def test_contenido_distinto(self):
        self.commit_consigna("2026-09-24T13:00:05Z", {"enunciado.md": b"otra cosa\n"})
        self.assertTrue(any("no es la sellada" in e for e in self.auditar().errors))

    def test_entro_por_otro_commit(self):
        self.commit_consigna("2026-09-24T13:00:05Z", mensaje="agrego el enunciado")
        self.assertTrue(any("no por la liberación" in e for e in self.auditar().errors))

    def test_sin_liberar_y_verificacion_fallida_en_la_extension(self):
        s = SessionFactory(self.repo)
        s.start(START + timedelta(minutes=2))
        s.event("consigna_verificada", {"sha256_esperado": "a" * 64, "sha256_obtenido": "b" * 64, "coincide": False},
                START + timedelta(minutes=3))
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        a = ua.UatuAuditor(self.repo, self.teacher.verify_hex)
        a.run()
        self.assertTrue(any("no se liberó" in w for w in a.warnings))
        self.assertTrue(any("no coincide con la sellada" in w for w in a.warnings))


if __name__ == "__main__":
    unittest.main()
