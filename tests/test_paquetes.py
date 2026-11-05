"""Paquetes de examen por estudiante (Ola 47): sellar, distribuir, liberar a la hora de GitHub y auditar."""

import base64
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
from uatu_tools import consigna, paquetes  # noqa: E402
from uatu_tools.github import GitHubClient  # noqa: E402
from telemetry_factory import START, SessionFactory, TeacherKeys, base_config, git, make_exam_repo  # noqa: E402
from test_consigna import FakeGitHub, escribir_carpeta, run  # noqa: E402

TEMA_1 = {"examen.pdf": b"%PDF tema 1"}
TEMA_2 = {"examen.pdf": b"%PDF tema 2", "datos/entrada.txt": b"3 1 2\n"}


class SellarTests(unittest.TestCase):
    def test_sellar_y_abrir(self):
        paquete, clave = paquetes.sellar("ana", TEMA_2)
        self.assertNotIn(base64.b64encode(b"tema 2").decode(), json.dumps(paquete))
        self.assertEqual(paquetes.abrir(paquete, clave, paquete["sha256"]), TEMA_2)

    def test_el_mismo_tema_no_se_nota_en_el_hash(self):
        self.assertNotEqual(paquetes.hash_paquete("ana", TEMA_1), paquetes.hash_paquete("beto", TEMA_1))

    def test_no_se_puede_cambiar_de_dueno_ni_de_clave(self):
        paquete, clave = paquetes.sellar("ana", TEMA_1)
        with self.assertRaises(consigna.ConsignaError):
            paquetes.abrir(dict(paquete, usuario="beto"), clave)
        with self.assertRaises(consigna.ConsignaError):
            paquetes.abrir(paquete, os.urandom(32))
        with self.assertRaises(consigna.ConsignaError):
            paquetes.abrir(paquete, clave, "f" * 64)

    def test_usuarios(self):
        self.assertEqual(paquetes.normalizar_usuario(" Ana-P "), "ana-p")
        for invalido in ("", "-ana", "ana_p", "../x", "a" * 40):
            with self.assertRaises(consigna.ConsignaError):
                paquetes.normalizar_usuario(invalido)

    def test_asignar_repos(self):
        asignados, sobrantes = paquetes.asignar_repos(
            ["org/parcial-ana", "org/parcial_Beto", "org/parcial-otro"], "parcial", ["ana", "beto", "carla"])
        self.assertEqual(asignados, {"ana": "org/parcial-ana", "beto": "org/parcial_Beto"})
        self.assertEqual(sobrantes, ["org/parcial-otro"])

    def test_vector_que_comparte_con_la_extension(self):
        """Mismos valores que test/paquete.test.ts de la extensión de uatu."""
        paquete, _ = paquetes.sellar("ana", {"a.txt": b"hola\n"}, bytes(range(32)), bytes(range(12)))
        self.assertEqual(paquete["sha256"], "b322f83db9bc4fe55775563853be533090479402006f12872400c42e14e5e866")
        self.assertEqual(paquete["datos"], "PCC3NbGdtjm3YbXq9tALNNK5uhaNAAt/59YO53QptUdUX3hf4g==")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.config = os.path.join(self.dir, ".uatu.conf")
        with open(self.config, "w") as f:
            json.dump(base_config(), f)
        self.fuente = os.path.join(self.dir, "repartidos")
        escribir_carpeta(os.path.join(self.fuente, "ana"), TEMA_1)
        escribir_carpeta(os.path.join(self.fuente, "beto"), TEMA_2)
        self.enc = os.path.join(self.dir, "paquetes.enc")
        self.claves = os.path.join(self.dir, "paquetes.claves")
        self.keys = os.path.join(self.dir, "keys")
        self.assertEqual(run("--keys-dir", self.keys, "keygen", "--key-id", "prof-lead-2026")[0], 0)
        code, _, err = run("--keys-dir", self.keys, "paquetes", "sellar", self.fuente, "--config", self.config,
                           "--salida", self.enc, "--claves", self.claves, "--key-id", "prof-lead-2026")
        self.assertEqual(code, 0, err)

    def comando(self, accion, fake, *extra):
        destino = extra if "--org" in extra else ("--repo", "org/examen-ana=ana", *extra)
        cliente = GitHubClient("t", transport=fake)
        with mock.patch.object(uatu_admin, "GitHubClient", return_value=cliente), \
                mock.patch.dict(os.environ, {"GH_TOKEN": "t"}):
            return run("paquetes", accion, "--config", self.config, "--paquetes", self.enc, *destino)

    def liberar(self, ahora, fake):
        return self.comando("liberar", fake, "--claves", self.claves, "--ahora", ahora)

    def rutas_publicadas(self, fake):
        return [e["path"] for o in fake.objetos.values() for e in o.get("entradas", [])]

    def test_sellar_firma_y_protege_las_claves(self):
        with open(self.config) as f:
            config = json.load(f)
        self.assertEqual(sorted(config["paquetes"]["hashes"]), ["ana", "beto"])
        self.assertTrue(config["crypto"]["signature"])
        self.assertEqual(stat.S_IMODE(os.stat(self.claves).st_mode), 0o600)
        with open(os.path.join(self.enc, "ana.json")) as f:
            self.assertEqual(json.load(f)["sha256"], config["paquetes"]["hashes"]["ana"])

    def test_consigna_y_paquetes_son_excluyentes(self):
        with open(self.config) as f:
            config = json.load(f)
        config["consigna"] = {"carpeta": "consigna", "sha256": "a" * 64}
        with open(self.config, "w") as f:
            json.dump(config, f)
        code, _, err = run("paquetes", "sellar", self.fuente, "--config", self.config, "--salida", self.enc,
                           "--claves", self.claves)
        self.assertNotEqual(code, 0)
        self.assertIn("consigna o paquetes", err)

    def test_distribuir_no_publica_la_clave(self):
        fake = FakeGitHub()
        code, _, err = self.comando("distribuir", fake)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rutas_publicadas(fake), [paquetes.ARCHIVO_PAQUETE])

    def test_un_estudiante_sin_repositorio_no_pasa_por_exito(self):
        code, _, err = self.comando("distribuir", FakeGitHub(), "--org", "org", "--prefijo", "examen")
        self.assertEqual(code, 1)
        self.assertIn("beto: no tiene repositorio", err)

    def test_no_libera_ni_lee_las_claves_antes_de_hora(self):
        fake = FakeGitHub()
        os.remove(self.claves)  # si las leyera, fallaría por otro motivo
        code, _, err = self.liberar("2026-09-24T12:59:00Z", fake)
        self.assertEqual(code, 3, err)
        self.assertEqual(self.rutas_publicadas(fake), [])

    def test_libera_a_la_hora_con_el_paquete_y_es_idempotente(self):
        fake = FakeGitHub()
        code, out, err = self.liberar("2026-09-24T13:00:00Z", fake)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rutas_publicadas(fake), [paquetes.ARCHIVO_PAQUETE, paquetes.ARCHIVO_CLAVE])
        anteriores = len(fake.llamadas)
        self.liberar("2026-09-24T13:00:10Z", fake)
        self.assertFalse([c for c in fake.llamadas[anteriores:] if c[0] != "GET"], "no vuelve a publicar")

    def test_una_clave_que_no_abre_no_se_publica(self):
        with open(self.claves) as f:
            claves = json.load(f)
        claves["ana"] = base64.b64encode(os.urandom(32)).decode()
        with open(self.claves, "w") as f:
            json.dump(claves, f)
        code, _, err = self.liberar("2026-09-24T13:00:00Z", FakeGitHub())
        self.assertNotEqual(code, 0)
        self.assertIn("No se pudo descifrar", err)


class AuditoriaTests(unittest.TestCase):
    def setUp(self):
        self.teacher = TeacherKeys()
        self.paquete, self.clave = paquetes.sellar("octocat", TEMA_1)
        cfg = base_config()
        cfg["paquetes"] = {"carpeta": "consigna", "hashes": {"octocat": self.paquete["sha256"]}}
        self.repo = make_exam_repo(self.teacher, cfg)

    def commit(self, ruta, contenido, mensaje, fecha):
        with open(os.path.join(self.repo, ruta), "w") as f:
            f.write(contenido)
        git(self.repo, "add", ruta)
        git(self.repo, "commit", "-q", "-m", mensaje, env={"GIT_COMMITTER_DATE": fecha, "GIT_AUTHOR_DATE": fecha})

    def distribuir(self, paquete=None):
        self.commit(paquetes.ARCHIVO_PAQUETE, json.dumps(paquete or self.paquete), "uatu: distribuir paquete (x)",
                    "2026-09-24T10:00:00Z")

    def liberar(self, fecha="2026-09-24T13:00:05Z", mensaje="uatu: liberar clave del paquete (x)", clave=None):
        self.commit(paquetes.ARCHIVO_CLAVE, consigna.codificar_clave(clave or self.clave) + "\n", mensaje, fecha)

    def auditar(self, usuario="octocat", evento=("paquete_abierto", {"clock_source": "http-date"})):
        s = SessionFactory(self.repo, user=usuario)
        s.start(START + timedelta(minutes=2))
        s.event(evento[0], evento[1], START + timedelta(minutes=3))
        s.event("session_end", {"reason": "deadline"}, START + timedelta(minutes=5))
        s.publish()
        auditor = ua.UatuAuditor(self.repo, self.teacher.verify_hex)
        auditor.run()
        return auditor

    def test_liberacion_correcta(self):
        self.distribuir()
        self.liberar()
        a = self.auditar()
        self.assertEqual([e for e in a.errors if "paquete" in e], [])
        self.assertEqual([w for w in a.warnings if "paquete" in w.lower()], [])

    def test_clave_antes_de_hora(self):
        self.distribuir()
        self.liberar("2026-09-24T12:00:00Z")
        self.assertTrue(any("antes de start_utc" in e for e in self.auditar().errors))

    def test_clave_por_otro_commit(self):
        self.distribuir()
        self.liberar(mensaje="agrego la clave")
        self.assertTrue(any("no por la liberación" in e for e in self.auditar().errors))

    def test_clave_que_no_abre(self):
        self.distribuir()
        self.liberar(clave=os.urandom(32))
        self.assertTrue(any("no abre el paquete" in e for e in self.auditar().errors))

    def test_paquete_de_otro_estudiante(self):
        ajeno, _ = paquetes.sellar("beto", TEMA_2)
        self.distribuir(ajeno)
        self.assertTrue(any("no es el sellado" in e for e in self.auditar().errors))

    def test_sesion_de_otro_usuario(self):
        self.distribuir()
        self.liberar()
        self.assertTrue(any("sesiones de @beto" in e for e in self.auditar(usuario="beto").errors))

    def test_sin_distribuir_o_sin_liberar(self):
        self.assertTrue(any("no se distribuyó" in w for w in self.auditar().warnings))

    def test_rechazo_y_reloj_sin_calibrar_quedan_como_advertencia(self):
        self.distribuir()
        self.liberar()
        a = self.auditar(evento=("paquete_rechazado", {"motivo": "paquete_de_otro"}))
        self.assertTrue(any("paquete_de_otro" in w for w in a.warnings))
        b = self.auditar(evento=("paquete_abierto", {"clock_source": "local"}))
        self.assertTrue(any("sin reloj calibrado" in w for w in b.warnings))
