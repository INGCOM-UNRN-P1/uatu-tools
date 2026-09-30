"""Contrato de línea de comandos (LINEAMIENTOS §3.2, N-ECO-04): --version/-v, -h y doctor --json."""

from __future__ import annotations

import json

import pytest

from uatu_tools import admin, audit


@pytest.mark.parametrize("modulo, nombre", [(audit, "uatu-audit"), (admin, "uatu-admin")])
@pytest.mark.parametrize("opcion", ["--version", "-v"])
def test_version(capsys, modulo, nombre, opcion):
    with pytest.raises(SystemExit) as salida:
        modulo.main([opcion])
    assert salida.value.code == 0
    assert capsys.readouterr().out.startswith(nombre)


@pytest.mark.parametrize("modulo", [audit, admin])
def test_ayuda_corta(capsys, modulo):
    with pytest.raises(SystemExit) as salida:
        modulo.main(["-h"])
    assert salida.value.code == 0
    ayuda = capsys.readouterr().out
    assert ayuda.startswith("uso: ") and "muestra esta ayuda y sale" in ayuda  # en español (N-ECO-14)


@pytest.mark.parametrize("modulo, argumentos, mensaje", [
    (admin, ["nada"], "'nada' no es ninguna de estas opciones: doctor, "),
    (admin, ["keygen"], "faltan los argumentos obligatorios: --key-id"),
    (audit, ["--max-paste-chars", "x"], "argumento --max-paste-chars: valor inválido (int): 'x'"),
    (audit, ["--repo"], "argumento --repo: necesita un valor"),
])
def test_errores_de_uso_en_espanol(capsys, modulo, argumentos, mensaje):
    with pytest.raises(SystemExit) as salida:
        modulo.main(argumentos)
    assert salida.value.code == 2
    error = capsys.readouterr().err
    assert "uso: " in error and mensaje in error


@pytest.mark.parametrize("modulo, nombre", [(audit, "uatu-audit"), (admin, "uatu-admin")])
def test_doctor_json(capsys, modulo, nombre):
    codigo = modulo.main(["doctor", "--json"])
    datos = json.loads(capsys.readouterr().out)
    assert datos["schema_version"] == "1.0.0"
    assert datos["herramienta"] == nombre
    assert codigo == (0 if datos["ok"] else 1)
    assert {c["nombre"] for c in datos["chequeos"]} >= {"python", "cryptography", "git"}
