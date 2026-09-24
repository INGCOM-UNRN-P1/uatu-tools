# uatu-tools

Herramientas de línea de comandos de uatu, instalables con `uv tool`:

| Comando | Uso |
|---|---|
| `uatu-audit` | Validador forense para CI: verifica firmas, cadena, lotes y génesis de las ramas `uatu-audit/*`, aplica heurísticas y descifra evidencia. Códigos de salida 0/1/2. |
| `uatu-admin` | Herramientas de cátedra: claves raíz y docentes, registro de claves y firma de `.uatu.conf`. |

```bash
# Instalación como herramienta global (desde un clon del repositorio)
uv tool install ./cli

# O desde Git, sin clonar
uv tool install "git+https://github.com/<org>/uatu#subdirectory=cli"

# Ejecución efímera, sin instalar
uvx --from ./cli uatu-audit --help
```

`uatu_tools/audit.py` no depende del resto del paquete y declara sus
dependencias con metadatos PEP 723, por lo que también puede copiarse a un
repositorio y ejecutarse con `uv run audit.py ...`.

Pruebas:

```bash
uv run --project cli python -m unittest discover -s cli/tests -v
```
