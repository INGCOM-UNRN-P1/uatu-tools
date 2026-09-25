# uatu-tools

Herramientas de línea de comandos de [uatu](https://github.com/INGCOM-UNRN-P1/uatu),
el sistema de proctorización y auditoría criptográfica Git-native para
exámenes prácticos en VS Code.

| Comando | Uso |
|---|---|
| `uatu-audit` | Validador forense para CI: audita las ramas `uatu-audit/<usuario>/<sesión>` de una entrega (firmas Ed25519, hash-chain, micro-lotes, bloque génesis y ventana temporal), aplica heurísticas y descifra los pegados con la clave docente. |
| `uatu-admin` | Herramientas de cátedra: almacén de claves en `~/.config/uatu/keys`, registro público de claves docentes, firma de `.uatu.conf`, secretos de GitHub Actions y protección de las ramas de telemetría. |

📖 **[Manual de referencia](manual/index.md)** con todos los comandos y opciones.
La guía del sistema completo está en el
[manual de uatu](https://github.com/INGCOM-UNRN-P1/uatu/blob/main/manual/index.md),
y los formatos en su [`docs/protocolo.md`](https://github.com/INGCOM-UNRN-P1/uatu/blob/main/docs/protocolo.md).

## Instalación

Requiere [uv](https://docs.astral.sh/uv/) y Python 3.9+.

```bash
# Como herramienta global
uv tool install "git+https://github.com/INGCOM-UNRN-P1/uatu-tools"

# Desde un clon local
uv tool install .

# Sin instalar
uvx --from "git+https://github.com/INGCOM-UNRN-P1/uatu-tools" uatu-audit --help
```

`src/uatu_tools/audit.py` es autocontenido y declara sus dependencias con
metadatos PEP 723: también puede copiarse a un repositorio y ejecutarse con
`uv run audit.py ...`.

## Almacén de claves

`uatu-admin` guarda las claves en `~/.config/uatu/keys/<id>/` (directorios
0700, claves privadas 0600). La ubicación se cambia con `--keys-dir` o
`UATU_KEYS_DIR`. Los demás comandos aceptan el identificador de la clave en
lugar de rutas.

```bash
uatu-admin keys list
uatu-admin keys show prof-lead-2026
uatu-admin keys import prof-lead-2026 --signing firma.pem --decryption descifrado.pem
uatu-admin keys export prof-lead-2026 -f verify-key                 # hex para --teacher-key
uatu-admin keys export inicial_unrn -f trust-anchors                # anclas para la extensión
uatu-admin keys export prof-lead-2026 -f decryption-key --out docente.pem
```

## Flujo para la cátedra

1. **Clave raíz institucional** (una vez), embebida en la extensión a través
   de la variable `UATU_TRUST_ANCHORS` del repositorio uatu:

   ```bash
   uatu-admin root-keygen --key-id inicial_unrn --name "Raíz institucional"
   uatu-admin keys setup-anchors inicial_unrn --repo INGCOM-UNRN-P1/uatu
   ```

2. **Clave del docente y registro público**, que se publica en la URL de
   `auth.public_key_registry_url`:

   ```bash
   uatu-admin keygen --key-id prof-lead-2026 --name "Programación I - 2026"
   uatu-admin registry-add --registry keys.json --key-id prof-lead-2026
   uatu-admin registry-sign --registry keys.json --root-key-id inicial_unrn
   uatu-admin verify-registry --registry keys.json
   ```

3. **Manifiesto del examen**:

   ```bash
   uatu-admin sign-config --config .uatu.conf --key-id prof-lead-2026
   uatu-admin verify-config --config .uatu.conf
   ```

4. **Repositorio del examen en GitHub**: secretos del workflow forense y ramas
   de telemetría protegidas contra borrado y force-push:

   ```bash
   uatu-admin keys setup-audit prof-lead-2026 --repo ORG/examen
   uatu-admin protect-branches --repo ORG/examen
   # o, para todos los repositorios de una tarea de GitHub Classroom:
   uatu-admin protect-branches --org ORG --repo-pattern 'examen-parcial-1-*'
   ```

5. **Auditoría de una entrega** (con la clave en el almacén, `uatu-audit` la
   toma del `teacher_key_id` del manifiesto):

   ```bash
   git fetch origin '+refs/heads/uatu-audit/*:refs/remotes/origin/uatu-audit/*'
   uatu-audit --repo . --md-out reporte.md --json-out reporte.json [--user <github_user>]
   ```

   | Código | Significado |
   |---|---|
   | `0` | Integridad criptográfica verificada sin anomalías. |
   | `1` | Falla de integridad: cadena rota, firmas inválidas, manifiesto alterado o ausencia de registros. |
   | `2` | Cadena íntegra con alertas heurísticas: pegados masivos, inserciones externas, extensiones no autorizadas, silencios de telemetría. |

En GitHub Actions, el workflow de ejemplo de uatu
(`templates/exam-repo/.github/workflows/uatu-audit.yml`) clona este
repositorio y lo instala con `uv tool install`; la variable `UATU_TOOLS_REF`
permite fijar una versión.

## Desarrollo

```bash
uv sync
uv run pytest -q
```
