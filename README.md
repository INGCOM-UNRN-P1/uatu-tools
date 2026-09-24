# uatu-tools

Herramientas de línea de comandos de [uatu](https://github.com/INGCOM-UNRN-P1/uatu),
el sistema de proctorización y auditoría criptográfica Git-native para
exámenes prácticos en VS Code.

| Comando | Uso |
|---|---|
| `uatu-audit` | Validador forense para CI: audita las ramas `uatu-audit/<usuario>/<sesión>` de una entrega (firmas Ed25519, hash-chain, micro-lotes, bloque génesis y ventana temporal), aplica heurísticas y descifra los pegados con la clave docente. |
| `uatu-admin` | Herramientas de cátedra: clave raíz institucional, claves docentes, registro público de claves y firma de `.uatu.conf`. |

Los formatos que verifica están especificados en
[`docs/protocolo.md`](https://github.com/INGCOM-UNRN-P1/uatu/blob/main/docs/protocolo.md)
del repositorio de uatu.

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

## Flujo para la cátedra

1. **Clave raíz institucional** (una vez). El `anchor` que imprime se copia en
   `extension/resources/trust-anchors.json` de uatu antes de empaquetar la
   extensión:

   ```bash
   uatu-admin root-keygen --out secretos/ --key-id uba-root-2026
   ```

2. **Claves del docente y registro público**, que se publica en la URL de
   `auth.public_key_registry_url`:

   ```bash
   uatu-admin keygen --out secretos/ --key-id prof-lead-2026
   uatu-admin registry-add --registry keys.json --key-id prof-lead-2026 \
       --verify-key <ed25519_verify_key> --encrypt-key <x25519_encryption_key>
   uatu-admin registry-sign --registry keys.json \
       --root-key secretos/uba-root-2026.root.pem --root-key-id uba-root-2026
   uatu-admin verify-registry --registry keys.json --anchor-key <anchor>
   ```

3. **Firma del manifiesto del examen**:

   ```bash
   uatu-admin sign-config --config .uatu.conf \
       --key secretos/prof-lead-2026.ed25519.pem --key-id prof-lead-2026
   uatu-admin verify-config --config .uatu.conf --verify-key <ed25519_verify_key>
   ```

4. **Auditoría de una entrega**:

   ```bash
   git fetch origin '+refs/heads/uatu-audit/*:refs/remotes/origin/uatu-audit/*'
   uatu-audit --repo . --teacher-key <ed25519_verify_key> \
       --decrypt-key secretos/prof-lead-2026.x25519.pem \
       --md-out reporte.md --json-out reporte.json [--user <github_user>]
   ```

   | Código | Significado |
   |---|---|
   | `0` | Integridad criptográfica verificada sin anomalías. |
   | `1` | Falla de integridad: cadena rota, firmas inválidas, manifiesto alterado o ausencia de registros. |
   | `2` | Cadena íntegra con alertas heurísticas: pegados masivos, inserciones externas, extensiones no autorizadas, silencios de telemetría. |

   Opciones heurísticas: `--max-paste-chars` (50), `--grace-seconds` (60),
   `--code-ref` (`HEAD`) y `--remote` (por omisión `git.remote_name` del
   manifiesto).

En GitHub Actions, el workflow de ejemplo de uatu
(`templates/exam-repo/.github/workflows/uatu-audit.yml`) clona este
repositorio y lo instala con `uv tool install`; la variable `UATU_TOOLS_REF`
permite fijar una versión.

## Desarrollo

```bash
uv sync
uv run pytest -q
```
