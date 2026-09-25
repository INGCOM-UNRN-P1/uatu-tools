---
title: "Manual de Referencia: uatu-tools"
subtitle: "uatu-admin y uatu-audit — Gestión Criptográfica de Exámenes y Validación Forense"
author: "Cátedra de Algoritmos y Programación"
date: "2026-09-25"
---

(manual-uatu-tools)=
# uatu-tools — Gestión Criptográfica de Exámenes y Validación Forense

````{abstract}
**Rol en el ecosistema:** Herramientas de línea de comandos del lado docente de [uatu](https://github.com/INGCOM-UNRN-P1/uatu). `uatu-admin` administra claves, registro de docentes, manifiestos firmados y la configuración de GitHub; `uatu-audit` verifica la telemetría de las entregas, aplica heurísticas forenses y descifra la evidencia.
````

La guía de uso del sistema completo (estudiantes, cátedra, modelo de amenazas)
está en el [manual de uatu](https://github.com/INGCOM-UNRN-P1/uatu/blob/main/manual/index.md).
Este documento es la referencia exhaustiva de los comandos.

---

(manual-uatu-tools-instalacion)=
## 1. Instalación

```bash
uv tool install "git+https://github.com/INGCOM-UNRN-P1/uatu-tools"   # última versión
uv tool install "git+https://github.com/INGCOM-UNRN-P1/uatu-tools@v2.1.0"  # versión fija
uv tool upgrade uatu-tools
```

Sin instalar: `uvx --from "git+https://github.com/INGCOM-UNRN-P1/uatu-tools" uatu-audit --help`.

`src/uatu_tools/audit.py` es autocontenido (PEP 723) y también funciona suelto:
`uv run audit.py --help`.

Requisitos: Python 3.9+, `cryptography>=42`. Las operaciones sobre GitHub
(`keys export --gh-*`, `keys setup-*`, `protect-branches`) usan la CLI `gh` o
un token en `GH_TOKEN`/`GITHUB_TOKEN`.

### Variables de entorno

| Variable | Uso |
|---|---|
| `UATU_KEYS_DIR` | Ubicación del almacén de claves. |
| `XDG_CONFIG_HOME` | Base del almacén si no se define `UATU_KEYS_DIR` (`$XDG_CONFIG_HOME/uatu/keys`). |
| `UATU_TEACHER_PUBLIC_KEY` | Valor por omisión de `uatu-audit --teacher-key`. |
| `GH_TOKEN`, `GITHUB_TOKEN` | Token para la API de GitHub; si faltan se usa `gh auth token`. |

---

(manual-uatu-tools-almacen)=
## 2. Almacén de Claves

```
${UATU_KEYS_DIR:-${XDG_CONFIG_HOME:-~/.config}/uatu/keys}/   (0700)
├── <raíz>/     key.json · root.ed25519.pem
└── <docente>/  key.json · signing.ed25519.pem · decryption.x25519.pem
```

- Un directorio por clave (0700); los PEM privados son PKCS#8 sin cifrar (0600).
- `key.json` contiene solo datos públicos:

  ```json
  {
    "format": 1,
    "key_id": "prof-lead-2026",
    "kind": "teacher",
    "created_at_utc": "2026-09-25T13:10:59Z",
    "ed25519_verify_key": "ab53…",
    "x25519_encryption_key": "66fb…",
    "name": "Programación I - 2026"
  }
  ```

- Los identificadores admiten letras, dígitos, `.`, `_` y `-`. Nunca se
  sobrescribe una clave existente.

La opción global `--keys-dir DIR` (antes del subcomando) cambia el almacén en
cualquier invocación de `uatu-admin`.

---

(manual-uatu-tools-admin)=
## 3. `uatu-admin`

```
uatu-admin [--keys-dir DIR] <comando> [opciones]
```

Todos los comandos devuelven `0` si tienen éxito y `1` ante un error, que se
informa en una línea por stderr.

### 3.1 `root-keygen`

Genera la clave raíz institucional Ed25519.

| Opción | Descripción |
|---|---|
| `--key-id ID` | Identificador (obligatorio). |
| `--name TEXTO` | Descripción legible. |

Imprime en stdout `{"key_id", "kind", "directory", "anchor"}` y en stderr los
próximos pasos.

### 3.2 `keygen`

Genera el par docente: Ed25519 (firma de manifiestos) y X25519 (descifrado).

| Opción | Descripción |
|---|---|
| `--key-id ID` | Identificador; es el `crypto.teacher_key_id` de los manifiestos. |
| `--name TEXTO` | Descripción; se copia a la entrada del registro. |

`--out DIR` se acepta como sinónimo de `--keys-dir` por compatibilidad.

### 3.3 `keys list`

Lista las claves del almacén: identificador, tipo, prefijo de la clave
pública, fecha y descripción. `--json` devuelve los `key.json` completos.

### 3.4 `keys show ID`

Muestra los metadatos de una clave y las rutas de sus archivos.

### 3.5 `keys import ID`

Incorpora claves PEM existentes (valida el tipo de cada una).

| Opción | Descripción |
|---|---|
| `--root PEM` | Clave raíz Ed25519. |
| `--signing PEM --decryption PEM` | Claves docentes Ed25519 y X25519. |
| `--name TEXTO` | Descripción. |

### 3.6 `keys export ID [ID…]`

Extrae una clave en el formato que necesita cada destino.

| `--format` / `-f` | Tipo | Salida |
|---|---|---|
| `public` | ambos | `key.json` |
| `anchor` | raíz | `{"key_id", "ed25519_public_key"}` |
| `trust-anchors` | raíz (una o varias) | `{"anchors": [...]}` |
| `root-key` 🔒 | raíz | PEM privado |
| `root-key-path` | raíz | Ruta del PEM |
| `verify-key` | docente | Ed25519 pública (hex) |
| `encrypt-key` | docente | X25519 pública (hex) |
| `registry-entry` | docente | `{"<id>": {...}}` para el registro |
| `signing-key` 🔒 / `signing-key-path` | docente | PEM Ed25519 / ruta |
| `decryption-key` 🔒 / `decryption-key-path` | docente | PEM X25519 / ruta |

Destinos (uno por invocación; por omisión, stdout):

| Opción | Destino |
|---|---|
| `--out ARCHIVO` | Archivo (0600 si el formato es privado 🔒). |
| `--gh-secret NOMBRE` | Secreto de GitHub Actions (vía `gh secret set`, valor por stdin). |
| `--gh-variable NOMBRE` | Variable de Actions (rechazado para formatos 🔒). |
| `--repo OWNER/REPO` \| `--org ORG` | Alcance del secreto o variable. |
| `--visibility all\|private\|selected` | Visibilidad de un secreto de organización. |
| `--show-secret` | Permite mostrar un formato 🔒 en una terminal interactiva. |

```bash
uatu-admin keys export inicial_unrn -f trust-anchors
uatu-admin keys export prof-lead-2026 -f verify-key
uatu-admin keys export prof-lead-2026 -f decryption-key --out ~/respaldo/docente.pem
uatu-admin keys export prof-lead-2026 -f decryption-key | age -r "$RECIPIENT" > docente.pem.age
uatu-admin keys export prof-lead-2026 -f decryption-key --gh-secret UATU_TEACHER_PRIVATE_KEY --repo ORG/examen
```

### 3.7 `keys setup-audit ID`

Carga los dos secretos del workflow de evaluación forense:
`UATU_TEACHER_PUBLIC_KEY` (Ed25519 hex) y `UATU_TEACHER_PRIVATE_KEY` (PEM
X25519). Acepta `--repo`, `--org` y `--visibility`.

```bash
uatu-admin keys setup-audit prof-lead-2026 --repo ORG/examen
uatu-admin keys setup-audit prof-lead-2026 --org ORG --visibility private
```

### 3.8 `keys setup-anchors ID [ID…]`

Publica las anclas raíz donde las consume la extensión.

| Opción | Descripción |
|---|---|
| `--repo OWNER/REPO` | Carga la variable de Actions (por omisión `UATU_TRUST_ANCHORS`) que usa el workflow *Release* de uatu. |
| `--variable NOMBRE` | Otro nombre de variable. |
| `--file RUTA` | Escribe `trust-anchors.json`. |

### 3.9 `registry-add`

Agrega o reemplaza un docente en el registro (lo crea si no existe) y descarta
la firma previa.

| Opción | Descripción |
|---|---|
| `--registry ARCHIVO` | Registro (`keys.json`). |
| `--key-id ID` | Identificador del docente. |
| `--verify-key HEX --encrypt-key HEX` | Claves públicas; si se omiten, se toman del almacén. |
| `--name TEXTO` | Descripción (por omisión la del almacén). |
| `--not-before ISO`, `--not-after ISO` | Vigencia de la clave. |

### 3.10 `registry-sign`

Firma el registro con la clave raíz y fija `root_key_id` e `issued_at_utc`.

| Opción | Descripción |
|---|---|
| `--registry ARCHIVO` | Registro. |
| `--root-key-id ID` | Raíz (del almacén, salvo `--root-key`). |
| `--root-key PEM` | Clave raíz explícita. |

### 3.11 `verify-registry`

Verifica la firma raíz. `--anchor-key HEX` explícita o, por omisión, la del
almacén según el `root_key_id` del registro. Devuelve `1` si la firma es
inválida.

### 3.12 `sign-config`

Firma el manifiesto excluyendo el bloque `crypto`.

| Opción | Descripción |
|---|---|
| `--config ARCHIVO` | Por omisión `.uatu.conf`. |
| `--key-id ID` | Clave del almacén; se escribe como `crypto.teacher_key_id`. Por omisión, el `teacher_key_id` del manifiesto. |
| `--key PEM` | Clave Ed25519 explícita. |

### 3.13 `verify-config`

Verifica la firma del manifiesto con `--verify-key HEX` o con la clave del
almacén (`--key-id` o el `teacher_key_id` del manifiesto). Devuelve `1` si es
inválida.

### 3.14 `protect-branches`

Crea o actualiza (por nombre) un ruleset de GitHub que impide **borrar** y
**reescribir con force-push** las ramas `refs/heads/<prefijo>/**`, sin
excepciones ni siquiera para administradores. La creación de ramas y los push
con avance rápido siguen permitidos.

| Opción | Descripción |
|---|---|
| `--repo OWNER/REPO` | Ruleset del repositorio del examen. |
| `--org ORG --repo-pattern PATRÓN` | Ruleset de organización para los repositorios que coinciden (repetible; `~ALL` para todos). |
| `--prefix PREFIJO` | Prefijo de las ramas. |
| `--config ARCHIVO` | Manifiesto del que leer `git.telemetry_branch_prefix` (por omisión `.uatu.conf`; si no existe, `uatu-audit`). |
| `--name NOMBRE` | Nombre del ruleset (por omisión `uatu: telemetría inmutable`). |
| `--dry-run` | Muestra el endpoint y el JSON sin aplicarlos. |

```bash
uatu-admin protect-branches --repo ORG/examen --dry-run
uatu-admin protect-branches --org ORG --repo-pattern 'examen-parcial-1-*'
```

Requiere permisos de administración sobre el repositorio u organización.

---

(manual-uatu-tools-audit)=
## 4. `uatu-audit`

```
uatu-audit [--repo DIR] [--teacher-key HEX|ID] [--decrypt-key PEM|ID] [--key-id ID]
           [--md-out ARCHIVO] [--json-out ARCHIVO] [--user USUARIO] [--remote REMOTO]
           [--max-paste-chars N] [--grace-seconds N] [--code-ref REF] [--keys-dir DIR]
```

| Opción | Por omisión | Descripción |
|---|---|---|
| `--repo` | `.` | Repositorio de la entrega (con las ramas de telemetría descargadas). |
| `--teacher-key` | `$UATU_TEACHER_PUBLIC_KEY` | Ed25519 docente en hex o identificador del almacén. |
| `--decrypt-key` | — | PEM X25519 o identificador del almacén; sin ella no se descifra. |
| `--key-id` | — | Clave docente del almacén: verifica y descifra con ella. |
| `--keys-dir` | almacén por omisión | Ubicación del almacén. |
| `--md-out` | `summary.md` | Reporte Markdown. |
| `--json-out` | — | Reporte JSON. |
| `--user` | todos | Audita solo las ramas de ese usuario. |
| `--remote` | `git.remote_name` | Remoto donde buscar `refs/remotes/<remoto>/<prefijo>/*` (si no hay, se usan `refs/heads/`). |
| `--max-paste-chars` | 50 | Umbral de alerta para pegados. |
| `--grace-seconds` | 60 | Tolerancia posterior al deadline. |
| `--code-ref` | `HEAD` | Referencia de código a correlacionar con la telemetría. |

Sin `--teacher-key` ni `--key-id`, si el `crypto.teacher_key_id` del
manifiesto existe en el almacén, se usa esa clave y se informa por stderr.

### 4.1 Códigos de salida

| Código | Significado |
|---|---|
| `0` | OK: integridad criptográfica verificada sin anomalías. |
| `1` | CRITICAL: falla de integridad o ausencia de registros. |
| `2` | WARNING: cadena íntegra con alertas heurísticas. |

### 4.2 Verificaciones

**Críticas**: firma del manifiesto; rama huérfana sin merges y con commits que
solo agregan lotes; secuencia, conteo, encadenamiento y firma de cada lote;
génesis (`session_start`, H₀, manifiesto, commit raíz, usuario y sesión de la
rama); cadena de eventos (secuencia, `prev_hash`, clave constante, firma de
cada H_i); eventos anteriores a `start_utc`; manifiesto alterado en sesión;
contenido descifrado distinto de `sha256_plaintext`; ausencia de ramas.

**Heurísticas**: pegados sobre el umbral e inserciones externas (con snippet
descifrado), inserciones con el editor sin foco, eventos posteriores al
deadline, reloj que retrocede o desfasado, extensiones prohibidas, silencios
mayores a tres latidos, sesiones sin `session_end`, lotes sin firma y commits
de código dentro de la ventana sin telemetría activa.

### 4.3 Reporte JSON

```json
{
  "version": "2.1",
  "status": "ok | critical | warning",
  "exam_id": "demo-p1-2026",
  "errors": ["..."],
  "warnings": ["..."],
  "sessions": [
    {
      "branch": "uatu-audit/octocat/<uuid>",
      "github_user": "octocat",
      "session_uuid": "<uuid>",
      "batches": 3,
      "events": 7,
      "first_event_utc": "...",
      "last_event_utc": "...",
      "clipboard_pastes": 2,
      "external_insertions": 0,
      "unfocused_ms": 12000,
      "disallowed_extensions": [],
      "closed_reason": "deadline"
    }
  ]
}
```

---

(manual-uatu-tools-flujos)=
## 5. Flujos Completos

### 5.1 Puesta en marcha institucional

```bash
uatu-admin root-keygen --key-id inicial_unrn --name "Raíz institucional"
uatu-admin keys setup-anchors inicial_unrn --repo INGCOM-UNRN-P1/uatu
# en el repositorio uatu: git tag vX.Y.Z && git push origin vX.Y.Z
```

### 5.2 Alta de un docente

```bash
uatu-admin keygen --key-id prof-lead-2026 --name "Programación I - 2026"
uatu-admin registry-add --registry keys.json --key-id prof-lead-2026 --not-after 2027-03-31T23:59:59Z
uatu-admin registry-sign --registry keys.json --root-key-id inicial_unrn
uatu-admin verify-registry --registry keys.json
# publicar keys.json en la URL del registro
```

### 5.3 Preparación de un examen

```bash
cp uatu/templates/exam-repo/uatu.conf.example examen/.uatu.conf   # editar ventana y reglas
uatu-admin sign-config --config examen/.uatu.conf --key-id prof-lead-2026
uatu-admin keys setup-audit prof-lead-2026 --repo ORG/examen
uatu-admin protect-branches --repo ORG/examen --config examen/.uatu.conf
```

### 5.4 Corrección

```bash
cd entrega
git fetch origin '+refs/heads/uatu-audit/*:refs/remotes/origin/uatu-audit/*'
uatu-audit --md-out reporte.md --json-out reporte.json
```

---

(manual-uatu-tools-desarrollo)=
## 6. Desarrollo

```bash
uv sync
uv run pytest -q
```

El CI ejecuta la suite en Python 3.9, 3.11 y 3.13, verifica la instalación
como `uv tool` y corre las pruebas de la extensión uatu contra el validador del
commit en curso, para detectar roturas del protocolo compartido.
