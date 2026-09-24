#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["cryptography>=42"]
# ///
"""
Validador de Integridad, Forense y Descifrado Uatu v2.1.

Audita las ramas huérfanas de telemetría (refs/heads/uatu-audit/<user>/<uuid>)
de una entrega: verifica la firma docente del manifiesto, la cadena de hashes,
las firmas Ed25519 de cada evento y de cada micro-lote, el bloque génesis, la
ventana temporal y aplica heurísticas forenses. Opcionalmente descifra los
sobres ECIES (X25519 + HKDF-SHA256 + AES-256-GCM) con la clave privada docente.

Códigos de salida POSIX:
  0  OK: integridad criptográfica verificada sin anomalías.
  1  CRITICAL ERROR: falla de integridad o ausencia de registros.
  2  WARNING: cadena íntegra pero con alertas heurísticas.

Única dependencia externa: `cryptography`. El módulo es autocontenido: se
instala como `uatu-audit` (uv tool install) o se ejecuta suelto con
`uv run audit.py`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key

VERSION = "2.1"
HKDF_INFO = b"uatu-clipboard-envelope-v2"
ENVELOPE_ALGORITHM = "X25519-AES-256-GCM"
STUDENT_KEY_PREFIX = "ed25519:"
EMPTY_COMMIT_SHA = "0" * 40
INSERTION_EVENTS = ("clipboard_paste", "external_insertion")


# --------------------------------------------------------------------------- primitivas


def canonical(obj: Any) -> bytes:
    """Serialización canónica compartida con la extensión (sección 5.2)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def without(obj: Dict[str, Any], key: str) -> Dict[str, Any]:
    return {k: v for k, v in obj.items() if k != key}


def event_hash(event: Dict[str, Any]) -> str:
    """H_i = SHA-256(Serialize(evento sin firma))."""
    return sha256_hex(canonical(without(event, "signature")))


def batch_hash(batch: Dict[str, Any]) -> str:
    return sha256_hex(canonical(without(batch, "batch_signature")))


def genesis_hash(initial_commit: str, config_sha256: str, github_user: str, student_pub_hex: str) -> str:
    """H_0 = SHA-256(Initial_Commit_SHA || SHA-256(.uatu.conf) || GitHub_User || Student_Pubkey)."""
    return sha256_hex((initial_commit + config_sha256 + github_user + student_pub_hex).encode("utf-8"))


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def verify_ed25519(public_hex: str, signature_hex: str, message: bytes) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        key.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def fmt_duration(ms: int) -> str:
    seconds = int(ms // 1000)
    return f"{seconds // 60}m {seconds % 60:02d}s"


def snippet(text: str, limit: int = 100) -> str:
    flat = text.replace("\r\n", "\n").replace("\n", " ⏎ ").replace("`", "'")
    return flat[:limit] + ("..." if len(flat) > limit else "")


# --------------------------------------------------------------------------- modelo


@dataclass
class SessionReport:
    branch: str
    ref: str
    github_user: str = ""
    session_uuid: str = ""
    batches: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    closed_reason: Optional[str] = None
    pastes: int = 0
    external_insertions: int = 0
    unfocused_ms: int = 0
    disallowed: List[str] = field(default_factory=list)
    flagged: List[str] = field(default_factory=list)


class UatuAuditor:
    def __init__(
        self,
        repo_path: str,
        teacher_verify_key_hex: str,
        teacher_decrypt_key_pem: Optional[str] = None,
        max_paste_chars: int = 50,
        target_user: Optional[str] = None,
        remote: Optional[str] = None,
        grace_seconds: int = 60,
        code_ref: str = "HEAD",
    ):
        self.repo = repo_path
        self.teacher_verify_key_hex = teacher_verify_key_hex.strip()
        self.teacher_decrypt_key_pem = teacher_decrypt_key_pem
        self.max_paste_chars = max_paste_chars
        self.target_user = target_user.strip() if target_user else None
        self.remote_override = remote
        self.grace = timedelta(seconds=grace_seconds)
        self.code_ref = code_ref
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.sessions: Dict[str, SessionReport] = {}
        self.config: Dict[str, Any] = {}
        self.config_sha256: Optional[str] = None
        self._decrypt_key: Optional[x25519.X25519PrivateKey] = None
        self._decrypt_key_error: Optional[str] = None

    # ------------------------------------------------------------------ git

    def _git(self, cmd: List[str]) -> str:
        res = subprocess.run(
            ["git", "-C", self.repo] + cmd,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
        return res.stdout.strip()

    # ------------------------------------------------------------------ manifiesto

    def verify_config(self) -> Dict[str, Any]:
        cfg_path = os.path.join(self.repo, ".uatu.conf")
        if not os.path.exists(cfg_path):
            self.errors.append("Falta el archivo de configuración .uatu.conf.")
            return {}

        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            self.errors.append(f".uatu.conf ilegible: {e}")
            return {}
        if not isinstance(cfg, dict):
            self.errors.append(".uatu.conf no contiene un objeto JSON.")
            return {}

        sig = str(cfg.get("crypto", {}).get("signature", ""))
        if not verify_ed25519(self.teacher_verify_key_hex, sig, canonical(without(cfg, "crypto"))):
            self.errors.append("Firma docente en .uatu.conf INVÁLIDA: el manifiesto fue alterado o la clave no corresponde.")

        self.config = cfg
        self.config_sha256 = sha256_hex(canonical(cfg))
        return cfg

    @property
    def _session_cfg(self) -> Dict[str, Any]:
        return self.config.get("session", {}) if isinstance(self.config.get("session"), dict) else {}

    def _window(self) -> Tuple[Optional[datetime], Optional[datetime]]:
        s = self._session_cfg
        start = parse_utc(s["start_utc"]) if s.get("start_utc") else None
        deadline = parse_utc(s["deadline_utc"]) if s.get("deadline_utc") else None
        return start, deadline

    # ------------------------------------------------------------------ descubrimiento

    def discover_telemetry_branches(self, prefix: str = "uatu-audit") -> List[Tuple[str, str]]:
        """Devuelve pares (rama, referencia completa) bajo el prefijo de telemetría."""
        remote = self.remote_override or self.config.get("git", {}).get("remote_name", "origin")
        found: List[Tuple[str, str]] = []
        try:
            for namespace in (f"refs/remotes/{remote}/", "refs/heads/"):
                raw = self._git(["for-each-ref", "--format=%(refname)", f"{namespace}{prefix}/"])
                for ref in raw.splitlines():
                    ref = ref.strip()
                    if ref:
                        found.append((ref[len(namespace):], ref))
                if found:
                    break
        except subprocess.CalledProcessError as e:
            self.errors.append(f"Fallo al listar ramas de Git: {e.stderr.strip()}")
            return []

        if self.target_user:
            found = [(b, r) for b, r in found if b.split("/")[-2:-1] == [self.target_user]]
        if not found:
            who = f" para el usuario '{self.target_user}'" if self.target_user else ""
            self.errors.append(f"No se encontraron ramas de telemetría con prefijo '{prefix}'{who} (ausencia de registros).")
        return sorted(found)

    def load_branch_batches(self, branch: str, ref: Optional[str] = None) -> List[Dict[str, Any]]:
        """Carga los lotes de la punta de la rama y audita la historia de commits."""
        ref = ref or f"refs/remotes/origin/{branch}"
        try:
            commits = self._git(["rev-list", "--reverse", "--parents", ref]).splitlines()
            seen_files: set = set()
            for idx, line in enumerate(commits):
                parts = line.split()
                sha, parents = parts[0], parts[1:]
                if idx == 0 and parents:
                    self.errors.append(f"[{branch}] La rama de telemetría no es huérfana (commit raíz {sha[:10]} tiene padres).")
                if len(parents) > 1:
                    self.errors.append(f"[{branch}] Commit de merge {sha[:10]} en la rama de telemetría.")
                changes = self._git(["diff-tree", "--no-commit-id", "--name-status", "-r", "--root", sha]).splitlines()
                for change in changes:
                    status, _, path = change.partition("\t")
                    if status != "A":
                        self.errors.append(
                            f"[{branch}] El commit {sha[:10]} modifica o elimina '{path}' (estado {status}): historia reescrita."
                        )
                    elif path in seen_files:
                        self.errors.append(f"[{branch}] '{path}' se agregó más de una vez.")
                    seen_files.add(path)

            batches = []
            files = self._git(["ls-tree", "-r", "--name-only", ref]).splitlines()
            for filename in files:
                if not filename.endswith(".json"):
                    continue
                parsed = json.loads(self._git(["show", f"{ref}:{filename}"]))
                if isinstance(parsed, dict) and "events" in parsed:
                    batches.append(parsed)
                else:
                    self.errors.append(f"[{branch}] Archivo inesperado en la rama de telemetría: {filename}")
            batches.sort(key=lambda b: b.get("batch_sequence_id", -1))
            return batches
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            detail = e.stderr.strip() if isinstance(e, subprocess.CalledProcessError) else str(e)
            self.errors.append(f"Error procesando eventos en rama {branch}: {detail}")
            return []

    # ------------------------------------------------------------------ descifrado

    def _load_decrypt_key(self) -> Optional[x25519.X25519PrivateKey]:
        if self._decrypt_key or self._decrypt_key_error or not self.teacher_decrypt_key_pem:
            return self._decrypt_key
        try:
            with open(self.teacher_decrypt_key_pem, "rb") as f:
                key = load_pem_private_key(f.read(), password=None)
            if not isinstance(key, x25519.X25519PrivateKey):
                raise ValueError("la clave provista no es X25519")
            self._decrypt_key = key
        except Exception as e:  # noqa: BLE001 - se reporta como texto
            self._decrypt_key_error = str(e)
        return self._decrypt_key

    def decrypt_payload(self, enc_dict: Dict[str, Any]) -> str:
        if not self.teacher_decrypt_key_pem:
            return "[Descifrado omitido: Clave privada no provista]"
        priv_key = self._load_decrypt_key()
        if priv_key is None:
            return f"[Fallo al cargar la clave privada docente: {self._decrypt_key_error}]"
        try:
            if enc_dict.get("algorithm") != ENVELOPE_ALGORITHM:
                raise ValueError(f"algoritmo no soportado: {enc_dict.get('algorithm')}")
            ephemeral_bytes = base64.b64decode(enc_dict["ephemeral_public_key"])
            iv = base64.b64decode(enc_dict["iv"])
            tag = base64.b64decode(enc_dict["auth_tag"])
            ciphertext = base64.b64decode(enc_dict["ciphertext_base64"])

            # Acepta la clave efímera cruda (32 bytes) o en SPKI DER.
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_bytes[-32:])
            shared_secret = priv_key.exchange(peer_public_key)
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=HKDF_INFO).derive(shared_secret)
            plaintext_bytes = AESGCM(derived_key).decrypt(iv, ciphertext + tag, None)
            return plaintext_bytes.decode("utf-8")
        except Exception as e:  # noqa: BLE001
            return f"[Fallo al descifrar contenido: {e}]"

    # ------------------------------------------------------------------ auditoría

    def audit_session(self, branch: str, batches: List[Dict[str, Any]], ref: str = "") -> SessionReport:
        report = SessionReport(branch=branch, ref=ref, batches=batches)
        parts = branch.split("/")
        branch_user = parts[-2] if len(parts) >= 3 else ""
        branch_uuid = parts[-1] if parts else ""
        report.github_user, report.session_uuid = branch_user, branch_uuid

        if not batches:
            self.errors.append(f"[{branch}] Rama sin lotes de telemetría.")
            return report

        err = lambda msg: self.errors.append(f"[{branch}] {msg}")  # noqa: E731
        warn = lambda msg: self.warnings.append(f"[{branch}] {msg}")  # noqa: E731

        # --- lotes -------------------------------------------------------
        events: List[Dict[str, Any]] = []
        prev_end: Optional[str] = None
        student_key_hex: Optional[str] = None
        for expected_seq, batch in enumerate(batches):
            seq = batch.get("batch_sequence_id")
            if seq != expected_seq:
                err(f"Lote faltante o fuera de orden: se esperaba {expected_seq} y se encontró {seq}.")
            if batch.get("session_uuid") != branch_uuid or batch.get("github_user") != branch_user:
                err(f"El lote {seq} declara sesión/usuario distintos a los de la rama.")
            batch_events = batch.get("events", [])
            if batch.get("events_count") != len(batch_events):
                err(f"El lote {seq} declara {batch.get('events_count')} eventos pero contiene {len(batch_events)}.")
            if batch_events:
                if batch.get("batch_start_hash") != batch_events[0].get("prev_hash"):
                    err(f"batch_start_hash del lote {seq} no coincide con su primer evento.")
                if batch.get("batch_end_hash") != event_hash(batch_events[-1]):
                    err(f"batch_end_hash del lote {seq} no coincide con su último evento.")
            if prev_end is not None and batch.get("batch_start_hash") != prev_end:
                err(f"Ruptura de encadenamiento entre los lotes {expected_seq - 1} y {seq}.")
            prev_end = batch.get("batch_end_hash")
            if student_key_hex is None and batch_events:
                student_key_hex = str(batch_events[0].get("student_public_key", "")).replace(STUDENT_KEY_PREFIX, "")
            if not batch.get("batch_signature"):
                warn(f"El lote {seq} no tiene firma de lote (sesión recuperada sin clave).")
            elif not student_key_hex or not verify_ed25519(
                student_key_hex, batch["batch_signature"], bytes.fromhex(batch_hash(batch))
            ):
                err(f"Firma del lote {seq} inválida.")
            events.extend(batch_events)

        report.events = events
        if not events:
            err("La sesión no contiene eventos.")
            return report
        if not student_key_hex:
            err("La sesión carece de student_public_key en génesis.")
            return report

        # --- génesis -----------------------------------------------------
        genesis = events[0]
        gdata = genesis.get("data", {}) if isinstance(genesis.get("data"), dict) else {}
        if genesis.get("event_type") != "session_start":
            err("El primer evento no es session_start: falta el bloque génesis.")
        else:
            if gdata.get("session_uuid") != branch_uuid or gdata.get("github_user") != branch_user:
                err("El génesis declara una sesión o usuario distintos a los de la rama (posible suplantación).")
            expected_h0 = genesis_hash(
                str(gdata.get("initial_commit_sha", "")),
                str(gdata.get("config_sha256", "")),
                str(gdata.get("github_user", "")),
                student_key_hex,
            )
            if genesis.get("prev_hash") != expected_h0:
                err("El hash génesis H_0 no corresponde a los datos declarados.")
            if self.config_sha256 and gdata.get("config_sha256") != self.config_sha256:
                err("El génesis se ancló a un .uatu.conf distinto al de la entrega (alteración de reglas).")
            initial = str(gdata.get("initial_commit_sha", ""))
            if initial == EMPTY_COMMIT_SHA:
                warn("La sesión comenzó sobre un repositorio sin commits (commit inicial vacío).")
            elif initial and not self._is_root_commit(initial):
                err(f"El commit inicial declarado ({initial[:10]}) no es un commit raíz de este repositorio.")
            offset = gdata.get("clock_offset_ms")
            if isinstance(offset, int) and abs(offset) >= 30_000:
                warn(f"Desfase de reloj local de {offset / 1000:.0f} s respecto de la fuente confiable al iniciar.")

        # --- cadena, firmas y reglas ---------------------------------------
        start_dt, deadline_dt = self._window()
        heartbeat_s = int(self._session_cfg.get("heartbeat_interval_seconds", 120) or 120)
        gap_limit = timedelta(seconds=max(3 * heartbeat_s, 60))
        prev_hash_expected = genesis.get("prev_hash")
        prev_dt: Optional[datetime] = None
        last_unfocused_total = 0

        for idx, ev in enumerate(events):
            seq = ev.get("sequence_id", idx)
            etype = ev.get("event_type")
            data = ev.get("data", {}) if isinstance(ev.get("data"), dict) else {}

            if seq != idx:
                err(f"sequence_id {seq} fuera de orden (se esperaba {idx}): eventos eliminados o reordenados.")
            if ev.get("prev_hash") != prev_hash_expected:
                err(f"Ruptura de hash-chain en seq {seq}: {ev.get('prev_hash')} != {prev_hash_expected}")
            if str(ev.get("student_public_key", "")).replace(STUDENT_KEY_PREFIX, "") != student_key_hex:
                err(f"La clave del estudiante cambia en seq {seq}.")

            h = event_hash(ev)
            if not verify_ed25519(student_key_hex, str(ev.get("signature", "")), bytes.fromhex(h)):
                err(f"Firma digital del estudiante inválida en seq {seq}.")
            prev_hash_expected = h

            # Ventana temporal
            ts_str = ev.get("timestamp_utc")
            try:
                ev_dt = parse_utc(ts_str) if ts_str else None
            except ValueError:
                ev_dt = None
                err(f"Marca temporal inválida en seq {seq}: {ts_str}")
            if ev_dt:
                recovered_end = etype == "session_end" and str(data.get("reason", "")).startswith("recovered")
                if start_dt and ev_dt < start_dt:
                    err(f"Evento {seq} registrado antes de start_utc ({ts_str} < {self._session_cfg.get('start_utc')}).")
                if deadline_dt and ev_dt > deadline_dt + self.grace and not recovered_end:
                    warn(f"Evento {seq} emitido con posterioridad al deadline_utc ({ts_str} > {self._session_cfg.get('deadline_utc')}).")
                if prev_dt and ev_dt < prev_dt:
                    warn(f"El reloj retrocedió entre seq {seq - 1} y {seq} ({prev_dt.isoformat()} -> {ts_str}).")
                if prev_dt and ev_dt - prev_dt > gap_limit and not recovered_end:
                    warn(
                        f"Silencio de telemetría de {fmt_duration(int((ev_dt - prev_dt).total_seconds() * 1000))} "
                        f"antes de seq {seq} (posible desactivación de la extensión)."
                    )
                report.first_ts = report.first_ts or ev_dt
                report.last_ts = ev_dt
                prev_dt = ev_dt

            # Heurísticas
            if etype in INSERTION_EVENTS:
                self._audit_insertion(branch, report, seq, etype, data)
            elif etype == "window_focus":
                total = data.get("unfocused_total_ms")
                if isinstance(total, int):
                    last_unfocused_total = max(last_unfocused_total, total)
            elif etype == "heartbeat":
                total = data.get("unfocused_total_ms")
                if isinstance(total, int):
                    last_unfocused_total = max(last_unfocused_total, total)
            elif etype == "disallowed_extension":
                ext = f"{data.get('extension_id')} ({data.get('state')})"
                report.disallowed.append(ext)
                if data.get("state") != "removed":
                    warn(f"Extensión no autorizada detectada en seq {seq}: {ext}.")
            elif etype == "clock_skew":
                warn(f"Desfase de reloj registrado en seq {seq}: {data.get('offset_ms')} ms.")
            elif etype == "config_changed":
                if data.get("signature_valid") is True:
                    warn(f"El manifiesto cambió durante la sesión (seq {seq}) con firma docente válida.")
                else:
                    err(f"El manifiesto fue alterado o eliminado durante la sesión (seq {seq}): {json.dumps(data, ensure_ascii=False)}")
            elif etype == "session_end":
                report.closed_reason = str(data.get("reason", ""))

        report.unfocused_ms = last_unfocused_total
        if report.closed_reason is None:
            warn("La sesión no registra session_end: cierre abrupto o extensión deshabilitada.")
        elif report.closed_reason == "recovered_without_key":
            warn("La sesión se cerró por recuperación sin la clave de sesión.")
        return report

    def _audit_insertion(self, branch: str, report: SessionReport, seq: int, etype: str, data: Dict[str, Any]) -> None:
        chars = data.get("char_count", 0) if isinstance(data.get("char_count"), int) else 0
        if etype == "clipboard_paste":
            report.pastes += 1
        else:
            report.external_insertions += 1

        decrypted: Optional[str] = None
        if isinstance(data.get("encrypted_payload"), dict) and self.teacher_decrypt_key_pem:
            decrypted = self.decrypt_payload(data["encrypted_payload"])
            if not decrypted.startswith("[Fallo"):
                if sha256_hex(decrypted.encode("utf-8")) != data.get("sha256_plaintext"):
                    self.errors.append(f"[{branch}] El contenido descifrado en seq {seq} no coincide con sha256_plaintext.")

        suspicious_external = etype == "external_insertion" and data.get("window_focused") is False
        if chars > self.max_paste_chars or suspicious_external:
            kind = "Pegado masivo" if etype == "clipboard_paste" else "Inserción externa"
            if suspicious_external:
                kind += " con el editor sin foco"
            if decrypted is not None:
                text = decrypted
            elif isinstance(data.get("encrypted_payload"), dict):
                text = self.decrypt_payload(data["encrypted_payload"])
            else:
                text = "[sin contenido cifrado]"
            message = (
                f"[{report.github_user}] {kind} ({chars} chars) en seq {seq} sobre '{data.get('target_file')}'. "
                f"Snippet: {snippet(text)}"
            )
            self.warnings.append(message)
            report.flagged.append(message)

    def _is_root_commit(self, sha: str) -> bool:
        try:
            parents = self._git(["rev-list", "--parents", "-n", "1", sha]).split()
            return len(parents) == 1
        except subprocess.CalledProcessError:
            return False

    # ------------------------------------------------------------------ correlación

    def check_code_commits(self) -> None:
        """Commits de código dentro de la ventana que ocurren sin telemetría activa."""
        start_dt, deadline_dt = self._window()
        spans = [(s.first_ts, s.last_ts) for s in self.sessions.values() if s.first_ts and s.last_ts]
        if not (start_dt and deadline_dt and spans):
            return
        heartbeat_s = int(self._session_cfg.get("heartbeat_interval_seconds", 120) or 120)
        slack = timedelta(seconds=max(3 * heartbeat_s, 60))
        try:
            log = self._git(["log", self.code_ref, "--format=%H %cI %s"])
        except subprocess.CalledProcessError:
            return
        for line in log.splitlines():
            sha, _, rest = line.partition(" ")
            iso, _, subject = rest.partition(" ")
            try:
                when = parse_utc(iso)
            except ValueError:
                continue
            if not (start_dt <= when <= deadline_dt):
                continue
            if not any(a - slack <= when <= b + slack for a, b in spans):
                self.warnings.append(
                    f"Commit de código {sha[:10]} ({iso}, '{subject}') fuera de todo período con telemetría activa."
                )

    def consolidate(self) -> Dict[str, List[Tuple[datetime, str, Dict[str, Any]]]]:
        """Línea de tiempo cronológica por usuario combinando todas sus sesiones."""
        timeline: Dict[str, List[Tuple[datetime, str, Dict[str, Any]]]] = {}
        for report in self.sessions.values():
            for ev in report.events:
                try:
                    when = parse_utc(ev["timestamp_utc"])
                except (KeyError, ValueError):
                    continue
                timeline.setdefault(report.github_user, []).append((when, report.session_uuid, ev))
        for user in timeline:
            timeline[user].sort(key=lambda item: (item[0], item[1], item[2].get("sequence_id", 0)))
        return timeline

    # ------------------------------------------------------------------ orquestación

    def run(self) -> None:
        cfg = self.verify_config()
        if not cfg:
            return

        prefix = cfg.get("git", {}).get("telemetry_branch_prefix", "uatu-audit")
        for branch, ref in self.discover_telemetry_branches(prefix):
            batches = self.load_branch_batches(branch, ref)
            self.sessions[branch] = self.audit_session(branch, batches, ref)
        self.check_code_commits()

    @property
    def status(self) -> str:
        if self.errors:
            return "❌ FALLO / MANIPULACIÓN"
        if self.warnings:
            return "⚠️ ADVERTENCIAS"
        return "✅ AUDITORÍA LIMPIA"

    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0

    def write_summary(self, path: str) -> None:
        total_batches = sum(len(s.batches) for s in self.sessions.values())
        total_events = sum(len(s.events) for s in self.sessions.values())

        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Reporte de Auditoría Uatu: {self.status}\n\n")
            if self.config.get("exam_id"):
                f.write(f"- **Examen:** `{self.config.get('exam_id')}`\n")
            if self.target_user:
                f.write(f"- **Usuario auditado:** `{self.target_user}`\n")
            f.write(f"- **Ramas/Sesiones Auditadas:** {len(self.sessions)}\n")
            f.write(f"- **Micro-Lotes Procesados:** {total_batches}\n")
            f.write(f"- **Total de Eventos Verificados:** {total_events}\n")
            f.write(f"- **Errores Críticos:** {len(self.errors)}\n")
            f.write(f"- **Advertencias / Pegados:** {len(self.warnings)}\n\n")

            if self.sessions:
                f.write("### Sesiones\n\n")
                f.write("| Usuario | Sesión | Inicio | Fin | Eventos | Pegados | Inserciones externas | Fuera de foco | Cierre |\n")
                f.write("|---|---|---|---|---|---|---|---|---|\n")
                for s in sorted(self.sessions.values(), key=lambda r: (r.github_user, r.first_ts or datetime.min.replace(tzinfo=timezone.utc))):
                    f.write(
                        f"| {s.github_user} | `{s.session_uuid[:8]}` | {s.first_ts.strftime('%H:%M:%S') if s.first_ts else '-'} "
                        f"| {s.last_ts.strftime('%H:%M:%S') if s.last_ts else '-'} | {len(s.events)} | {s.pastes} "
                        f"| {s.external_insertions} | {fmt_duration(s.unfocused_ms)} | {s.closed_reason or 'sin cierre'} |\n"
                    )
                f.write("\n")

            if self.errors:
                f.write("### Violaciones Críticas de Integridad\n")
                for e in self.errors:
                    f.write(f"- 🔴 {e}\n")
                f.write("\n")

            if self.warnings:
                f.write("### Evidencia de Pegado y Heurísticas\n")
                for w in self.warnings:
                    f.write(f"- 🟡 {w}\n")
                f.write("\n")

            timeline = self.consolidate()
            if timeline:
                f.write("### Línea de Tiempo Consolidada\n\n")
                for user, items in sorted(timeline.items()):
                    f.write(f"<details><summary>{user} — {len(items)} eventos</summary>\n\n")
                    f.write("| Hora UTC | Sesión | Seq | Evento | Detalle |\n|---|---|---|---|---|\n")
                    for when, session, ev in items:
                        f.write(
                            f"| {when.strftime('%H:%M:%S')} | `{session[:8]}` | {ev.get('sequence_id')} "
                            f"| {ev.get('event_type')} | {self._describe(ev)} |\n"
                        )
                    f.write("\n</details>\n")

    @staticmethod
    def _describe(ev: Dict[str, Any]) -> str:
        data = ev.get("data", {}) or {}
        etype = ev.get("event_type")
        if etype in INSERTION_EVENTS:
            return f"{data.get('char_count')} chars en `{data.get('target_file')}`"
        if etype == "window_focus":
            return "recupera foco" if data.get("focused") else "pierde foco"
        if etype == "disallowed_extension":
            return f"{data.get('extension_id')} ({data.get('state')})"
        if etype == "session_end":
            return str(data.get("reason", ""))
        if etype == "heartbeat":
            return f"uptime {data.get('uptime_seconds')} s"
        return ""

    def write_json(self, path: str) -> None:
        payload = {
            "version": VERSION,
            "status": {0: "ok", 1: "critical", 2: "warning"}[self.exit_code()],
            "exam_id": self.config.get("exam_id"),
            "errors": self.errors,
            "warnings": self.warnings,
            "sessions": [
                {
                    "branch": s.branch,
                    "github_user": s.github_user,
                    "session_uuid": s.session_uuid,
                    "batches": len(s.batches),
                    "events": len(s.events),
                    "first_event_utc": s.first_ts.isoformat() if s.first_ts else None,
                    "last_event_utc": s.last_ts.isoformat() if s.last_ts else None,
                    "clipboard_pastes": s.pastes,
                    "external_insertions": s.external_insertions,
                    "unfocused_ms": s.unfocused_ms,
                    "disallowed_extensions": s.disallowed,
                    "closed_reason": s.closed_reason,
                }
                for s in self.sessions.values()
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"Validador Forense Uatu v{VERSION}")
    parser.add_argument("--repo", default=".", help="Ruta del repositorio de la entrega")
    parser.add_argument(
        "--teacher-key",
        default=os.environ.get("UATU_TEACHER_PUBLIC_KEY"),
        help="Clave pública Ed25519 docente (hex). Por omisión $UATU_TEACHER_PUBLIC_KEY",
    )
    parser.add_argument("--decrypt-key", default=None, help="Clave privada docente X25519 (PEM) para descifrado")
    parser.add_argument("--md-out", default="summary.md", help="Reporte Markdown de salida")
    parser.add_argument("--json-out", default=None, help="Reporte JSON opcional para integraciones")
    parser.add_argument("--user", default=None, help="Auditar solo las sesiones de este usuario de GitHub")
    parser.add_argument("--remote", default=None, help="Remoto donde buscar las ramas (por omisión git.remote_name)")
    parser.add_argument("--max-paste-chars", type=int, default=50, help="Umbral heurístico de pegado masivo")
    parser.add_argument("--grace-seconds", type=int, default=60, help="Tolerancia posterior al deadline_utc")
    parser.add_argument("--code-ref", default="HEAD", help="Referencia de código a correlacionar con la telemetría")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    if not args.teacher_key:
        print("Se requiere --teacher-key o la variable UATU_TEACHER_PUBLIC_KEY.", file=sys.stderr)
        return 1

    auditor = UatuAuditor(
        args.repo,
        args.teacher_key,
        args.decrypt_key,
        max_paste_chars=args.max_paste_chars,
        target_user=args.user or None,
        remote=args.remote,
        grace_seconds=args.grace_seconds,
        code_ref=args.code_ref,
    )
    auditor.run()
    auditor.write_summary(args.md_out)
    if args.json_out:
        auditor.write_json(args.json_out)
    print(f"{auditor.status}: {len(auditor.errors)} errores, {len(auditor.warnings)} advertencias. Reporte: {args.md_out}")
    return auditor.exit_code()


if __name__ == "__main__":
    sys.exit(main())
