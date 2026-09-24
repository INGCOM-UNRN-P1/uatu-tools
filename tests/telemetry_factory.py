"""
Fábrica de telemetría para pruebas: reproduce en Python, de forma
independiente, el formato que emite la extensión (eventos, lotes y rama
huérfana) para ejercitar el validador sin depender de Node.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import uatu_audit as ua
import uatu_admin

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Estudiante",
    "GIT_AUTHOR_EMAIL": "e@example.com",
    "GIT_COMMITTER_NAME": "Estudiante",
    "GIT_COMMITTER_EMAIL": "e@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}

START = datetime(2026, 9, 24, 13, 0, tzinfo=timezone.utc)
DEADLINE = datetime(2026, 9, 24, 16, 0, tzinfo=timezone.utc)


def git(repo: str, *args: str, input: Optional[bytes] = None, env: Optional[Dict[str, str]] = None) -> str:
    res = subprocess.run(
        ["git", "-C", repo, *args],
        input=input,
        capture_output=True,
        check=True,
        env={**os.environ, **GIT_ENV, **(env or {})},
    )
    return res.stdout.decode("utf-8").strip()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def raw_pub(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class TeacherKeys:
    def __init__(self) -> None:
        self.sign = Ed25519PrivateKey.generate()
        self.decrypt = x25519.X25519PrivateKey.generate()
        self.verify_hex = raw_pub(self.sign).hex()
        self.encrypt_raw = raw_pub(self.decrypt)

    def write_decrypt_pem(self, directory: str) -> str:
        path = os.path.join(directory, "teacher_x25519.pem")
        with open(path, "wb") as f:
            f.write(
                self.decrypt.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
        return path


def base_config(**session_overrides: Any) -> Dict[str, Any]:
    session = {
        "start_utc": "2026-09-24T13:00:00Z",
        "deadline_utc": "2026-09-24T16:00:00Z",
        "batch_interval_seconds": 30,
        "batch_max_events": 20,
        "sync_max_backoff_seconds": 60,
        "heartbeat_interval_seconds": 120,
    }
    session.update(session_overrides)
    return {
        "version": "2.1",
        "exam_id": "eval-sistemas-distribuidos-2026",
        "session": session,
        "auth": {"public_key_registry_url": "https://example.invalid/keys.json", "require_github_auth": True},
        "monitoring": {
            "clipboard": {"enabled": True, "character_threshold": 15, "encrypt_content": True, "hash_algorithm": "sha256"},
            "window_focus": True,
            "disallowed_extensions": ["github.copilot"],
        },
        "crypto": {"teacher_key_id": "prof-lead-2026", "signature": ""},
        "git": {"telemetry_branch_prefix": "uatu-audit", "remote_name": "origin", "auto_push": True},
    }


def make_exam_repo(teacher: TeacherKeys, config: Optional[Dict[str, Any]] = None) -> str:
    repo = tempfile.mkdtemp(prefix="uatu-py-")
    git(repo, "init", "-q", "-b", "main")
    with open(os.path.join(repo, "main.c"), "w") as f:
        f.write("int main(void) { return 0; }\n")
    signed = uatu_admin.sign_config(config or base_config(), teacher.sign)
    with open(os.path.join(repo, ".uatu.conf"), "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2)
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "enunciado", env={"GIT_COMMITTER_DATE": "2026-09-20T10:00:00Z", "GIT_AUTHOR_DATE": "2026-09-20T10:00:00Z"})
    return repo


def encrypt(plaintext: str, teacher_pub_raw: bytes) -> Dict[str, str]:
    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(teacher_pub_raw))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=ua.HKDF_INFO).derive(shared)
    iv = os.urandom(12)
    sealed = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return {
        "algorithm": ua.ENVELOPE_ALGORITHM,
        "ephemeral_public_key": base64.b64encode(raw_pub(eph)).decode(),
        "iv": base64.b64encode(iv).decode(),
        "auth_tag": base64.b64encode(sealed[-16:]).decode(),
        "ciphertext_base64": base64.b64encode(sealed[:-16]).decode(),
    }


class SessionFactory:
    """Genera la telemetría firmada de una sesión y la publica como rama huérfana."""

    def __init__(self, repo: str, user: str = "octocat", session_uuid: Optional[str] = None,
                 config_sha256: Optional[str] = None, prefix: str = "uatu-audit") -> None:
        self.repo = repo
        self.user = user
        self.session_uuid = session_uuid or str(uuid.uuid4())
        self.key = Ed25519PrivateKey.generate()
        self.pub_hex = raw_pub(self.key).hex()
        with open(os.path.join(repo, ".uatu.conf"), encoding="utf-8") as f:
            self.config_sha256 = config_sha256 or ua.sha256_hex(ua.canonical(json.load(f)))
        self.initial_commit = git(repo, "rev-list", "--max-parents=0", "HEAD").splitlines()[-1]
        self.genesis = ua.genesis_hash(self.initial_commit, self.config_sha256, user, self.pub_hex)
        self.events: List[Dict[str, Any]] = []
        self.last_hash = self.genesis
        self.ref = f"refs/heads/{prefix}/{user}/{self.session_uuid}"
        self.batches: List[Dict[str, Any]] = []

    def event(self, event_type: str, data: Dict[str, Any], when: datetime) -> Dict[str, Any]:
        unsigned = {
            "sequence_id": len(self.events),
            "prev_hash": self.last_hash,
            "timestamp_utc": iso(when),
            "student_public_key": ua.STUDENT_KEY_PREFIX + self.pub_hex,
            "event_type": event_type,
            "data": data,
        }
        h = ua.event_hash(unsigned)
        ev = {**unsigned, "signature": self.key.sign(bytes.fromhex(h)).hex()}
        self.events.append(ev)
        self.last_hash = h
        return ev

    def start(self, when: datetime = START + timedelta(minutes=1)) -> Dict[str, Any]:
        return self.event(
            "session_start",
            {
                "exam_id": "eval-sistemas-distribuidos-2026",
                "session_uuid": self.session_uuid,
                "github_user": self.user,
                "initial_commit_sha": self.initial_commit,
                "config_sha256": self.config_sha256,
                "teacher_key_id": "prof-lead-2026",
                "clock_offset_ms": 0,
            },
            when,
        )

    def paste(self, text: str, when: datetime, teacher: TeacherKeys, event_type: str = "clipboard_paste",
              focused: bool = True) -> Dict[str, Any]:
        return self.event(
            event_type,
            {
                "target_file": "src/scheduler.c",
                "range": {"start": [45, 0], "end": [45, len(text)]},
                "char_count": len(text),
                "change_count": 1,
                "sha256_plaintext": ua.sha256_hex(text.encode("utf-8")),
                "clipboard_match": event_type == "clipboard_paste",
                "window_focused": focused,
                "active_editor": True,
                "encrypted_payload": encrypt(text, teacher.encrypt_raw),
            },
            when,
        )

    def build_batch(self, events: List[Dict[str, Any]], seq: int, sign: bool = True) -> Dict[str, Any]:
        unsigned = {
            "version": "2.1",
            "batch_sequence_id": seq,
            "session_uuid": self.session_uuid,
            "github_user": self.user,
            "created_at_utc": events[-1]["timestamp_utc"],
            "head_code_commit": self.initial_commit,
            "batch_start_hash": events[0]["prev_hash"],
            "batch_end_hash": ua.event_hash(events[-1]),
            "events_count": len(events),
            "events": events,
        }
        sig = self.key.sign(bytes.fromhex(ua.batch_hash(unsigned))).hex() if sign else ""
        return {**unsigned, "batch_signature": sig}

    def commit_file(self, path: str, content: bytes) -> str:
        index = tempfile.mktemp(prefix="uatu-idx-")
        env = {"GIT_INDEX_FILE": index}
        try:
            parent = git(self.repo, "rev-parse", "--verify", "-q", self.ref)
        except subprocess.CalledProcessError:
            parent = ""
        if parent:
            git(self.repo, "read-tree", parent, env=env)
        else:
            git(self.repo, "read-tree", "--empty", env=env)
        blob = git(self.repo, "hash-object", "-w", "--stdin", input=content)
        git(self.repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
        tree = git(self.repo, "write-tree", env=env)
        args = ["commit-tree", tree, "-m", f"uatu: {path}"]
        if parent:
            args += ["-p", parent]
        commit = git(self.repo, *args)
        git(self.repo, "update-ref", self.ref, commit)
        return commit

    def publish(self, batch_sizes: Optional[List[int]] = None, sign_batches: bool = True) -> List[Dict[str, Any]]:
        """Empaqueta los eventos en lotes y los confirma en la rama huérfana."""
        sizes = batch_sizes or [len(self.events)]
        offset = len(sum((b["events"] for b in self.batches), []))
        for size in sizes:
            chunk = self.events[offset:offset + size]
            if not chunk:
                break
            batch = self.build_batch(chunk, len(self.batches), sign_batches)
            self.batches.append(batch)
            content = (json.dumps(batch, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            self.commit_file(f"batches/batch-{batch['batch_sequence_id']:06d}.json", content)
            offset += size
        return self.batches
