"""
Almacén local de claves de uatu.

Organiza el material criptográfico de la cátedra en un directorio por clave:

    ~/.config/uatu/keys/                 (0700)
    ├── inicial_unrn/                    clave raíz institucional
    │   ├── key.json                     metadatos públicos (ancla)
    │   └── root.ed25519.pem             privada (0600)
    └── prof-lead-2026/                  clave docente
        ├── key.json                     metadatos públicos
        ├── signing.ed25519.pem          firma de .uatu.conf (0600)
        └── decryption.x25519.pem        descifrado de evidencia (0600)

La ubicación se puede cambiar con --keys-dir o con la variable UATU_KEYS_DIR;
por omisión respeta XDG_CONFIG_HOME.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_FILE = "key.json"
ROOT_PEM = "root.ed25519.pem"
SIGNING_PEM = "signing.ed25519.pem"
DECRYPTION_PEM = "decryption.x25519.pem"

KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class KeyStoreError(Exception):
    pass


def default_keys_dir() -> str:
    """UATU_KEYS_DIR, o ${XDG_CONFIG_HOME:-~/.config}/uatu/keys."""
    explicit = os.environ.get("UATU_KEYS_DIR")
    if explicit:
        return os.path.expanduser(explicit)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "uatu", "keys")


def raw_public_hex(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def private_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _write_secret(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class StoredKey:
    key_id: str
    kind: str  # "root" | "teacher"
    directory: str
    info: Dict[str, Any]

    def path(self, filename: str) -> str:
        return os.path.join(self.directory, filename)

    @property
    def root_key_path(self) -> str:
        self._require("root")
        return self.path(ROOT_PEM)

    @property
    def signing_key_path(self) -> str:
        self._require("teacher")
        return self.path(SIGNING_PEM)

    @property
    def decryption_key_path(self) -> str:
        self._require("teacher")
        return self.path(DECRYPTION_PEM)

    @property
    def anchor(self) -> Dict[str, str]:
        self._require("root")
        return {"key_id": self.key_id, "ed25519_public_key": self.info["ed25519_public_key"]}

    @property
    def verify_key(self) -> str:
        self._require("teacher")
        return self.info["ed25519_verify_key"]

    @property
    def encrypt_key(self) -> str:
        self._require("teacher")
        return self.info["x25519_encryption_key"]

    def registry_entry(self) -> Dict[str, str]:
        entry = {"ed25519_verify_key": self.verify_key, "x25519_encryption_key": self.encrypt_key}
        if self.info.get("name"):
            entry["name"] = self.info["name"]
        return entry

    def _require(self, kind: str) -> None:
        if self.kind != kind:
            nombre = "raíz" if kind == "root" else "docente"
            raise KeyStoreError(f"La clave '{self.key_id}' no es una clave {nombre} (es de tipo '{self.kind}').")


class KeyStore:
    def __init__(self, directory: Optional[str] = None) -> None:
        self.directory = os.path.abspath(os.path.expanduser(directory or default_keys_dir()))

    # ------------------------------------------------------------------ helpers

    def _key_dir(self, key_id: str) -> str:
        if not KEY_ID_RE.match(key_id):
            raise KeyStoreError(f"Identificador de clave inválido: '{key_id}' (use letras, dígitos, '.', '_' o '-').")
        return os.path.join(self.directory, key_id)

    def _new_key_dir(self, key_id: str) -> str:
        path = self._key_dir(key_id)
        if os.path.exists(path):
            raise KeyStoreError(f"Ya existe una clave '{key_id}' en {path}.")
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)
        os.mkdir(path, 0o700)
        return path

    def _save_info(self, path: str, info: Dict[str, Any]) -> None:
        with open(os.path.join(path, KEY_FILE), "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
            f.write("\n")

    # ------------------------------------------------------------------ alta

    def _store_root(self, key_id: str, key: Ed25519PrivateKey, name: Optional[str]) -> StoredKey:
        path = self._new_key_dir(key_id)
        _write_secret(os.path.join(path, ROOT_PEM), private_pem(key))
        info = {
            "format": 1,
            "key_id": key_id,
            "kind": "root",
            "created_at_utc": _now_utc(),
            "ed25519_public_key": raw_public_hex(key),
        }
        if name:
            info["name"] = name
        self._save_info(path, info)
        return StoredKey(key_id, "root", path, info)

    def _store_teacher(self, key_id: str, sign_key: Ed25519PrivateKey, enc_key: x25519.X25519PrivateKey,
                       name: Optional[str]) -> StoredKey:
        path = self._new_key_dir(key_id)
        _write_secret(os.path.join(path, SIGNING_PEM), private_pem(sign_key))
        _write_secret(os.path.join(path, DECRYPTION_PEM), private_pem(enc_key))
        info = {
            "format": 1,
            "key_id": key_id,
            "kind": "teacher",
            "created_at_utc": _now_utc(),
            "ed25519_verify_key": raw_public_hex(sign_key),
            "x25519_encryption_key": raw_public_hex(enc_key),
        }
        if name:
            info["name"] = name
        self._save_info(path, info)
        return StoredKey(key_id, "teacher", path, info)

    def create_root(self, key_id: str, name: Optional[str] = None) -> StoredKey:
        return self._store_root(key_id, Ed25519PrivateKey.generate(), name)

    def create_teacher(self, key_id: str, name: Optional[str] = None) -> StoredKey:
        return self._store_teacher(key_id, Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate(), name)

    def import_root(self, key_id: str, pem_path: str, name: Optional[str] = None) -> StoredKey:
        key = load_private(pem_path)
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyStoreError(f"{pem_path} no contiene una clave privada Ed25519.")
        return self._store_root(key_id, key, name)

    def import_teacher(self, key_id: str, signing_pem: str, decryption_pem: str,
                       name: Optional[str] = None) -> StoredKey:
        sign_key = load_private(signing_pem)
        enc_key = load_private(decryption_pem)
        if not isinstance(sign_key, Ed25519PrivateKey):
            raise KeyStoreError(f"{signing_pem} no contiene una clave privada Ed25519.")
        if not isinstance(enc_key, x25519.X25519PrivateKey):
            raise KeyStoreError(f"{decryption_pem} no contiene una clave privada X25519.")
        return self._store_teacher(key_id, sign_key, enc_key, name)

    # ------------------------------------------------------------------ consulta

    def get(self, key_id: str) -> StoredKey:
        path = self._key_dir(key_id)
        info_path = os.path.join(path, KEY_FILE)
        if not os.path.exists(info_path):
            raise KeyStoreError(f"No existe la clave '{key_id}' en {self.directory} (vea 'uatu-admin keys list').")
        with open(info_path, encoding="utf-8") as f:
            info = json.load(f)
        return StoredKey(key_id, str(info.get("kind")), path, info)

    def list(self) -> List[StoredKey]:
        if not os.path.isdir(self.directory):
            return []
        keys = []
        for name in sorted(os.listdir(self.directory)):
            if os.path.exists(os.path.join(self.directory, name, KEY_FILE)):
                try:
                    keys.append(self.get(name))
                except (KeyStoreError, ValueError):
                    continue
        return keys

    def find_by_verify_key(self, verify_hex: str) -> Optional[StoredKey]:
        for key in self.list():
            if key.kind == "teacher" and key.info.get("ed25519_verify_key") == verify_hex:
                return key
        return None
