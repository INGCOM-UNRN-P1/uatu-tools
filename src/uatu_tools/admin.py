#!/usr/bin/env python3
"""
Herramientas de cátedra para Uatu v2.1.

Gestiona el material criptográfico del lado docente (sección 3.3):

Uso: uatu-admin <comando> [opciones]

  root-keygen      Genera la clave raíz institucional (ancla embebida en la extensión).
  keygen           Genera el par docente: Ed25519 (firma de .uatu.conf) y X25519 (descifrado).
  registry-add     Agrega o reemplaza un docente en el registro público de claves.
  registry-sign    Firma el registro con la clave raíz institucional.
  verify-registry  Verifica la firma raíz del registro.
  sign-config      Firma .uatu.conf con la clave Ed25519 docente.
  verify-config    Verifica la firma docente de .uatu.conf.

Todas las firmas se calculan sobre la serialización canónica compartida con la
extensión y con el validador (uatu-audit).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from uatu_tools.audit import canonical, verify_ed25519, without


def _raw_public_hex(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def _write_private_pem(path: str, private_key) -> None:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _load_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- comandos


def cmd_root_keygen(args: argparse.Namespace) -> int:
    os.makedirs(args.out, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path = os.path.join(args.out, f"{args.key_id}.root.pem")
    _write_private_pem(path, key)
    anchor = {"key_id": args.key_id, "ed25519_public_key": _raw_public_hex(key)}
    print(json.dumps({"private_key": path, "anchor": anchor}, indent=2))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    os.makedirs(args.out, exist_ok=True)
    sign_key = Ed25519PrivateKey.generate()
    enc_key = x25519.X25519PrivateKey.generate()
    sign_path = os.path.join(args.out, f"{args.key_id}.ed25519.pem")
    enc_path = os.path.join(args.out, f"{args.key_id}.x25519.pem")
    _write_private_pem(sign_path, sign_key)
    _write_private_pem(enc_path, enc_key)
    print(
        json.dumps(
            {
                "key_id": args.key_id,
                "signing_private_key": sign_path,
                "decryption_private_key": enc_path,
                "ed25519_verify_key": _raw_public_hex(sign_key),
                "x25519_encryption_key": _raw_public_hex(enc_key),
            },
            indent=2,
        )
    )
    return 0


def cmd_registry_add(args: argparse.Namespace) -> int:
    registry: Dict[str, Any]
    if os.path.exists(args.registry):
        registry = _load_json(args.registry)
    else:
        registry = {"version": "1", "teachers": {}}
    for name, value in (("--verify-key", args.verify_key), ("--encrypt-key", args.encrypt_key)):
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            print(f"{name} debe ser una clave cruda de 32 bytes en hex (minúsculas).", file=sys.stderr)
            return 1
    entry: Dict[str, Any] = {"ed25519_verify_key": args.verify_key, "x25519_encryption_key": args.encrypt_key}
    if args.name:
        entry["name"] = args.name
    if args.not_before:
        entry["not_before_utc"] = args.not_before
    if args.not_after:
        entry["not_after_utc"] = args.not_after
    registry.setdefault("teachers", {})[args.key_id] = entry
    registry.pop("signature", None)  # cualquier cambio invalida la firma previa
    _save_json(args.registry, registry)
    print(f"Docente '{args.key_id}' agregado a {args.registry}. Recuerde volver a firmar el registro.")
    return 0


def sign_registry(registry: Dict[str, Any], root_key, root_key_id: str) -> Dict[str, Any]:
    unsigned = without(registry, "signature")
    unsigned["root_key_id"] = root_key_id
    unsigned["issued_at_utc"] = unsigned.get("issued_at_utc") or _now_utc()
    signature = root_key.sign(canonical(unsigned)).hex()
    return {**unsigned, "signature": signature}


def cmd_registry_sign(args: argparse.Namespace) -> int:
    registry = _load_json(args.registry)
    registry.pop("issued_at_utc", None)
    signed = sign_registry(registry, _load_private(args.root_key), args.root_key_id)
    _save_json(args.registry, signed)
    print(f"Registro firmado por '{args.root_key_id}'.")
    return 0


def cmd_verify_registry(args: argparse.Namespace) -> int:
    registry = _load_json(args.registry)
    ok = verify_ed25519(args.anchor_key, str(registry.get("signature", "")), canonical(without(registry, "signature")))
    print("Firma raíz VÁLIDA." if ok else "Firma raíz INVÁLIDA.")
    return 0 if ok else 1


def sign_config(config: Dict[str, Any], signing_key, key_id: Optional[str] = None) -> Dict[str, Any]:
    crypto_block = dict(config.get("crypto") or {})
    if key_id:
        crypto_block["teacher_key_id"] = key_id
    if not crypto_block.get("teacher_key_id"):
        raise ValueError("crypto.teacher_key_id es obligatorio (use --key-id).")
    crypto_block["signature"] = signing_key.sign(canonical(without(config, "crypto"))).hex()
    return {**config, "crypto": crypto_block}


def cmd_sign_config(args: argparse.Namespace) -> int:
    config = _load_json(args.config)
    try:
        signed = sign_config(config, _load_private(args.key), args.key_id)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    _save_json(args.config, signed)
    print(f"{args.config} firmado con la clave '{signed['crypto']['teacher_key_id']}'.")
    return 0


def cmd_verify_config(args: argparse.Namespace) -> int:
    config = _load_json(args.config)
    sig = str(config.get("crypto", {}).get("signature", ""))
    ok = verify_ed25519(args.verify_key, sig, canonical(without(config, "crypto")))
    print("Firma docente VÁLIDA." if ok else "Firma docente INVÁLIDA.")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Herramientas de cátedra para Uatu v2.1")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("root-keygen", help="Genera la clave raíz institucional")
    p.add_argument("--out", required=True)
    p.add_argument("--key-id", required=True)
    p.set_defaults(func=cmd_root_keygen)

    p = sub.add_parser("keygen", help="Genera las claves Ed25519/X25519 de un docente")
    p.add_argument("--out", required=True)
    p.add_argument("--key-id", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("registry-add", help="Agrega un docente al registro de claves")
    p.add_argument("--registry", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--verify-key", required=True, help="Ed25519 pública (hex)")
    p.add_argument("--encrypt-key", required=True, help="X25519 pública (hex)")
    p.add_argument("--name")
    p.add_argument("--not-before")
    p.add_argument("--not-after")
    p.set_defaults(func=cmd_registry_add)

    p = sub.add_parser("registry-sign", help="Firma el registro con la clave raíz")
    p.add_argument("--registry", required=True)
    p.add_argument("--root-key", required=True)
    p.add_argument("--root-key-id", required=True)
    p.set_defaults(func=cmd_registry_sign)

    p = sub.add_parser("verify-registry", help="Verifica la firma raíz del registro")
    p.add_argument("--registry", required=True)
    p.add_argument("--anchor-key", required=True, help="Ed25519 pública raíz (hex)")
    p.set_defaults(func=cmd_verify_registry)

    p = sub.add_parser("sign-config", help="Firma .uatu.conf")
    p.add_argument("--config", default=".uatu.conf")
    p.add_argument("--key", required=True, help="Clave privada Ed25519 docente (PEM)")
    p.add_argument("--key-id", help="Valor para crypto.teacher_key_id")
    p.set_defaults(func=cmd_sign_config)

    p = sub.add_parser("verify-config", help="Verifica la firma de .uatu.conf")
    p.add_argument("--config", default=".uatu.conf")
    p.add_argument("--verify-key", required=True, help="Ed25519 pública docente (hex)")
    p.set_defaults(func=cmd_verify_config)
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
