#!/usr/bin/env python3
"""
Herramientas de cátedra para Uatu v2.1.

Gestiona el material criptográfico del lado docente (sección 3.3) y la
configuración de los repositorios de examen en GitHub.

Uso: uatu-admin [--keys-dir DIR] <comando> [opciones]

  root-keygen       Genera la clave raíz institucional (ancla embebida en la extensión).
  keygen            Genera el par docente: Ed25519 (firma de .uatu.conf) y X25519 (descifrado).
  keys              Lista, muestra, importa y exporta claves del almacén local, y las
                    carga donde se usan (secretos y variables de GitHub, trust-anchors.json).
  registry-add      Agrega o reemplaza un docente en el registro público de claves.
  registry-sign     Firma el registro con la clave raíz institucional.
  verify-registry   Verifica la firma raíz del registro.
  sign-config       Firma .uatu.conf con la clave Ed25519 docente.
  verify-config     Verifica la firma docente de .uatu.conf.
  protect-branches  Protege las ramas de telemetría contra borrado y force-push.

Las claves se guardan por omisión en ~/.config/uatu/keys/<id>/ (ver
uatu_tools.keystore). Todas las firmas se calculan sobre la serialización
canónica compartida con la extensión y con el validador (uatu-audit).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from uatu_tools.audit import canonical, verify_ed25519, without
from uatu_tools.github import (
    RULESET_NAME,
    GitHubClient,
    GitHubError,
    apply_ruleset,
    build_ruleset,
    resolve_token,
    set_actions_value,
)
from uatu_tools.keystore import KeyStore, KeyStoreError, StoredKey, load_private

AUDIT_PUBLIC_SECRET = "UATU_TEACHER_PUBLIC_KEY"
AUDIT_PRIVATE_SECRET = "UATU_TEACHER_PRIVATE_KEY"
ANCHORS_VARIABLE = "UATU_TRUST_ANCHORS"

SECRET_FORMATS = {"root-key", "signing-key", "decryption-key"}
ROOT_FORMATS = ["anchor", "trust-anchors", "root-key", "root-key-path"]
TEACHER_FORMATS = [
    "verify-key",
    "encrypt-key",
    "registry-entry",
    "signing-key",
    "signing-key-path",
    "decryption-key",
    "decryption-key-path",
]
ALL_FORMATS = ["public"] + ROOT_FORMATS + TEACHER_FORMATS


class AdminError(Exception):
    pass


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _store(args: argparse.Namespace) -> KeyStore:
    return KeyStore(getattr(args, "keys_dir", None))


def _is_hex32(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


# --------------------------------------------------------------------------- generación


def cmd_root_keygen(args: argparse.Namespace) -> int:
    key = _store(args).create_root(args.key_id, args.name)
    print(json.dumps({"key_id": key.key_id, "kind": "root", "directory": key.directory, "anchor": key.anchor}, indent=2))
    print(
        f"\nClave raíz guardada en {key.directory}. Para embeberla en la extensión:\n"
        f"  uatu-admin keys setup-anchors {key.key_id} --repo OWNER/uatu          (variable {ANCHORS_VARIABLE})\n"
        f"  uatu-admin keys setup-anchors {key.key_id} --file extension/resources/trust-anchors.json",
        file=sys.stderr,
    )
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    key = _store(args).create_teacher(args.key_id, args.name)
    print(json.dumps({"key_id": key.key_id, "kind": "teacher", "directory": key.directory,
                      "ed25519_verify_key": key.verify_key, "x25519_encryption_key": key.encrypt_key}, indent=2))
    print(
        f"\nClave docente guardada en {key.directory}. Próximos pasos:\n"
        f"  uatu-admin registry-add --registry keys.json --key-id {key.key_id}\n"
        f"  uatu-admin sign-config --config .uatu.conf --key-id {key.key_id}\n"
        f"  uatu-admin keys setup-audit {key.key_id} --repo OWNER/REPO-DEL-EXAMEN",
        file=sys.stderr,
    )
    return 0


# --------------------------------------------------------------------------- almacén


def cmd_keys_list(args: argparse.Namespace) -> int:
    store = _store(args)
    keys = store.list()
    if args.json:
        print(json.dumps([k.info for k in keys], ensure_ascii=False, indent=2))
        return 0
    if not keys:
        print(f"No hay claves en {store.directory}.")
        return 0
    print(f"Claves en {store.directory}:")
    for k in keys:
        public = k.info.get("ed25519_public_key") if k.kind == "root" else k.info.get("ed25519_verify_key")
        kind = "raíz   " if k.kind == "root" else "docente"
        name = f"  {k.info['name']}" if k.info.get("name") else ""
        print(f"  {k.key_id:<24} {kind}  {public[:16]}…  {k.info.get('created_at_utc', '')}{name}")
    return 0


def cmd_keys_show(args: argparse.Namespace) -> int:
    key = _store(args).get(args.key_id)
    info = dict(key.info, directory=key.directory)
    if key.kind == "root":
        info["files"] = {"root_key": key.root_key_path}
    else:
        info["files"] = {"signing_key": key.signing_key_path, "decryption_key": key.decryption_key_path}
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def cmd_keys_import(args: argparse.Namespace) -> int:
    store = _store(args)
    if args.root:
        if args.signing or args.decryption:
            raise AdminError("Use --root para una clave raíz, o --signing y --decryption para una clave docente.")
        key = store.import_root(args.key_id, args.root, args.name)
    elif args.signing and args.decryption:
        key = store.import_teacher(args.key_id, args.signing, args.decryption, args.name)
    else:
        raise AdminError("Indique --root PEM, o bien --signing PEM y --decryption PEM.")
    print(f"Clave '{key.key_id}' ({key.kind}) importada en {key.directory}.")
    return 0


def export_value(keys: List[StoredKey], fmt: str) -> str:
    """Valor textual de una clave (o de varias raíces para trust-anchors) en el formato pedido."""
    if fmt == "trust-anchors":
        return json.dumps({"anchors": [k.anchor for k in keys]}, ensure_ascii=False)
    if len(keys) != 1:
        raise AdminError(f"El formato '{fmt}' admite una sola clave.")
    key = keys[0]
    if fmt == "public":
        return json.dumps(key.info, ensure_ascii=False, indent=2)
    if fmt == "anchor":
        return json.dumps(key.anchor, ensure_ascii=False)
    if fmt == "root-key-path":
        return key.root_key_path
    if fmt == "root-key":
        return open(key.root_key_path, encoding="utf-8").read()
    if fmt == "verify-key":
        return key.verify_key
    if fmt == "encrypt-key":
        return key.encrypt_key
    if fmt == "registry-entry":
        return json.dumps({key.key_id: key.registry_entry()}, ensure_ascii=False, indent=2)
    if fmt == "signing-key-path":
        return key.signing_key_path
    if fmt == "signing-key":
        return open(key.signing_key_path, encoding="utf-8").read()
    if fmt == "decryption-key-path":
        return key.decryption_key_path
    if fmt == "decryption-key":
        return open(key.decryption_key_path, encoding="utf-8").read()
    raise AdminError(f"Formato desconocido: {fmt}")


def cmd_keys_export(args: argparse.Namespace) -> int:
    store = _store(args)
    keys = [store.get(k) for k in args.key_ids]
    value = export_value(keys, args.format)
    secret = args.format in SECRET_FORMATS
    destinations = [d for d in (args.out, args.gh_secret, args.gh_variable) if d]
    if len(destinations) > 1:
        raise AdminError("Use un solo destino: --out, --gh-secret o --gh-variable.")

    if args.gh_secret or args.gh_variable:
        kind = "secret" if args.gh_secret else "variable"
        if kind == "variable" and secret:
            raise AdminError("Una clave privada no puede cargarse como variable (son visibles): use --gh-secret.")
        name = args.gh_secret or args.gh_variable
        set_actions_value(kind, name, value.strip() if not secret else value,
                          repo=args.repo, org=args.org, visibility=args.visibility)
        target = args.repo or f"org {args.org}"
        print(f"{'Secreto' if kind == 'secret' else 'Variable'} {name} cargado en {target}.", file=sys.stderr)
        return 0

    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if secret else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value if value.endswith("\n") else value + "\n")
        print(f"Exportado '{args.format}' en {args.out}.", file=sys.stderr)
        return 0

    if secret and sys.stdout.isatty() and not args.show_secret:
        raise AdminError(
            f"'{args.format}' es una clave privada: redirija la salida, use --out, --gh-secret, "
            "o confirme con --show-secret para mostrarla en la terminal."
        )
    sys.stdout.write(value if value.endswith("\n") else value + "\n")
    return 0


def cmd_keys_setup_audit(args: argparse.Namespace) -> int:
    """Carga los dos secretos que usa el workflow de evaluación forense."""
    key = _store(args).get(args.key_id)
    set_actions_value("secret", AUDIT_PUBLIC_SECRET, key.verify_key, repo=args.repo, org=args.org, visibility=args.visibility)
    with open(key.decryption_key_path, encoding="utf-8") as f:
        set_actions_value("secret", AUDIT_PRIVATE_SECRET, f.read(), repo=args.repo, org=args.org, visibility=args.visibility)
    target = args.repo or f"la organización {args.org}"
    print(f"Secretos {AUDIT_PUBLIC_SECRET} y {AUDIT_PRIVATE_SECRET} de '{key.key_id}' cargados en {target}.")
    return 0


def cmd_keys_setup_anchors(args: argparse.Namespace) -> int:
    """Publica las anclas raíz donde las consume la extensión."""
    store = _store(args)
    value = export_value([store.get(k) for k in args.key_ids], "trust-anchors")
    if bool(args.file) == bool(args.repo):
        raise AdminError("Indique --repo OWNER/REPO (variable de Actions) o --file PATH (trust-anchors.json).")
    if args.file:
        with open(args.file, "w", encoding="utf-8") as f:
            json.dump(json.loads(value), f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"Anclas escritas en {args.file}.")
    else:
        set_actions_value("variable", args.variable, value, repo=args.repo)
        print(f"Variable {args.variable} cargada en {args.repo}.")
    return 0


# --------------------------------------------------------------------------- registro


def cmd_registry_add(args: argparse.Namespace) -> int:
    registry: Dict[str, Any]
    if os.path.exists(args.registry):
        registry = _load_json(args.registry)
    else:
        registry = {"version": "1", "teachers": {}}
    verify_key, encrypt_key, name = args.verify_key, args.encrypt_key, args.name
    if not (verify_key and encrypt_key):
        if verify_key or encrypt_key:
            raise AdminError("Indique ambas claves públicas o ninguna (se toman del almacén).")
        stored = _store(args).get(args.key_id)
        verify_key, encrypt_key = stored.verify_key, stored.encrypt_key
        name = name or stored.info.get("name")
    for flag, value in (("--verify-key", verify_key), ("--encrypt-key", encrypt_key)):
        if not _is_hex32(value):
            raise AdminError(f"{flag} debe ser una clave cruda de 32 bytes en hex (minúsculas).")
    entry: Dict[str, Any] = {"ed25519_verify_key": verify_key, "x25519_encryption_key": encrypt_key}
    if name:
        entry["name"] = name
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
    root_path = args.root_key or _store(args).get(args.root_key_id).root_key_path
    signed = sign_registry(registry, load_private(root_path), args.root_key_id)
    _save_json(args.registry, signed)
    print(f"Registro firmado por '{args.root_key_id}'.")
    return 0


def cmd_verify_registry(args: argparse.Namespace) -> int:
    registry = _load_json(args.registry)
    anchor = args.anchor_key
    if not anchor:
        root_id = str(registry.get("root_key_id", ""))
        anchor = _store(args).get(root_id).anchor["ed25519_public_key"]
    ok = verify_ed25519(anchor, str(registry.get("signature", "")), canonical(without(registry, "signature")))
    print("Firma raíz VÁLIDA." if ok else "Firma raíz INVÁLIDA.")
    return 0 if ok else 1


# --------------------------------------------------------------------------- manifiesto


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
    key_id = args.key_id or (config.get("crypto") or {}).get("teacher_key_id")
    if not args.key and not key_id:
        raise AdminError("Indique --key-id (clave del almacén) o --key PEM.")
    key_path = args.key or _store(args).get(key_id).signing_key_path
    try:
        signed = sign_config(config, load_private(key_path), key_id)
    except ValueError as e:
        raise AdminError(str(e)) from e
    _save_json(args.config, signed)
    print(f"{args.config} firmado con la clave '{signed['crypto']['teacher_key_id']}'.")
    return 0


def cmd_verify_config(args: argparse.Namespace) -> int:
    config = _load_json(args.config)
    verify_key = args.verify_key
    if not verify_key:
        key_id = args.key_id or (config.get("crypto") or {}).get("teacher_key_id")
        if not key_id:
            raise AdminError("Indique --verify-key HEX o --key-id.")
        verify_key = _store(args).get(key_id).verify_key
    sig = str(config.get("crypto", {}).get("signature", ""))
    ok = verify_ed25519(verify_key, sig, canonical(without(config, "crypto")))
    print("Firma docente VÁLIDA." if ok else "Firma docente INVÁLIDA.")
    return 0 if ok else 1


# --------------------------------------------------------------------------- GitHub


def cmd_protect_branches(args: argparse.Namespace) -> int:
    prefix = args.prefix
    if not prefix and args.config and os.path.exists(args.config):
        prefix = (_load_json(args.config).get("git") or {}).get("telemetry_branch_prefix")
    prefix = prefix or "uatu-audit"
    if bool(args.repo) == bool(args.org):
        raise AdminError("Indique --repo OWNER/REPO o --org ORG.")
    if args.org and not args.repo_pattern:
        raise AdminError("Con --org indique al menos un --repo-pattern (p. ej. 'examen-*' o '~ALL').")
    ruleset = build_ruleset(prefix, args.name, args.repo_pattern if args.org else None)
    scope = f"repos/{args.repo}" if args.repo else f"orgs/{args.org}"
    if args.dry_run:
        print(json.dumps({"endpoint": f"/{scope}/rulesets", "ruleset": ruleset}, ensure_ascii=False, indent=2))
        return 0
    client = GitHubClient(resolve_token())
    action, result = apply_ruleset(client, scope, ruleset)
    target = args.repo or f"la organización {args.org}"
    print(f"Ruleset '{args.name}' {action} en {target} (id {result.get('id') if isinstance(result, dict) else '?'}): "
          f"refs/heads/{prefix}/** no puede borrarse ni reescribirse con force-push.")
    return 0


# --------------------------------------------------------------------------- CLI


def _add_gh_target(p: argparse.ArgumentParser) -> None:
    target = p.add_mutually_exclusive_group()
    target.add_argument("--repo", help="Repositorio destino OWNER/REPO")
    target.add_argument("--org", help="Organización destino (secretos/variables de organización)")
    p.add_argument("--visibility", choices=["all", "private", "selected"],
                   help="Visibilidad de un secreto de organización (por omisión la de gh)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uatu-admin", description="Herramientas de cátedra para Uatu v2.1")
    parser.add_argument("--keys-dir", default=None,
                        help="Almacén de claves (por omisión $UATU_KEYS_DIR o ~/.config/uatu/keys)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("root-keygen", help="Genera la clave raíz institucional en el almacén")
    p.add_argument("--key-id", required=True)
    p.add_argument("--name", help="Descripción legible (p. ej. la institución)")
    p.add_argument("--out", dest="keys_dir", default=argparse.SUPPRESS, help=argparse.SUPPRESS)  # alias de --keys-dir
    p.set_defaults(func=cmd_root_keygen)

    p = sub.add_parser("keygen", help="Genera las claves Ed25519/X25519 de un docente en el almacén")
    p.add_argument("--key-id", required=True)
    p.add_argument("--name", help="Descripción legible (p. ej. el docente o la materia)")
    p.add_argument("--out", dest="keys_dir", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_keygen)

    keys = sub.add_parser("keys", help="Gestiona el almacén de claves y las exporta donde se usan")
    ksub = keys.add_subparsers(dest="keys_command", required=True)

    p = ksub.add_parser("list", help="Lista las claves del almacén")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_keys_list)

    p = ksub.add_parser("show", help="Muestra los metadatos y archivos de una clave")
    p.add_argument("key_id")
    p.set_defaults(func=cmd_keys_show)

    p = ksub.add_parser("import", help="Importa claves PEM existentes al almacén")
    p.add_argument("key_id")
    p.add_argument("--root", help="Clave privada raíz Ed25519 (PEM)")
    p.add_argument("--signing", help="Clave privada docente Ed25519 (PEM)")
    p.add_argument("--decryption", help="Clave privada docente X25519 (PEM)")
    p.add_argument("--name")
    p.set_defaults(func=cmd_keys_import)

    p = ksub.add_parser("export", help="Extrae una clave en el formato que necesita cada destino")
    p.add_argument("key_ids", nargs="+", metavar="key_id")
    p.add_argument("--format", "-f", required=True, choices=ALL_FORMATS,
                   help="raíz: anchor, trust-anchors, root-key, root-key-path | docente: verify-key, "
                        "encrypt-key, registry-entry, signing-key, signing-key-path, decryption-key, "
                        "decryption-key-path | ambas: public")
    p.add_argument("--out", help="Escribir en un archivo (0600 si es una clave privada)")
    p.add_argument("--gh-secret", metavar="NAME", help="Cargar como secreto de Actions (requiere gh)")
    p.add_argument("--gh-variable", metavar="NAME", help="Cargar como variable de Actions (requiere gh)")
    p.add_argument("--show-secret", action="store_true", help="Permitir mostrar una clave privada en la terminal")
    _add_gh_target(p)
    p.set_defaults(func=cmd_keys_export)

    p = ksub.add_parser("setup-audit", help=f"Carga {AUDIT_PUBLIC_SECRET} y {AUDIT_PRIVATE_SECRET} para el workflow forense")
    p.add_argument("key_id")
    _add_gh_target(p)
    p.set_defaults(func=cmd_keys_setup_audit)

    p = ksub.add_parser("setup-anchors", help="Publica las anclas raíz para empaquetar la extensión")
    p.add_argument("key_ids", nargs="+", metavar="key_id")
    p.add_argument("--repo", help=f"Repositorio de la extensión: carga la variable {ANCHORS_VARIABLE}")
    p.add_argument("--variable", default=ANCHORS_VARIABLE, help=f"Nombre de la variable (por omisión {ANCHORS_VARIABLE})")
    p.add_argument("--file", help="Escribir trust-anchors.json en esta ruta")
    p.set_defaults(func=cmd_keys_setup_anchors)

    p = sub.add_parser("registry-add", help="Agrega un docente al registro de claves")
    p.add_argument("--registry", required=True)
    p.add_argument("--key-id", required=True, help="Identificador del docente (y clave del almacén si no se dan las públicas)")
    p.add_argument("--verify-key", help="Ed25519 pública (hex); por omisión la del almacén")
    p.add_argument("--encrypt-key", help="X25519 pública (hex); por omisión la del almacén")
    p.add_argument("--name")
    p.add_argument("--not-before")
    p.add_argument("--not-after")
    p.set_defaults(func=cmd_registry_add)

    p = sub.add_parser("registry-sign", help="Firma el registro con la clave raíz")
    p.add_argument("--registry", required=True)
    p.add_argument("--root-key-id", required=True)
    p.add_argument("--root-key", help="Clave privada raíz (PEM); por omisión la del almacén")
    p.set_defaults(func=cmd_registry_sign)

    p = sub.add_parser("verify-registry", help="Verifica la firma raíz del registro")
    p.add_argument("--registry", required=True)
    p.add_argument("--anchor-key", help="Ed25519 pública raíz (hex); por omisión la del almacén según root_key_id")
    p.set_defaults(func=cmd_verify_registry)

    p = sub.add_parser("sign-config", help="Firma .uatu.conf")
    p.add_argument("--config", default=".uatu.conf")
    p.add_argument("--key-id", help="Clave docente del almacén y valor de crypto.teacher_key_id "
                                    "(por omisión el teacher_key_id del manifiesto)")
    p.add_argument("--key", help="Clave privada Ed25519 docente (PEM), en lugar del almacén")
    p.set_defaults(func=cmd_sign_config)

    p = sub.add_parser("verify-config", help="Verifica la firma de .uatu.conf")
    p.add_argument("--config", default=".uatu.conf")
    p.add_argument("--verify-key", help="Ed25519 pública docente (hex); por omisión la del almacén")
    p.add_argument("--key-id", help="Clave docente del almacén (por omisión el teacher_key_id del manifiesto)")
    p.set_defaults(func=cmd_verify_config)

    p = sub.add_parser("protect-branches", help="Impide borrar o reescribir las ramas de telemetría (ruleset de GitHub)")
    scope = p.add_mutually_exclusive_group()
    scope.add_argument("--repo", help="Repositorio del examen OWNER/REPO")
    scope.add_argument("--org", help="Organización (ruleset para todos los repositorios que coincidan)")
    p.add_argument("--repo-pattern", action="append", metavar="PATRÓN",
                   help="Con --org: patrón de nombres de repositorio (repetible; '~ALL' para todos)")
    p.add_argument("--prefix", help="Prefijo de las ramas (por omisión el de --config o 'uatu-audit')")
    p.add_argument("--config", default=".uatu.conf", help="Manifiesto del que leer git.telemetry_branch_prefix")
    p.add_argument("--name", default=RULESET_NAME, help="Nombre del ruleset (se actualiza si ya existe)")
    p.add_argument("--dry-run", action="store_true", help="Mostrar el ruleset sin aplicarlo")
    p.set_defaults(func=cmd_protect_branches)
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        return args.func(args)
    except (AdminError, KeyStoreError, GitHubError, FileNotFoundError) as e:
        print(f"uatu-admin: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
