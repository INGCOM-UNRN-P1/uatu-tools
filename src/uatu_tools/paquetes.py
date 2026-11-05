"""
Paquetes de examen por estudiante, con descifrado condicional en su equipo (Ola 47).

La consigna sellada (`uatu_tools.consigna`) es la misma para todos. Acá cada estudiante tiene la
suya: el tema que le tocó (`alucard repartir` arma una carpeta por usuario de GitHub).

1. `uatu-admin paquetes sellar <carpeta>` cifra cada `<carpeta>/<usuario>/` con una clave propia y
   agrega al `.uatu.conf` el bloque `paquetes` con un hash por usuario, bajo la firma docente.
2. `uatu-admin paquetes distribuir` publica cada paquete cifrado en el repositorio de su dueño, en
   cualquier momento antes del examen. Sin la clave no sirve.
3. `uatu-admin paquetes liberar`, cuando la hora de GitHub pasó `start_utc`, publica la clave.
4. La extensión, en sesión, descifra si la clave llegó, el usuario de GitHub es el del paquete y la
   hora calibrada está dentro de la ventana; registra `paquete_abierto` o `paquete_rechazado`.

Lo que impide abrir antes de hora o abrir el paquete de otro es del lado del servidor: la clave no
existe en el equipo del estudiante hasta `start_utc`, y sólo llega a su repositorio privado. Los
controles de la extensión dan evidencia, no seguridad: quien controla su equipo puede saltearlos,
pero sin la clave no tiene nada que descifrar (es la falla por la que se retiró keymaker, que
comparaba con el reloj local).

El hash incluye al usuario (`hash_paquete`): el `.uatu.conf` está en todos los repositorios, y con
el hash del contenido se vería quiénes comparten tema.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from uatu_tools.consigna import CARPETA_POR_OMISION, ConsignaError, hash_archivos, leer_carpeta

FORMATO = "uatu-paquete-v1"
ARCHIVO_PAQUETE = ".uatu-paquete.enc"
ARCHIVO_CLAVE = ".uatu-paquete.clave"
MENSAJE_DISTRIBUCION = "uatu: distribuir paquete"
MENSAJE_LIBERACION = "uatu: liberar clave del paquete"
_USUARIO = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?")


def normalizar_usuario(usuario: str) -> str:
    """El login de GitHub en minúsculas: GitHub no distingue mayúsculas en los nombres de usuario."""
    normalizado = usuario.strip().lower()
    if not _USUARIO.fullmatch(normalizado):
        raise ConsignaError(f"'{usuario}' no es un usuario de GitHub válido.")
    return normalizado


def hash_paquete(usuario: str, archivos: Dict[str, bytes]) -> str:
    return hashlib.sha256(f"{usuario}\n{hash_archivos(archivos)}\n".encode("utf-8")).hexdigest()


def _dato_asociado(usuario: str, digest: str) -> bytes:
    return f"{FORMATO}:{usuario}:{digest}".encode("utf-8")


def sellar(usuario: str, archivos: Dict[str, bytes], clave: Optional[bytes] = None,
           nonce: Optional[bytes] = None) -> Tuple[Dict[str, Any], bytes]:
    """(paquete cifrado, clave). Usuario y hash van como dato asociado: no se cambian sin la clave."""
    clave = clave or AESGCM.generate_key(bit_length=256)
    nonce = nonce or os.urandom(12)
    digest = hash_paquete(usuario, archivos)
    plano = json.dumps({r: base64.b64encode(c).decode() for r, c in sorted(archivos.items())},
                       sort_keys=True).encode("utf-8")
    cifrado = AESGCM(clave).encrypt(nonce, plano, _dato_asociado(usuario, digest))
    paquete = {"formato": FORMATO, "algoritmo": "AES-256-GCM", "usuario": usuario, "sha256": digest,
               "nonce": base64.b64encode(nonce).decode(), "datos": base64.b64encode(cifrado).decode()}
    return paquete, clave


def abrir(paquete: Dict[str, Any], clave: bytes, sha256_esperado: Optional[str] = None) -> Dict[str, bytes]:
    """Descifra en memoria y verifica el hash (el del `.uatu.conf` firmado, si se da)."""
    if paquete.get("formato") != FORMATO:
        raise ConsignaError(f"Formato de paquete desconocido: {paquete.get('formato')}")
    usuario, digest = str(paquete.get("usuario", "")), str(paquete.get("sha256", ""))
    if sha256_esperado and digest != sha256_esperado:
        raise ConsignaError(f"El paquete de {usuario} no es el declarado en .uatu.conf (sha256 distinto).")
    try:
        plano = AESGCM(clave).decrypt(base64.b64decode(paquete["nonce"]), base64.b64decode(paquete["datos"]),
                                      _dato_asociado(usuario, digest))
    except Exception as e:  # noqa: BLE001 - InvalidTag u otro error de formato
        raise ConsignaError(f"No se pudo descifrar el paquete de {usuario}: clave incorrecta o paquete alterado.") from e
    archivos = {r: base64.b64decode(c) for r, c in json.loads(plano).items()}
    if hash_paquete(usuario, archivos) != digest:
        raise ConsignaError(f"El contenido del paquete de {usuario} no coincide con su hash.")
    return archivos


def leer_paquetes(carpeta: str) -> Dict[str, Dict[str, bytes]]:
    """{usuario: archivos} de una carpeta con una subcarpeta por usuario de GitHub."""
    paquetes: Dict[str, Dict[str, bytes]] = {}
    for nombre in sorted(os.listdir(carpeta)):
        ruta = os.path.join(carpeta, nombre)
        if not os.path.isdir(ruta):
            continue
        usuario = normalizar_usuario(nombre)
        if usuario in paquetes:
            raise ConsignaError(f"Hay dos carpetas para el usuario {usuario}.")
        paquetes[usuario] = leer_carpeta(ruta)
    if not paquetes:
        raise ConsignaError(f"{carpeta} no tiene una carpeta por usuario (la arma `alucard repartir`).")
    return paquetes


def bloque_paquetes(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    bloque = config.get("paquetes")
    if not isinstance(bloque, dict) or not isinstance(bloque.get("hashes"), dict) or not bloque["hashes"]:
        return None
    return {"carpeta": str(bloque.get("carpeta") or CARPETA_POR_OMISION), "hashes": dict(bloque["hashes"])}


def asignar_repos(repos: Iterable[str], prefijo: str, usuarios: Iterable[str]) -> Tuple[Dict[str, str], List[str]]:
    """({usuario: repositorio}, repositorios sin usuario) con los nombres `<prefijo>[-_]<usuario>` de Classroom."""
    buscados = set(usuarios)
    asignados: Dict[str, str] = {}
    sobrantes: List[str] = []
    for repo in repos:
        resto = repo.rsplit("/", 1)[-1][len(prefijo):].lstrip("-_").lower()
        if resto in buscados:
            asignados[resto] = repo
        else:
            sobrantes.append(repo)
    return asignados, sobrantes
