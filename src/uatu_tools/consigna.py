"""
Liberación de la consigna de un examen con bloqueo de tiempo (Decisión 1, ex keymaker).

La consigna (enunciado y pruebas base) no puede estar en la máquina del estudiante antes de
`session.start_utc`, ni siquiera cifrada junto a una clave que el estudiante pueda alcanzar:

1. `uatu-admin consigna sellar <carpeta>` la cifra con AES-256-GCM y una clave aleatoria
   (`consigna.enc` y la clave en un archivo 0600 del docente) y agrega al `.uatu.conf` el bloque
   `consigna` con el hash del contenido (`sha256`, el mismo que calcula la extensión), que
   queda bajo la firma docente.
2. `uatu-admin consigna liberar` descifra **en memoria** y, sólo si la hora del servidor de
   GitHub (cabecera Date, no el reloj local) ya pasó `start_utc`, publica `consigna/` en cada
   repositorio de examen con la API de Git: un commit `uatu: liberar consigna …` con fecha del
   servidor. Ningún secreto llega a los repositorios de los estudiantes: un workflow de
   liberación en el repositorio del estudiante podría ser editado por él para imprimir la
   clave antes de hora.
3. La extensión, al entrar en sesión, trae la consigna y verifica el hash; `uatu-audit`
   comprueba que el commit de liberación sea posterior a `start_utc` y que el contenido coincida.

El hash de una carpeta es SHA-256 de las líneas `<ruta relativa con />\\n<sha256 del archivo>\\n`
de cada archivo, ordenadas por ruta (bytes UTF-8).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMATO = "uatu-consigna-v1"
MENSAJE_LIBERACION = "uatu: liberar consigna"
CARPETA_POR_OMISION = "consigna"


class ConsignaError(Exception):
    pass


class ConsignaAntesDeHora(ConsignaError):
    pass


# --------------------------------------------------------------------------- hash y paquete


def hash_archivos(archivos: Dict[str, bytes]) -> str:
    """Hash de un conjunto de archivos {ruta relativa con /: contenido}."""
    h = hashlib.sha256()
    for ruta in sorted(archivos, key=lambda r: r.encode("utf-8")):
        h.update(f"{ruta}\n{hashlib.sha256(archivos[ruta]).hexdigest()}\n".encode("utf-8"))
    return h.hexdigest()


def leer_carpeta(carpeta: str) -> Dict[str, bytes]:
    archivos: Dict[str, bytes] = {}
    for raiz, dirs, nombres in os.walk(carpeta):
        dirs[:] = [d for d in dirs if d != ".git"]
        for nombre in nombres:
            ruta = os.path.join(raiz, nombre)
            if os.path.islink(ruta):
                raise ConsignaError(f"La consigna no puede tener enlaces simbólicos: {ruta}")
            with open(ruta, "rb") as f:
                archivos[os.path.relpath(ruta, carpeta).replace(os.sep, "/")] = f.read()
    if not archivos:
        raise ConsignaError(f"La carpeta {carpeta} está vacía.")
    return archivos


def sellar(archivos: Dict[str, bytes], clave: Optional[bytes] = None) -> Tuple[Dict[str, Any], bytes]:
    """(paquete cifrado, clave). El hash va como dato asociado: no se puede cambiar sin la clave."""
    clave = clave or AESGCM.generate_key(bit_length=256)
    digest = hash_archivos(archivos)
    nonce = os.urandom(12)
    plano = json.dumps({r: base64.b64encode(c).decode() for r, c in sorted(archivos.items())},
                       sort_keys=True).encode("utf-8")
    cifrado = AESGCM(clave).encrypt(nonce, plano, f"{FORMATO}:{digest}".encode())
    paquete = {"formato": FORMATO, "algoritmo": "AES-256-GCM", "sha256": digest,
               "nonce": base64.b64encode(nonce).decode(), "datos": base64.b64encode(cifrado).decode()}
    return paquete, clave


def abrir(paquete: Dict[str, Any], clave: bytes, sha256_esperado: Optional[str] = None) -> Dict[str, bytes]:
    """Descifra en memoria y verifica el hash (el del `.uatu.conf` firmado, si se da)."""
    if paquete.get("formato") != FORMATO:
        raise ConsignaError(f"Formato de paquete desconocido: {paquete.get('formato')}")
    digest = str(paquete.get("sha256", ""))
    if sha256_esperado and digest != sha256_esperado:
        raise ConsignaError("El paquete no es el de la consigna declarada en .uatu.conf (sha256 distinto).")
    try:
        plano = AESGCM(clave).decrypt(base64.b64decode(paquete["nonce"]), base64.b64decode(paquete["datos"]),
                                      f"{FORMATO}:{digest}".encode())
    except Exception as e:  # noqa: BLE001 - InvalidTag u otro error de formato
        raise ConsignaError("No se pudo descifrar la consigna: clave incorrecta o paquete alterado.") from e
    archivos = {r: base64.b64decode(c) for r, c in json.loads(plano).items()}
    if hash_archivos(archivos) != digest:
        raise ConsignaError("El contenido descifrado no coincide con su hash.")
    return archivos


def codificar_clave(clave: bytes) -> str:
    return base64.b64encode(clave).decode()


def decodificar_clave(texto: str) -> bytes:
    try:
        clave = base64.b64decode(texto.strip(), validate=True)
    except ValueError as e:
        raise ConsignaError("La clave de la consigna no es base64 válido.") from e
    if len(clave) != 32:
        raise ConsignaError("La clave de la consigna tiene que ser de 256 bits.")
    return clave


# --------------------------------------------------------------------------- ventana temporal


def bloque_consigna(config: Dict[str, Any]) -> Optional[Dict[str, str]]:
    bloque = config.get("consigna")
    if not isinstance(bloque, dict) or not bloque.get("sha256"):
        return None
    return {"sha256": str(bloque["sha256"]), "carpeta": str(bloque.get("carpeta") or CARPETA_POR_OMISION)}


def inicio(config: Dict[str, Any]) -> datetime:
    valor = (config.get("session") or {}).get("start_utc")
    if not valor:
        raise ConsignaError(".uatu.conf no tiene session.start_utc.")
    return datetime.strptime(valor, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def fecha_de_github(api_url: str = "https://api.github.com") -> datetime:
    """La hora del servidor de GitHub (cabecera Date): el reloj del docente no manda."""
    import urllib.request

    req = urllib.request.Request(api_url, method="HEAD", headers={"User-Agent": "uatu-admin"})
    with urllib.request.urlopen(req, timeout=15) as res:
        fecha = res.headers.get("Date")
    if not fecha:
        raise ConsignaError("GitHub no informó la hora (cabecera Date).")
    return parsedate_to_datetime(fecha).astimezone(timezone.utc)


def esperar_inicio(config: Dict[str, Any], reloj: Callable[[], datetime], esperar: bool,
                   dormir: Callable[[float], None] = time.sleep) -> datetime:
    """La hora del servidor cuando ya pasó `start_utc`; antes, espera (con `esperar`) o falla."""
    comienzo = inicio(config)
    while True:
        ahora = reloj()
        if ahora >= comienzo:
            return ahora
        faltan = (comienzo - ahora).total_seconds()
        if not esperar:
            raise ConsignaAntesDeHora(f"Todavía no: faltan {int(faltan)} s para start_utc ({comienzo:%Y-%m-%dT%H:%M:%SZ}, "
                                      f"hora de GitHub {ahora:%H:%M:%S}Z). Usá --esperar para liberarla a la hora.")
        dormir(min(max(faltan, 1.0), 30.0))



# --------------------------------------------------------------------------- publicación en GitHub


@dataclass
class Publicacion:
    repo: str
    estado: str  # "liberada", "ya_estaba" o "error"
    detalle: str = ""


def repos_de_la_organizacion(cliente: Any, org: str, prefijo: str) -> List[str]:
    nombres: List[str] = []
    pagina = 1
    while True:
        lote = cliente.request("GET", f"/orgs/{org}/repos?per_page=100&page={pagina}") or []
        nombres += [r["full_name"] for r in lote if str(r.get("name", "")).startswith(prefijo)]
        if len(lote) < 100:
            return sorted(nombres)
        pagina += 1


def publicar(cliente: Any, repo: str, archivos: Dict[str, bytes], carpeta: str, digest: str,
             rama: Optional[str] = None) -> Publicacion:
    """Un commit en `rama` (la principal, por omisión) que agrega `carpeta/` (idempotente)."""
    from uatu_tools.github import GitHubError

    try:
        rama = rama or cliente.request("GET", f"/repos/{repo}")["default_branch"]
        ref = cliente.request("GET", f"/repos/{repo}/git/ref/heads/{rama}")
        padre = ref["object"]["sha"]
        commit_padre = cliente.request("GET", f"/repos/{repo}/git/commits/{padre}")
        arbol_padre = cliente.request("GET", f"/repos/{repo}/git/trees/{commit_padre['tree']['sha']}")
        if any(e.get("path") == carpeta for e in arbol_padre.get("tree", [])):
            return Publicacion(repo, "ya_estaba", f"{carpeta}/ ya existe en {rama}")
        entradas = []
        for ruta, contenido in sorted(archivos.items()):
            blob = cliente.request("POST", f"/repos/{repo}/git/blobs",
                                   {"content": base64.b64encode(contenido).decode(), "encoding": "base64"})
            entradas.append({"path": f"{carpeta}/{ruta}", "mode": "100644", "type": "blob", "sha": blob["sha"]})
        arbol = cliente.request("POST", f"/repos/{repo}/git/trees",
                                {"base_tree": commit_padre["tree"]["sha"], "tree": entradas})
        # Sin author/committer: GitHub usa la cuenta del token y la hora del servidor.
        commit = cliente.request("POST", f"/repos/{repo}/git/commits",
                                 {"message": f"{MENSAJE_LIBERACION} ({digest[:12]})", "tree": arbol["sha"],
                                  "parents": [padre]})
        cliente.request("PATCH", f"/repos/{repo}/git/refs/heads/{rama}", {"sha": commit["sha"], "force": False})
        return Publicacion(repo, "liberada", commit["sha"])
    except (GitHubError, KeyError, TypeError) as e:
        return Publicacion(repo, "error", str(e))
