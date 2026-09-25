"""
Integración con GitHub para la cátedra.

- Reglas de protección (rulesets) para las ramas de telemetría uatu-audit/**:
  impiden borrarlas y reescribirlas (force-push) sin bloquear la creación ni
  los pushes normales de la extensión.
- Carga de secretos y variables de Actions mediante la CLI `gh`, que cifra los
  secretos con la clave pública del repositorio.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

API_URL = "https://api.github.com"
RULESET_NAME = "uatu: telemetría inmutable"


class GitHubError(Exception):
    pass


# --------------------------------------------------------------------------- autenticación


def resolve_token(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> str:
    """GH_TOKEN, GITHUB_TOKEN o, en su defecto, `gh auth token`."""
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    if shutil.which("gh"):
        res = runner(["gh", "auth", "token"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    raise GitHubError("No hay credenciales de GitHub: defina GH_TOKEN o inicie sesión con 'gh auth login'.")


# --------------------------------------------------------------------------- API REST

Transport = Callable[[str, str, Optional[Dict[str, Any]], Dict[str, str]], Tuple[int, Any]]


def urllib_transport(method: str, url: str, body: Optional[Dict[str, Any]], headers: Dict[str, str]) -> Tuple[int, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            raw = res.read().decode("utf-8")
            return res.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"message": raw}
        return e.code, payload


@dataclass
class GitHubClient:
    token: str
    transport: Transport = urllib_transport
    api_url: str = API_URL

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "uatu-admin",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        status, payload = self.transport(method, self.api_url + path, body, headers)
        if status >= 400:
            message = payload.get("message") if isinstance(payload, dict) else payload
            details = payload.get("errors") if isinstance(payload, dict) else None
            hint = ""
            if status == 404:
                hint = " (¿existe el repositorio/organización y el token tiene permisos de administración?)"
            elif status == 403:
                hint = " (el token necesita permisos de administración sobre el repositorio u organización)"
            raise GitHubError(f"GitHub respondió {status} a {method} {path}: {message}{hint}"
                              + (f" {details}" if details else ""))
        return payload


# --------------------------------------------------------------------------- rulesets


def branch_pattern(prefix: str) -> str:
    return f"refs/heads/{prefix.strip('/')}/**"


def build_ruleset(prefix: str, name: str = RULESET_NAME,
                  repository_patterns: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """
    Ruleset que bloquea el borrado y el force-push de <prefix>/** para todos,
    incluidos los administradores (sin bypass). La creación y los pushes con
    avance rápido siguen permitidos, que es lo que hace la extensión.
    """
    conditions: Dict[str, Any] = {"ref_name": {"include": [branch_pattern(prefix)], "exclude": []}}
    if repository_patterns is not None:
        conditions["repository_name"] = {"include": list(repository_patterns), "exclude": [], "protected": False}
    return {
        "name": name,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": conditions,
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
    }


def apply_ruleset(client: GitHubClient, scope: str, ruleset: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Crea o actualiza (por nombre) el ruleset en `scope`, que es
    "repos/<owner>/<repo>" u "orgs/<org>". Devuelve ("creado"|"actualizado", ruleset).
    """
    # En un repositorio se excluyen los rulesets heredados de la organización.
    query = "?per_page=100" + ("&includes_parents=false" if scope.startswith("repos/") else "")
    existing: List[Dict[str, Any]] = client.request("GET", f"/{scope}/rulesets{query}") or []
    match = next((r for r in existing if r.get("name") == ruleset["name"]), None)
    if match:
        result = client.request("PUT", f"/{scope}/rulesets/{match['id']}", ruleset)
        return "actualizado", result
    result = client.request("POST", f"/{scope}/rulesets", ruleset)
    return "creado", result


# --------------------------------------------------------------------------- secretos y variables


Runner = Callable[..., subprocess.CompletedProcess]


def _target_args(repo: Optional[str], org: Optional[str], visibility: Optional[str]) -> List[str]:
    if bool(repo) == bool(org):
        raise GitHubError("Indique exactamente uno de --repo OWNER/REPO u --org ORG.")
    if repo:
        return ["--repo", repo]
    args = ["--org", str(org)]
    if visibility:
        args += ["--visibility", visibility]
    return args


def set_actions_value(kind: str, name: str, value: str, repo: Optional[str] = None, org: Optional[str] = None,
                      visibility: Optional[str] = None, runner: Runner = subprocess.run) -> None:
    """Carga un secreto (kind="secret") o variable (kind="variable") de Actions con `gh`."""
    if kind not in ("secret", "variable"):
        raise ValueError(kind)
    if not shutil.which("gh") and runner is subprocess.run:
        raise GitHubError("Se necesita la CLI 'gh' para cargar secretos y variables (https://cli.github.com).")
    cmd = ["gh", kind, "set", name] + _target_args(repo, org, visibility)
    # El valor viaja por stdin: nunca queda en la línea de comandos ni en el historial.
    res = runner(cmd, input=value, capture_output=True, text=True)
    if res.returncode != 0:
        raise GitHubError(f"'gh {kind} set {name}' falló: {(res.stderr or res.stdout).strip()}")
