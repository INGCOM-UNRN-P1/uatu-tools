"""
Integración con GitHub para la cátedra: carga de secretos y variables de
Actions mediante la CLI `gh`, que cifra los secretos con la clave pública del
repositorio.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Callable, List, Optional


class GitHubError(Exception):
    pass


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
