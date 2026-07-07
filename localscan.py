"""
localscan.py
------------
Wrapper per scanner LOCALI opzionali (capability ASPM: secrets + container).

Se i binari sono installati sulla macchina che ospita l'app, esegue:

  - gitleaks  -> secrets scanning di una directory/repository locale
                 (`gitleaks detect --no-git -s <path> -f json`)
  - trivy     -> vulnerability scanning di un'immagine container
                 (`trivy image <ref> -f json`), incluse le secret rilevate
                 nei layer

L'output JSON del tool viene passato ai parser di ingest.py: i finding
confluiscono nel ciclo di vita unificato come qualunque report importato.

Se il binario manca, LocalScanError con istruzioni: nessuna dipendenza dura.
"""

import shutil
import subprocess
from pathlib import Path

TIMEOUT = 600   # trivy puo' scaricare il DB CVE al primo avvio


class LocalScanError(RuntimeError):
    """Binario assente, target non valido o esecuzione fallita."""


def _require_bin(name: str, hint: str) -> str:
    path = shutil.which(name)
    if not path:
        raise LocalScanError(f"Binario '{name}' non trovato nel PATH. {hint}")
    return path


def run_gitleaks(target_path: str) -> bytes:
    """
    Secrets scan di una directory locale. Ritorna il report JSON (bytes)
    nel formato nativo gitleaks (array di leak).
    """
    p = Path((target_path or "").strip()).expanduser()
    if not p.is_dir():
        raise LocalScanError(f"Directory non valida: {target_path}")
    binpath = _require_bin(
        "gitleaks",
        "Installa da https://github.com/gitleaks/gitleaks/releases")
    report = p / ".gitleaks-report.tmp.json"
    try:
        # exit code 1 = leak trovati (non e' un errore); 0 = puliti.
        proc = subprocess.run(
            [binpath, "detect", "--no-git", "-s", str(p),
             "-f", "json", "-r", str(report), "--exit-code", "1"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        if proc.returncode not in (0, 1):
            raise LocalScanError(
                f"gitleaks fallito (rc={proc.returncode}): {proc.stderr[-200:]}")
        return report.read_bytes() if report.exists() else b"[]"
    except subprocess.TimeoutExpired as exc:
        raise LocalScanError("gitleaks: timeout") from exc
    finally:
        report.unlink(missing_ok=True)


def run_trivy_image(image_ref: str) -> bytes:
    """
    Vulnerability + secrets scan di un'immagine container locale/registry.
    Ritorna il report JSON (bytes) nel formato nativo trivy.
    """
    ref = (image_ref or "").strip()
    if not ref or any(c in ref for c in " ;|&$`"):
        raise LocalScanError(f"Riferimento immagine non valido: {image_ref!r}")
    binpath = _require_bin(
        "trivy",
        "Installa da https://github.com/aquasecurity/trivy/releases")
    try:
        proc = subprocess.run(
            [binpath, "image", "--scanners", "vuln,secret",
             "-f", "json", "-q", ref],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise LocalScanError("trivy: timeout") from exc
    if proc.returncode != 0:
        raise LocalScanError(
            f"trivy fallito (rc={proc.returncode}): {proc.stderr[-200:]}")
    return proc.stdout.encode("utf-8")
