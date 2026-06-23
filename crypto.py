"""
crypto.py
---------
Wrapper per il binario encdec (https://github.com/daniloritarossi/encdec).

Usa modalita' machine-bound: ENC/DEC con ENCDEC_SECRET_PREFIX (env var).
Il prefisso segreto viene caricato una sola volta da start.sh e mai piu' richiesto.

Le password cifrate sono prefissate con "ENC:" nel file assets.txt.
"""

import os
import subprocess
from pathlib import Path

_BIN = Path(__file__).parent / ".encdec" / "encdec"
_PREFIX = "ENC:"
_ENCOUT_PREFIX = "encrypted : "   # encdec stampa "encrypted : <hex>" su stdout


def _bin_path() -> Path:
    if not _BIN.exists():
        raise RuntimeError(
            f"encdec non trovato: {_BIN}. Avvia l'applicazione con start.sh."
        )
    return _BIN


def encrypt_password(plain: str) -> str:
    """Cifra una password con ENC (machine-bound). Ritorna stringa 'ENC:<hex>'."""
    if not plain:
        return plain
    if is_encrypted(plain):
        return plain  # gia' cifrata
    result = subprocess.run(
        [str(_bin_path()), "ENC", plain],
        capture_output=True, text=True,
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        raise RuntimeError(f"encdec ENC fallito: {result.stderr.strip()}")
    out = result.stdout.strip()
    if out.startswith(_ENCOUT_PREFIX):
        out = out[len(_ENCOUT_PREFIX):]
    return _PREFIX + out


def decrypt_password(stored: str) -> str:
    """Decifra con DEC. Stringa senza prefisso ENC: ritornata invariata (retrocompat.)."""
    if not stored or not is_encrypted(stored):
        return stored
    payload = stored[len(_PREFIX):]
    if payload.startswith("p1:"):
        raise RuntimeError(
            "Password nel formato legacy ENCPASS (p1:...) non compatibile con "
            "la modalita' machine-bound attuale. Re-inserire la password "
            "dall'interfaccia asset."
        )
    result = subprocess.run(
        [str(_bin_path()), "DEC", payload],
        capture_output=True, text=True,
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        raise RuntimeError(f"encdec DEC fallito: {result.stderr.strip()}")
    return result.stdout.strip()


def is_encrypted(val: str) -> bool:
    return bool(val) and val.startswith(_PREFIX)
