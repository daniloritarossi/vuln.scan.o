"""
assets.py
---------
Lettura e parsing del file inventario degli asset.

Formato di ogni riga del file (default: assets.txt):

    IP|username|password

Regole:
- Le righe vuote e quelle che iniziano con '#' sono ignorate (commenti).
- Se username e password sono assenti o vuoti (es. "1.2.3.4||" oppure
  solo "1.2.3.4"), l'asset viene marcato come "Autenticazione non richiesta"
  (auth_required = False).
- Se sono presenti credenziali, auth_required = True.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class Asset:
    """Rappresenta un singolo asset dell'inventario."""
    ip: str
    username: str = ""
    password: str = ""
    os_type: str = ""          # "linux" | "windows" | ""
    os_major_version: str = "" # e.g. "22.04", "10", "2019"

    @property
    def auth_required(self) -> bool:
        """True se l'asset ha credenziali (username e password valorizzati)."""
        return bool(self.username and self.password)

    def to_dict(self) -> dict:
        """Versione serializzabile (senza esporre la password in chiaro)."""
        return {
            "ip": self.ip,
            "username": self.username or None,
            "auth_required": self.auth_required,
            "os_type": self.os_type or None,
            "os_major_version": self.os_major_version or None,
        }


def parse_line(line: str) -> Asset | None:
    """
    Converte una singola riga del file in un oggetto Asset.

    Ritorna None se la riga e' un commento, e' vuota o non contiene un IP.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Split su '|' mantenendo eventuali campi vuoti (maxsplit per robustezza).
    parts = line.split("|")
    ip = parts[0].strip()
    if not ip:
        return None

    username = parts[1].strip() if len(parts) > 1 else ""
    password = parts[2].strip() if len(parts) > 2 else ""
    os_type = parts[3].strip().lower() if len(parts) > 3 else ""
    os_major_version = parts[4].strip() if len(parts) > 4 else ""
    return Asset(ip=ip, username=username, password=password,
                 os_type=os_type, os_major_version=os_major_version)


def load_assets(path: str | Path = "assets.txt") -> List[Asset]:
    """
    Carica tutti gli asset validi dal file di inventario.

    Solleva FileNotFoundError se il file non esiste.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Inventory not found: {p}")

    assets: List[Asset] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        asset = parse_line(raw)
        if asset:
            assets.append(asset)
    return assets


def save_assets(assets: List[Asset], path: str | Path = "assets.txt") -> None:
    """
    Riscrive il file di inventario con la lista di asset fornita.

    Preserva il blocco di commenti iniziale (righe '#' o vuote in testa al file)
    e riscrive le righe asset nel formato 'IP|username|password'.
    """
    p = Path(path)
    header: List[str] = []
    if p.exists():
        for raw in p.read_text(encoding="utf-8").splitlines():
            s = raw.strip()
            if s.startswith("#") or not s:
                header.append(raw)
            else:
                break  # primo asset: il blocco header e' finito.

    lines = header[:]
    if lines and lines[-1].strip() != "":
        lines.append("")
    for a in assets:
        lines.append(f"{a.ip}|{a.username}|{a.password}|{a.os_type}|{a.os_major_version}")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    # Test rapido: stampa l'inventario interpretato.
    for a in load_assets():
        mode = "AUTH" if a.auth_required else "NO-AUTH"
        print(f"{a.ip:20} [{mode}] user={a.username or '-'}")
