"""
assets.py
---------
Inventario degli asset, persistito su Supabase (tabella 'assets').

Storicamente l'inventario viveva nel file assets.txt (formato
IP|username|password|os_type|os_major_version|enabled). Ora la sorgente di
verita' e' la tabella 'assets': alla prima lettura, se la tabella e' vuota e
assets.txt esiste, il file viene importato una sola volta e poi rinominato in
assets.txt.migrated (backup).

Regole invariate:
- Se username e password sono assenti o vuoti l'asset e' "Autenticazione non
  richiesta" (auth_required = False).
- Le password sono memorizzate cifrate con prefisso 'ENC:' (vedi crypto.py).
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import db


class AssetStoreError(RuntimeError):
    """Supabase non raggiungibile: inventario asset non disponibile."""


@dataclass
class Asset:
    """Rappresenta un singolo asset dell'inventario."""
    ip: str
    username: str = ""
    password: str = ""
    os_type: str = ""          # "linux" | "windows" | ""
    os_major_version: str = "" # e.g. "22.04", "10", "2019"
    enabled: bool = True       # False => asset escluso dalle scansioni
    # Contesto business (capability ASPM: prioritizzazione contestuale del rischio).
    environment: str = "unknown"     # "production" | "staging" | "dev" | "unknown"
    internet_facing: bool = False    # esposto su internet
    criticality: int = 3             # 1 (basso) .. 5 (alto)
    id: Optional[int] = None   # id riga Supabase (None se non persistito)

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
            "enabled": self.enabled,
            "environment": self.environment,
            "internet_facing": self.internet_facing,
            "criticality": self.criticality,
        }

    def to_row(self) -> dict:
        """Riga per la tabella 'assets' (password inclusa, gia' cifrata)."""
        return {
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "os_type": self.os_type,
            "os_major_version": self.os_major_version,
            "enabled": self.enabled,
            "environment": self.environment,
            "internet_facing": self.internet_facing,
            "criticality": self.criticality,
        }


def _row_to_asset(row: dict) -> Asset:
    """Converte una riga della tabella 'assets' in un oggetto Asset."""
    return Asset(
        ip=row.get("ip") or "",
        username=row.get("username") or "",
        password=row.get("password") or "",
        os_type=(row.get("os_type") or "").lower(),
        os_major_version=row.get("os_major_version") or "",
        enabled=bool(row.get("enabled", True)),
        environment=(row.get("environment") or "unknown"),
        internet_facing=bool(row.get("internet_facing", False)),
        criticality=int(row.get("criticality") or 3),
        id=row.get("id"),
    )


def parse_line(line: str) -> Asset | None:
    """
    Converte una singola riga del legacy assets.txt in un oggetto Asset.
    Usata solo dalla migrazione una-tantum.

    Ritorna None se la riga e' un commento, e' vuota o non contiene un IP.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split("|")
    ip = parts[0].strip()
    if not ip:
        return None

    username = parts[1].strip() if len(parts) > 1 else ""
    password = parts[2].strip() if len(parts) > 2 else ""
    os_type = parts[3].strip().lower() if len(parts) > 3 else ""
    os_major_version = parts[4].strip() if len(parts) > 4 else ""
    # Campo 'enabled' (opzionale, ultimo): assente o vuoto => abilitato (retrocompat).
    # Disabilitato solo con un valore esplicito falsy (0/false/no/off/disabled).
    enabled_raw = parts[5].strip().lower() if len(parts) > 5 else ""
    enabled = enabled_raw not in ("0", "false", "no", "off", "disabled")
    return Asset(ip=ip, username=username, password=password,
                 os_type=os_type, os_major_version=os_major_version,
                 enabled=enabled)


def _migrate_from_file(path: str | Path) -> bool:
    """
    Importa il legacy assets.txt nella tabella 'assets' (solo se la tabella
    e' vuota, controllato dal chiamante). Dopo l'import il file viene
    rinominato in <path>.migrated come backup. Ritorna True se ha importato.
    """
    p = Path(path)
    if not p.exists():
        return False
    parsed = [a for a in
              (parse_line(raw) for raw in p.read_text(encoding="utf-8").splitlines())
              if a]
    if not parsed:
        return False
    if not db.insert_assets([a.to_row() for a in parsed]):
        return False
    p.rename(p.with_suffix(p.suffix + ".migrated"))
    return True


def load_assets(path: str | Path = "assets.txt") -> List[Asset]:
    """
    Carica l'inventario dalla tabella 'assets' (ordinato per id).

    'path' indica il legacy assets.txt, usato solo per la migrazione
    una-tantum quando la tabella e' vuota.

    Solleva AssetStoreError se Supabase non e' raggiungibile.
    """
    rows = db.fetch_assets()
    if rows is None:
        raise AssetStoreError(
            "Supabase non raggiungibile: inventario asset non disponibile.")
    if not rows and _migrate_from_file(path):
        rows = db.fetch_assets() or []
    return [_row_to_asset(r) for r in rows]


def get_asset(asset_id: int, path: str | Path = "assets.txt") -> Optional[Asset]:
    """Ritorna l'asset con l'id indicato, None se non esiste."""
    for a in load_assets(path):
        if a.id == asset_id:
            return a
    return None


def add_asset(asset: Asset) -> Optional[int]:
    """Inserisce un asset in tabella e ritorna il suo id (None se fallisce)."""
    return db.insert_asset(asset.to_row())


def update_asset(asset_id: int, asset: Asset) -> bool:
    """Aggiorna l'asset indicato. False se non esiste o DB non raggiungibile."""
    return db.update_asset(asset_id, asset.to_row())


def set_asset_enabled(asset_id: int, enabled: bool) -> bool:
    """Abilita/disabilita l'asset indicato."""
    return db.update_asset(asset_id, {"enabled": bool(enabled)})


def update_asset_fields(asset_id: int, fields: dict) -> bool:
    """Aggiorna un sottoinsieme di campi dell'asset (es. contesto business)."""
    return db.update_asset(asset_id, fields)


def delete_asset(asset_id: int) -> bool:
    """Elimina l'asset indicato. False se non esiste o DB non raggiungibile."""
    return db.delete_asset(asset_id)


if __name__ == "__main__":
    # Test rapido: stampa l'inventario interpretato.
    for a in load_assets():
        mode = "AUTH" if a.auth_required else "NO-AUTH"
        print(f"[{a.id}] {a.ip:20} [{mode}] user={a.username or '-'}")
