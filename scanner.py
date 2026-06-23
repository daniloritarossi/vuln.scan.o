"""
scanner.py
----------
Motore di verifica (fingerprinting + matching).

Per ogni asset dell'inventario il motore stabilisce se il "Software Target"
identificato dall'OSINT e' presente, e con quale versione.

Due modalita', scelte in base alla presenza di credenziali sull'asset:

- NO-AUTH  -> banner grabbing REALE non autenticato: apertura di una socket TCP
              sulle porte note del prodotto e lettura del banner di servizio.
              Tecnica passiva/leggera, equivalente a `nmap -sV` su un singolo
              servizio. Da usare solo su asset che si e' autorizzati a testare.

- AUTH     -> accesso autenticato. Per sicurezza e' SIMULATO di default
              (SIMULATE_AUTH = True): non vengono effettuati login SSH reali
              verso host arbitrari. Lo scheletro paramiko e' presente e
              attivabile solo consapevolmente su asset di proprieta'.

ATTENZIONE: eseguire scansioni o login contro sistemi senza autorizzazione
esplicita e' illecito. Usare solo su asset di cui si ha la titolarita'.
"""

import re
import socket
from dataclasses import dataclass
from typing import Optional

from assets import Asset
from config import load_config
from crypto import decrypt_password
from osint import TargetInfo


def _scanner_cfg():
    return load_config()["scanner"]


# Mantenuti per compatibilita' con import esterni (app.py usa SIMULATE_AUTH).
@property
def _simulate_auth_prop():
    return _scanner_cfg().get("simulate_auth", True)


def _get_simulate_auth() -> bool:
    return bool(_scanner_cfg().get("simulate_auth", True))


def _get_socket_timeout() -> float:
    return float(_scanner_cfg().get("socket_timeout", 4.0))


# Retrocompatibilità: app.py importa SIMULATE_AUTH
SIMULATE_AUTH = True  # valore iniziale; scan_asset legge config a runtime

# Porte tipiche per prodotto (usate sia per banner grab che per la simulazione).
PRODUCT_PORTS = {
    "openssh": [22],
    "apache": [80, 443, 8080],
    "nginx": [80, 443, 8080],
    "python": [80, 8000, 8080, 5000],
    "php": [80, 443],
    "mysql": [3306],
    "postgresql": [5432],
    "redis": [6379],
    "tomcat": [8080, 8443],
    "vsftpd": [21],
    "exim": [25],
}

# Per il banner grab HTTP serve inviare una richiesta minima.
_HTTP_PORTS = {80, 8080, 8000, 5000, 8443, 443}

# Regex per estrarre versione da un banner (es. "OpenSSH_8.4p1", "nginx/1.21.0").
_BANNER_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3}[a-z]?\d*)")
# Versione "attaccata" al nome prodotto: <parola>('_'|'/')<versione>
# (es. OpenSSH_6.6.1p1, nginx/1.21.0, Apache/2.4.49). Cattura anche la parola
# che precede, cosi' da scartare le versioni di protocollo (HTTP/1.1, SSH-2.0).
_BANNER_PRODUCT_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9]*)[_/](\d+(?:\.\d+){1,3}[a-z]?\d*)"
)
# Token di protocollo da ignorare: la loro "versione" non e' quella del prodotto.
_PROTOCOL_TOKENS = {"http", "https", "ssh"}

# Versione dell'interprete Python: "Python/3.9.2" (header Server, Werkzeug/mod_wsgi)
# oppure "Python 3.9.2" (output di `python3 --version` / traceback).
_PYTHON_VERSION_RE = re.compile(r"python[/ ]v?(\d+(?:\.\d+){1,2})", re.I)


@dataclass
class ScanResult:
    """Esito della verifica per un singolo asset."""
    ip: str
    auth_required: bool
    method: str                       # "banner-grab" | "auth-sim" | "auth-ssh"
    product_found: bool
    detected_version: Optional[str]
    raw_evidence: str                 # banner o nota diagnostica
    vuln_match: str                   # "VULNERABILE" | "NON VULNERABILE" | "INCERTO"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "auth_required": self.auth_required,
            "method": self.method,
            "product_found": self.product_found,
            "detected_version": self.detected_version,
            "raw_evidence": self.raw_evidence[:300],
            "vuln_match": self.vuln_match,
        }


def _grab_banner(ip: str, port: int) -> str:
    """
    Apre una socket TCP e legge il banner del servizio.
    Per le porte HTTP invia una HEAD minima per sollecitare l'header Server.
    Ritorna stringa vuota in caso di porta chiusa/timeout.
    """
    timeout = _get_socket_timeout()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in _HTTP_PORTS:
                req = (
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
                    "User-Agent: VulnFeedAggregator/1.0\r\n\r\n"
                )
                sock.sendall(req.encode())
            data = sock.recv(2048)
            return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _http_get(ip: str, port: int, path: str = "/", maxbytes: int = 8192) -> str:
    """GET HTTP completo (header + corpo) per il deep probe. '' se fallisce."""
    timeout = _get_socket_timeout()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            req = (
                f"GET {path} HTTP/1.1\r\nHost: {ip}\r\n"
                "User-Agent: VulnFeedAggregator/1.0\r\nAccept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.sendall(req.encode())
            data = b""
            while len(data) < maxbytes:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _deep_python_probe(ip: str):
    """
    DEEP PROBE (attivo, opzionale): deduce la versione di Python oltre il banner
    passivo. Invia GET completi su '/' e su un path inesistente (per sollecitare
    404/500 e traceback dei framework) e cerca 'Python/X.Y' nell'header Server o
    'Python 3.x.y' in pagine d'errore/traceback.

    Ritorna (versione|None, evidenza). Genera traffico extra: usare solo su
    target autorizzati.
    """
    bogus = "/vfa-probe-nonexistent-aaaaaaaa"
    for port in PRODUCT_PORTS.get("python", [80, 8000, 8080, 5000]):
        for path in ("/", bogus):
            body = _http_get(ip, port, path)
            if not body:
                continue
            m = _PYTHON_VERSION_RE.search(body)
            if m:
                snippet = " ".join(body.split())[:140]
                return m.group(1), f":{port}{path} {snippet}"
    return None, ""


def _version_from_banner(banner: str) -> Optional[str]:
    """
    Estrae la versione del prodotto dal banner.
    Preferisce la versione "attaccata" al nome (dopo '_' o '/'), cosi' da
    ignorare la versione di protocollo (es. "SSH-2.0-OpenSSH_6.6.1p1" -> 6.6.1p1).
    In assenza, ricade sulla prima versione numerica presente.
    """
    for word, ver in _BANNER_PRODUCT_VERSION_RE.findall(banner):
        if word.lower() not in _PROTOCOL_TOKENS:
            return ver  # prima versione legata a un nome non-protocollo
    m = _BANNER_VERSION_RE.search(banner)
    return m.group(1) if m else None


def _product_in_text(product: str, text: str) -> bool:
    """True se il nome prodotto (o alias HTTP comune) compare nel testo banner."""
    text_l = text.lower()
    if product in text_l:
        return True
    # Alias frequenti nei banner reali.
    aliases = {
        "openssh": ["ssh"],
        "apache": ["apache", "httpd"],
        "nginx": ["nginx"],
        "python": ["python", "werkzeug", "gunicorn"],
    }
    return any(a in text_l for a in aliases.get(product, []))


def _compare_versions(found: str, target: str) -> bool:
    """
    Confronto numerico semplice: True se la versione rilevata e' <= target
    (euristica "potenzialmente vulnerabile fino alla versione indicata").
    In caso di parsing fallito ritorna True (prudenziale -> INCERTO a monte).
    """
    def norm(v: str):
        nums = re.findall(r"\d+", v)
        return tuple(int(n) for n in nums[:3]) if nums else None

    a, b = norm(found), norm(target)
    if not a or not b:
        return True
    # pad a stessa lunghezza
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return a <= b


def _norm_version(v: str):
    """Versione -> tupla di al piu' 3 interi (None se non parsabile)."""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:3]) if nums else None


def version_affected(detected: Optional[str], expr: str):
    """
    True/False/None: la versione 'detected' rientra nel vincolo 'expr'?

    'expr' es: 'all', '<2.5.0', '>=1.0 <2.0', '==1.2.3'. Ritorna None se il
    confronto non e' determinabile (versione/vincolo non parsabili) -> INCERTO.
    """
    if not expr:
        return None
    e = expr.strip().lower()
    if e in ("all", "any", "*"):
        return True
    cons = re.findall(r"(<=|>=|==|<|>)\s*([0-9][0-9.]*)", e)
    if not cons:
        m = re.search(r"([0-9][0-9.]*)", e)
        cons = [("<=", m.group(1))] if m else []
    if not cons:
        return None
    d = _norm_version(detected or "")
    if d is None:
        return None
    for op, ver in cons:
        b = _norm_version(ver)
        if b is None:
            continue
        length = max(len(d), len(b))
        a = d + (0,) * (length - len(d))
        b = b + (0,) * (length - len(b))
        ok = ((op == "<" and a < b) or (op == "<=" and a <= b) or
              (op == ">" and a > b) or (op == ">=" and a >= b) or
              (op == "==" and a == b))
        if not ok:
            return False
    return True


def _match_vuln(target: TargetInfo, found: bool, version: Optional[str]) -> str:
    """
    Decide l'esito del matching tra prodotto rilevato e vulnerabilita' inserita.
    """
    if not found:
        return "NON VULNERABILE"
    if not target.version or not version:
        # Prodotto presente ma versione non confrontabile.
        return "INCERTO"
    return "VULNERABILE" if _compare_versions(version, target.version) else "NON VULNERABILE"


def _scan_noauth(asset: Asset, target: TargetInfo, deep: bool = False) -> ScanResult:
    """
    Path non autenticato: banner grabbing reale sulle porte del prodotto.

    Se deep=True ed il prodotto e' Python, attiva il DEEP PROBE (GET completi +
    pagine d'errore) per dedurre la versione dell'interprete quando il banner
    passivo non la espone.
    """
    ports = PRODUCT_PORTS.get(target.product or "", [80, 443, 22])
    evidence = ""
    found = False
    version = None

    for port in ports:
        banner = _grab_banner(asset.ip, port)
        if not banner:
            continue
        evidence = f":{port} {banner}"
        if _product_in_text(target.product, banner):
            found = True
            version = _version_from_banner(banner)
            # Per Python, preferisci il token interprete "Python/X.Y" (Werkzeug,
            # mod_wsgi) rispetto alla versione del web server nel banner.
            if target.product == "python":
                pm = _PYTHON_VERSION_RE.search(banner)
                if pm:
                    version = pm.group(1)
            break

    # DEEP PROBE opzionale: solo Python e solo se la versione non e' nota.
    if deep and target.product == "python" and not version:
        v, ev = _deep_python_probe(asset.ip)
        if v:
            found = True
            version = v
            evidence = (f"{evidence} | DEEP {ev}").strip(" |")

    if not evidence:
        evidence = "Nessuna porta target raggiungibile / nessun banner."

    return ScanResult(
        ip=asset.ip,
        auth_required=False,
        method="deep-probe" if (deep and target.product == "python") else "banner-grab",
        product_found=found,
        detected_version=version,
        raw_evidence=evidence,
        vuln_match=_match_vuln(target, found, version),
    )


def _scan_auth_simulated(asset: Asset, target: TargetInfo) -> ScanResult:
    """
    Path autenticato SIMULATO: non effettua login reali.
    Genera un esito deterministico a partire da IP+prodotto per demo/test.
    """
    # Pseudo-determinismo: l'asset "possiede" il prodotto se l'hash combinato e' pari.
    seed = sum(ord(c) for c in (asset.ip + (target.product or ""))) % 3
    found = seed != 0
    version = target.version if found else None  # demo: assume versione vulnerabile

    return ScanResult(
        ip=asset.ip,
        auth_required=True,
        method="auth-sim",
        product_found=found,
        detected_version=version,
        raw_evidence=(
            f"[SIMULATO] login con user '{asset.username}'. "
            f"Query pacchetti installati per '{target.product}'."
        ),
        vuln_match=_match_vuln(target, found, version),
    )


def _scan_auth_real(asset: Asset, target: TargetInfo) -> ScanResult:
    """
    Path autenticato REALE via SSH (paramiko). Attivo solo se SIMULATE_AUTH=False.
    Esegue un comando di inventario pacchetti e ne fa il parsing.

    USARE SOLO SU HOST DI PROPRIA TITOLARITA'.
    """
    import paramiko  # import locale: dipendenza richiesta solo in questo path

    product = target.product or ""
    # Per Python si usa sempre 'python3 --version'; per gli altri il binario omonimo.
    binary = "python3" if product == "python" else product
    cmd = f"({binary} --version 2>&1; dpkg -l 2>/dev/null | grep -i {product})"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            asset.ip,
            username=asset.username,
            password=decrypt_password(asset.password),
            timeout=_get_socket_timeout(),
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, _ = client.exec_command(cmd, timeout=_get_socket_timeout())
        out = stdout.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return ScanResult(
            ip=asset.ip, auth_required=True, method="auth-ssh",
            product_found=False, detected_version=None,
            raw_evidence=f"SSH errore: {exc}", vuln_match="INCERTO",
        )
    finally:
        client.close()

    found = _product_in_text(product, out)
    if found and product == "python":
        pm = _PYTHON_VERSION_RE.search(out)   # 'Python 3.9.2' da python3 --version
        version = pm.group(1) if pm else _version_from_banner(out)
    else:
        version = _version_from_banner(out) if found else None
    return ScanResult(
        ip=asset.ip, auth_required=True, method="auth-ssh",
        product_found=found, detected_version=version,
        raw_evidence=out or "Nessun output.",
        vuln_match=_match_vuln(target, found, version),
    )


def scan_asset(asset: Asset, target: TargetInfo, deep: bool = False) -> ScanResult:
    """
    Verifica un singolo asset scegliendo il metodo in base alle credenziali.

    'deep' (solo path non autenticato) attiva il DEEP PROBE per la versione Python.
    Gli asset autenticati eseguono comunque 'python3 --version'.
    """
    if not asset.auth_required:
        return _scan_noauth(asset, target, deep=deep)
    if _get_simulate_auth():
        return _scan_auth_simulated(asset, target)
    return _scan_auth_real(asset, target)


if __name__ == "__main__":
    from assets import load_assets
    from osint import identify_product

    tgt = identify_product("Buffer overflow affecting OpenSSH 8.4", use_osint=False)
    print("Target:", tgt.to_dict())
    for a in load_assets():
        print(scan_asset(a, tgt).to_dict())
