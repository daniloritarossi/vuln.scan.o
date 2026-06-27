"""
posture.py
----------
Full asset posture (SCA — Software Composition Analysis) SENZA tool esterni.

Per ogni asset raccoglie l'inventario dei pacchetti installati e lo confronta
con OSV.dev (endpoint querybatch) per derivare la "postura" di sicurezza:
pacchetti vulnerabili, CVE totali, distribuzione per severita', score.

Due modalita' di raccolta:
- REALE (SSH, solo se SIMULATE_AUTH=False e asset autenticato): dpkg/rpm/pip.
- SIMULATA (default): inventario realistico e deterministico per IP, con un
  catalogo di pacchetti reali (versioni note vulnerabili) per demo offline.

Nessuna dipendenza nuova: usa 'requests' (gia' presente) verso OSV.
"""

import hashlib
import re
import requests

from scanner import _get_simulate_auth as _sim_auth, _get_socket_timeout as _sock_timeout

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Pesi per il calcolo dello score (piu' alta la severita', piu' pesa).
SEV_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.2, "UNKNOWN": 0.5}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Catalogo pacchetti realistico. Le voci con 'cves' sono versioni note
# vulnerabili (fallback usato se OSV non risponde); 'severity'/'category' danno
# dati ricchi ai grafici. Le voci senza 'cves' sono "pulite" (riempiono il totale).
CATALOG = [
    {"name": "openssl", "version": "1.0.1f", "ecosystem": "Debian", "category": "Crypto",
     "severity": "CRITICAL", "cves": ["CVE-2014-0160", "CVE-2014-3566"]},
    {"name": "bash", "version": "4.3", "ecosystem": "Debian", "category": "OS",
     "severity": "CRITICAL", "cves": ["CVE-2014-6271", "CVE-2014-7169"]},
    {"name": "sudo", "version": "1.8.16", "ecosystem": "Debian", "category": "OS",
     "severity": "HIGH", "cves": ["CVE-2021-3156"]},
    {"name": "openssh", "version": "6.6p1", "ecosystem": "Debian", "category": "Remote Access",
     "severity": "MEDIUM", "cves": ["CVE-2016-6210", "CVE-2016-0777"]},
    {"name": "glibc", "version": "2.23", "ecosystem": "Debian", "category": "OS",
     "severity": "HIGH", "cves": ["CVE-2015-7547"]},
    {"name": "nginx", "version": "1.10.0", "ecosystem": "Debian", "category": "Web",
     "severity": "HIGH", "cves": ["CVE-2017-7529"]},
    {"name": "curl", "version": "7.47.0", "ecosystem": "Debian", "category": "Network",
     "severity": "MEDIUM", "cves": ["CVE-2016-8624"]},
    {"name": "samba", "version": "4.3.11", "ecosystem": "Debian", "category": "Network",
     "severity": "CRITICAL", "cves": ["CVE-2017-7494"]},
    {"name": "wget", "version": "1.17", "ecosystem": "Debian", "category": "Network",
     "severity": "HIGH", "cves": ["CVE-2016-4971"]},
    {"name": "vim", "version": "7.4", "ecosystem": "Debian", "category": "OS",
     "severity": "LOW", "cves": ["CVE-2016-1248"]},
    {"name": "zlib", "version": "1.2.8", "ecosystem": "Debian", "category": "Compression",
     "severity": "MEDIUM", "cves": ["CVE-2016-9841"]},
    # Ecosistemi linguaggi (OSV li risolve bene -> CVE reali in piu').
    {"name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven", "category": "Java Library",
     "severity": "CRITICAL", "cves": ["CVE-2021-44228", "CVE-2021-45046"]},
    {"name": "django", "version": "1.11", "ecosystem": "PyPI", "category": "Python Library",
     "severity": "HIGH", "cves": ["CVE-2019-19844"]},
    {"name": "flask", "version": "0.12", "ecosystem": "PyPI", "category": "Python Library",
     "severity": "MEDIUM", "cves": ["CVE-2018-1000656"]},
    {"name": "requests", "version": "2.19.1", "ecosystem": "PyPI", "category": "Python Library",
     "severity": "MEDIUM", "cves": ["CVE-2018-18074"]},
    {"name": "lodash", "version": "4.17.4", "ecosystem": "npm", "category": "JS Library",
     "severity": "HIGH", "cves": ["CVE-2019-10744"]},
    {"name": "jquery", "version": "1.12.4", "ecosystem": "npm", "category": "JS Library",
     "severity": "MEDIUM", "cves": ["CVE-2019-11358"]},
    # Pacchetti "puliti" (nessuna CVE) per dare un totale realistico.
    {"name": "systemd", "version": "245", "ecosystem": "Debian", "category": "OS"},
    {"name": "coreutils", "version": "8.32", "ecosystem": "Debian", "category": "OS"},
    {"name": "ca-certificates", "version": "20210119", "ecosystem": "Debian", "category": "Crypto"},
    {"name": "tzdata", "version": "2023c", "ecosystem": "Debian", "category": "OS"},
    {"name": "grep", "version": "3.7", "ecosystem": "Debian", "category": "OS"},
]

OS_PROFILES = ["Debian 11", "Ubuntu 20.04", "CentOS 7", "Alpine 3.16"]

# Catalogo applicazioni Windows (coerente con la macchina di test: Notepad++ 7.8.1
# e PuTTY 0.70 sono i due software vulnerabili installati). ecosystem "Windows":
# OSV di norma non risolve queste app -> si usa il fallback cves/severity.
WINDOWS_CATALOG = [
    {"name": "Notepad++", "version": "7.8.1", "ecosystem": "Windows", "category": "Editor",
     "severity": "HIGH", "cves": ["CVE-2021-3811", "CVE-2020-13808"]},
    {"name": "PuTTY", "version": "0.70", "ecosystem": "Windows", "category": "Remote Access",
     "severity": "HIGH", "cves": ["CVE-2019-9894", "CVE-2019-9896", "CVE-2019-9898"]},
    {"name": "7-Zip", "version": "19.00", "ecosystem": "Windows", "category": "Compression",
     "severity": "HIGH", "cves": ["CVE-2022-29072"]},
    {"name": "Mozilla Firefox", "version": "78.0", "ecosystem": "Windows", "category": "Browser",
     "severity": "CRITICAL", "cves": ["CVE-2020-15999", "CVE-2021-29967"]},
    {"name": "Adobe Acrobat Reader DC", "version": "2019.012.20040", "ecosystem": "Windows",
     "category": "PDF", "severity": "CRITICAL", "cves": ["CVE-2021-28550"]},
    {"name": "VLC media player", "version": "3.0.6", "ecosystem": "Windows", "category": "Media",
     "severity": "HIGH", "cves": ["CVE-2019-12874"]},
    {"name": "Wireshark", "version": "3.0.0", "ecosystem": "Windows", "category": "Network",
     "severity": "MEDIUM", "cves": ["CVE-2019-10894"]},
    # "Puliti" (nessuna CVE) per un totale realistico.
    {"name": "Microsoft Edge", "version": "120.0.2210.91", "ecosystem": "Windows", "category": "Browser"},
    {"name": "Microsoft Visual C++ Redistributable", "version": "14.36.32532", "ecosystem": "Windows",
     "category": "Runtime"},
    {"name": "Microsoft Defender", "version": "4.18.23110", "ecosystem": "Windows", "category": "Security"},
]


def _seed(ip: str) -> int:
    return int(hashlib.sha256((ip or "").encode()).hexdigest(), 16)


def simulate_inventory(ip: str):
    """Inventario deterministico per IP: tutti i 'puliti' + subset dei vulnerabili."""
    seed = _seed(ip)
    os_guess = OS_PROFILES[seed % len(OS_PROFILES)]
    inv = []
    for i, pkg in enumerate(CATALOG):
        if not pkg.get("cves"):
            inv.append(dict(pkg))               # i puliti sempre presenti
        elif (seed >> i) & 1:                    # subset deterministico dei vulnerabili
            inv.append(dict(pkg))
    # garantisce almeno un paio di vulnerabili per asset
    if not any(p.get("cves") for p in inv):
        inv.extend(dict(p) for p in CATALOG[:2])
    return os_guess, inv


def simulate_windows_inventory(ip: str, os_major: str = ""):
    """Inventario Windows deterministico per IP: puliti sempre + subset dei
    vulnerabili. Garantisce sempre Notepad++ e PuTTY (coerenza macchina di test)."""
    seed = _seed(ip)
    os_guess = f"Windows {os_major}" if os_major else "Windows 10"
    inv = []
    for i, pkg in enumerate(WINDOWS_CATALOG):
        if not pkg.get("cves"):
            inv.append(dict(pkg))
        elif (seed >> i) & 1:
            inv.append(dict(pkg))
    names = {p["name"] for p in inv}
    for must in ("Notepad++", "PuTTY"):
        if must not in names:
            inv.append(dict(next(p for p in WINDOWS_CATALOG if p["name"] == must)))
    return os_guess, inv


# Righe di intestazione/separatori da ignorare nel parsing dell'inventario Windows.
_WIN_SKIP_RE = re.compile(r"^(name|displayname|-{2,}|=+|\s*$)", re.I)
_WIN_VER_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


def _parse_windows_inventory(out: str):
    """Parsa l'output PowerShell (winget list + registro Uninstall): per ogni riga
    con DisplayName + versione produce un finding. Best-effort, deduplicato."""
    inv = []
    seen = set()
    for raw in out.splitlines():
        line = raw.rstrip()
        if _WIN_SKIP_RE.match(line.strip()):
            continue
        m = _WIN_VER_RE.search(line)
        if not m:
            continue
        name = line[:m.start()].strip()
        # winget ha colonne multiple separate da spazi: il nome e' il primo campo.
        name = re.split(r"\s{2,}", name)[0].strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        inv.append({"name": name, "version": m.group(1),
                    "ecosystem": "Windows", "category": "Application"})
    return inv


def _ssh_inventory_windows(asset):
    """Inventario REALE Windows via SSH (winget + registro). Solo se SIMULATE_AUTH=False."""
    import paramiko
    from scanner import _WINDOWS_INVENTORY_CMD
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        _t = _sock_timeout()
        client.connect(asset.ip, username=asset.username, password=asset.password,
                       timeout=_t, allow_agent=False, look_for_keys=False)
        _, stdout, _ = client.exec_command(_WINDOWS_INVENTORY_CMD, timeout=_t * 6)
        out = stdout.read().decode("utf-8", errors="replace")
    finally:
        client.close()
    return f"windows {asset.os_major_version or ''}".strip(), _parse_windows_inventory(out)


def _ssh_inventory(asset):
    """Inventario REALE via SSH (dpkg + pip). Usato solo se SIMULATE_AUTH=False."""
    import paramiko
    cmd = (
        "(dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null; "
        "echo '---PIP---'; pip3 list --format=freeze 2>/dev/null)"
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        _t = _sock_timeout()
        client.connect(asset.ip, username=asset.username, password=asset.password,
                       timeout=_t, allow_agent=False, look_for_keys=False)
        _, stdout, _ = client.exec_command(cmd, timeout=_t * 4)
        out = stdout.read().decode("utf-8", errors="replace")
    finally:
        client.close()

    inv = []
    eco = "Debian"
    for line in out.splitlines():
        line = line.strip()
        if line == "---PIP---":
            eco = "PyPI"
            continue
        if not line:
            continue
        parts = line.replace("==", " ").split()
        if len(parts) >= 2:
            inv.append({"name": parts[0].lower(), "version": parts[1],
                        "ecosystem": eco, "category": "OS" if eco == "Debian" else "Python Library"})
    return "linux (ssh)", inv


def collect_inventory(asset):
    """
    Ritorna (os_guess, inventory, method).
    method: 'ssh' (reale) | 'sim' (simulato).
    """
    is_windows = (asset.os_type or "").lower() == "windows"
    if not _sim_auth() and asset.auth_required:
        try:
            if is_windows:
                os_guess, inv = _ssh_inventory_windows(asset)
            else:
                os_guess, inv = _ssh_inventory(asset)
            if inv:
                return os_guess, inv, "ssh"
        except Exception:
            pass  # fallback su simulazione in caso di errore SSH
    if is_windows:
        os_guess, inv = simulate_windows_inventory(asset.ip, asset.os_major_version)
    else:
        os_guess, inv = simulate_inventory(asset.ip)
    return os_guess, inv, "sim"


def _osv_batch(inventory, timeout: int = 20) -> dict:
    """querybatch OSV: ritorna {indice: {'count','ids'}}. {} se rete assente."""
    queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                "version": p["version"]} for p in inventory]
    if not queries:
        return {}
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        out = {}
        for i, res in enumerate(resp.json().get("results", [])):
            vulns = res.get("vulns") or []
            ids = [v.get("id") for v in vulns if v.get("id")]
            out[i] = {"count": len(ids), "ids": ids}
        return out
    except Exception:
        return {}


def assess_posture(asset_ip: str, os_guess: str, inventory: list, method: str) -> dict:
    """
    Confronta l'inventario con OSV e aggrega la postura dell'asset.

    Per ogni pacchetto: usa il conteggio/id reali OSV; se OSV non risponde o non
    ha dati, ricade sul fallback del catalogo (cves/severity). Severita' dal
    catalogo (demo) o 'UNKNOWN' per pacchetti reali senza hint.
    """
    osv = _osv_batch(inventory)
    findings = []
    sev_counts = {s: 0 for s in SEV_ORDER}
    total_vulns = 0
    weighted = 0.0

    for i, pkg in enumerate(inventory):
        r = osv.get(i, {})
        ids = r.get("ids") or pkg.get("cves") or []
        count = r.get("count") or len(pkg.get("cves") or [])
        if not ids and not count:
            continue  # pacchetto pulito
        sev = (pkg.get("severity") or "UNKNOWN").upper()
        if sev not in SEV_WEIGHT:
            sev = "UNKNOWN"
        sev_counts[sev] += 1
        total_vulns += count
        weighted += SEV_WEIGHT[sev]
        findings.append({
            "package": pkg["name"],
            "version": pkg["version"],
            "ecosystem": pkg["ecosystem"],
            "category": pkg.get("category") or pkg["ecosystem"],
            "vuln_count": count,
            "max_severity": sev,
            "cve_ids": ids[:25],
        })

    total = len(inventory)
    vulnerable = len(findings)
    # Score 0-100: 100 = nessun rischio. Penalita' pesata per severita'.
    score = 100 if total == 0 else max(0, round(100 * (1 - min(1.0, weighted / total * 1.3))))
    findings.sort(key=lambda f: (SEV_ORDER.index(f["max_severity"]), -f["vuln_count"]))

    return {
        "ip": asset_ip,
        "os_guess": os_guess,
        "method": method,
        "total_packages": total,
        "vulnerable_packages": vulnerable,
        "total_vulns": total_vulns,
        "score": score,
        "sev_critical": sev_counts["CRITICAL"],
        "sev_high": sev_counts["HIGH"],
        "sev_medium": sev_counts["MEDIUM"],
        "sev_low": sev_counts["LOW"],
        "sev_unknown": sev_counts["UNKNOWN"],
        "findings": findings,
    }


def scan_asset_posture(asset) -> dict:
    """Pipeline completa per un asset: raccolta inventario + valutazione."""
    os_guess, inv, method = collect_inventory(asset)
    return assess_posture(asset.ip, os_guess, inv, method)


if __name__ == "__main__":
    from assets import load_assets
    for a in load_assets()[:2]:
        rep = scan_asset_posture(a)
        print(f"{rep['ip']:24} {rep['os_guess']:14} score={rep['score']} "
              f"vuln={rep['vulnerable_packages']}/{rep['total_packages']} "
              f"cves={rep['total_vulns']} method={rep['method']}")
