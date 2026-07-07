"""
risk.py
-------
Prioritizzazione CONTESTUALE del rischio applicativo (capability ASPM).

Chiude i gap concettuali piu' citati rispetto ai tool ASPM di mercato, senza
introdurre dipendenze nuove (solo 'requests', gia' presente):

1) EXPLOITABILITY reale
   - EPSS (FIRST.org): probabilita' che una CVE venga sfruttata entro 30 giorni.
   - CISA KEV: catalogo delle vulnerabilita' note come attivamente sfruttate.
   Una CVE in KEV o con EPSS alto pesa molto piu' di una con la stessa severita'
   ma senza evidenza di sfruttamento.

2) REACHABILITY "lite"
   Correla i pacchetti vulnerabili con le porte di servizio realmente APERTE
   sull'asset (sonda TCP passiva). "Vulnerabile ED esposto" > "vulnerabile".

3) CONTESTO BUSINESS
   Criticita' dell'asset (1-5), ambiente (prod/staging/dev) ed esposizione
   internet pesano lo score. Un critical su un asset prod internet-facing conta
   piu' dello stesso critical su un asset dev interno.

Filosofia best-effort come il resto dell'app: se EPSS/KEV/rete non rispondono,
il calcolo procede con i fattori neutri e la pagina resta usabile offline.
"""

import math
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Peso base per severita' (allineato a posture.SEV_WEIGHT).
SEV_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.2, "UNKNOWN": 0.5}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Ambiente -> moltiplicatore di contesto. 'unknown' = neutro.
ENV_FACTOR = {"production": 1.35, "prod": 1.35, "staging": 0.85,
              "dev": 0.55, "development": 0.55, "test": 0.55, "unknown": 1.0, "": 1.0}

# Porte di servizio note per pacchetto/prodotto: se una di queste e' APERTA
# sull'asset, il pacchetto vulnerabile e' considerato "raggiungibile".
# Solo pacchetti che espongono un servizio di rete (i pacchetti-libreria non
# sono direttamente raggiungibili e restano non esposti).
PKG_SERVICE_PORTS = {
    "openssh": [22], "openssh-server": [22], "ssh": [22], "putty": [22],
    "nginx": [80, 443, 8080], "apache2": [80, 443, 8080], "apache": [80, 443, 8080],
    "httpd": [80, 443, 8080], "tomcat": [8080, 8443],
    "samba": [445, 139], "smbd": [445, 139],
    "vsftpd": [21], "proftpd": [21], "ftp": [21],
    "mysql": [3306], "mariadb": [3306], "postgresql": [5432], "postgres": [5432],
    "redis": [6379], "mongodb": [27017], "memcached": [11211],
    "exim": [25], "postfix": [25], "bind9": [53], "named": [53],
    "openssl": [443, 8443],  # tipicamente esposto tramite un servizio TLS
}

# Cache in-process del catalogo KEV (aggiornato ~1x/giorno lato CISA).
_KEV_CACHE = {"set": None, "ts": 0.0}
_KEV_TTL = 6 * 3600


def fetch_kev(timeout: int = 15) -> set:
    """Set di CVE ID presenti nel catalogo CISA KEV. set() se non raggiungibile."""
    now = time.time()
    if _KEV_CACHE["set"] is not None and (now - _KEV_CACHE["ts"]) < _KEV_TTL:
        return _KEV_CACHE["set"]
    try:
        resp = requests.get(KEV_URL, timeout=timeout)
        resp.raise_for_status()
        ids = {v.get("cveID") for v in resp.json().get("vulnerabilities", []) if v.get("cveID")}
        _KEV_CACHE["set"] = ids
        _KEV_CACHE["ts"] = now
        return ids
    except Exception:
        # Non azzera una cache valida: preferisce dati vecchi a nessun dato.
        return _KEV_CACHE["set"] or set()


def fetch_epss(cve_ids, timeout: int = 15) -> dict:
    """
    Mappa {cve_id: epss_float} per gli id richiesti. {} se non raggiungibile.
    L'API accetta liste separate da virgola; si spezza in chunk prudenti.
    """
    ids = [c for c in dict.fromkeys(cve_ids) if c and c.upper().startswith("CVE-")]
    out = {}
    if not ids:
        return out
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=timeout)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cve = row.get("cve")
                try:
                    out[cve] = float(row.get("epss") or 0.0)
                except (TypeError, ValueError):
                    out[cve] = 0.0
        except Exception:
            continue  # chunk fallito: gli id restano senza EPSS (fattore neutro)
    return out


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def probe_open_ports(host: str, ports, timeout: float = 1.2) -> set:
    """Set delle porte APERTE fra quelle richieste (sonda TCP parallela)."""
    ports = sorted(set(ports))
    if not host or not ports:
        return set()
    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as ex:
        results = ex.map(lambda p: (p, _port_open(host, p, timeout)), ports)
    return {p for p, ok in results if ok}


def _pkg_ports(name: str) -> list:
    """Porte di servizio note per un pacchetto (case-insensitive). [] se libreria."""
    return PKG_SERVICE_PORTS.get((name or "").lower(), [])


def _crit_factor(criticality) -> float:
    """Criticita' 1-5 -> moltiplicatore 0.76..1.40 (3 = ~1.08, neutro-alto)."""
    try:
        c = int(criticality)
    except (TypeError, ValueError):
        c = 3
    c = max(1, min(5, c))
    return 0.6 + c * 0.16


def _finding_cves(f) -> list:
    ids = f.get("cve_ids") or f.get("cve_ids".upper()) or []
    if isinstance(ids, str):
        ids = [ids]
    return [c for c in ids if c]


def assess_run_risk(run: dict, assets_ctx: dict, probe: bool = True) -> dict:
    """
    Calcola il rischio contestuale per una run di postura.

    - run:         output di db.fetch_posture() (posture_assets -> posture_findings)
    - assets_ctx:  {ip: {environment, internet_facing, criticality}} dall'inventario
    - probe:       se True, sonda le porte reali per la reachability (puo' rallentare)

    Ritorna un dict serializzabile con:
      assets[]  : per asset -> risk_index (0-100, alto = peggio), fattori, findings top
      summary   : conteggi aggregati (kev, esposti, per fascia di rischio)
      meta      : disponibilita' fonti (epss/kev/probe)
    """
    posture_assets = (run or {}).get("posture_assets") or []

    # 1) Raccoglie tutte le CVE della run per l'arricchimento in blocco.
    all_cves = []
    for pa in posture_assets:
        for f in (pa.get("posture_findings") or []):
            all_cves.extend(_finding_cves(f))
    kev = fetch_kev()
    epss = fetch_epss(all_cves)
    epss_ok = bool(epss)
    kev_ok = bool(kev)

    # 2) Sonda le porte aperte per asset (una volta, solo le porte rilevanti).
    open_ports_by_ip = {}
    if probe:
        for pa in posture_assets:
            ip = pa.get("ip")
            wanted = set()
            for f in (pa.get("posture_findings") or []):
                wanted.update(_pkg_ports(f.get("package")))
            if ip and wanted:
                open_ports_by_ip[ip] = probe_open_ports(ip, wanted)

    out_assets = []
    summary = {"assets": 0, "kev_findings": 0, "exposed_findings": 0,
               "critical_risk": 0, "high_risk": 0, "total_findings": 0}

    for pa in posture_assets:
        ip = pa.get("ip") or ""
        ctx = assets_ctx.get(ip) or {}
        env = (ctx.get("environment") or "unknown").lower()
        internet = bool(ctx.get("internet_facing"))
        crit = ctx.get("criticality", 3)

        open_ports = open_ports_by_ip.get(ip, set())
        env_f = ENV_FACTOR.get(env, 1.0)
        crit_f = _crit_factor(crit)
        ctx_mult = env_f * crit_f * (1.3 if internet else 1.0)

        finding_rows = []
        raw = 0.0
        for f in (pa.get("posture_findings") or []):
            sev = (f.get("max_severity") or "UNKNOWN").upper()
            if sev not in SEV_WEIGHT:
                sev = "UNKNOWN"
            cves = _finding_cves(f)
            in_kev = any(c in kev for c in cves)
            epss_max = max((epss.get(c, 0.0) for c in cves), default=0.0)

            ports = _pkg_ports(f.get("package"))
            exposed = bool(ports) and bool(open_ports & set(ports))

            base = SEV_WEIGHT[sev]
            # Exploitability: KEV = forte spinta; EPSS scala 0..1.
            exploit = 1.0 + (1.5 if in_kev else 0.0) + epss_max
            exposure = 1.4 if exposed else 1.0
            fr = base * exploit * exposure
            raw += fr

            summary["total_findings"] += 1
            if in_kev:
                summary["kev_findings"] += 1
            if exposed:
                summary["exposed_findings"] += 1

            finding_rows.append({
                "package": f.get("package"), "version": f.get("version"),
                "ecosystem": f.get("ecosystem"), "category": f.get("category"),
                "max_severity": sev, "vuln_count": f.get("vuln_count") or 0,
                "cve_ids": cves[:25],
                "kev": in_kev, "epss": round(epss_max, 4),
                "exposed": exposed, "exposed_ports": sorted(open_ports & set(ports)),
                "finding_risk": round(fr, 3),
            })

        asset_raw = raw * ctx_mult
        # Normalizzazione con saturazione: molti finding non spingono all'infinito.
        risk_index = round(100 * (1 - math.exp(-asset_raw / 8.0)))
        finding_rows.sort(key=lambda r: -r["finding_risk"])

        summary["assets"] += 1
        if risk_index >= 75:
            summary["critical_risk"] += 1
        elif risk_index >= 45:
            summary["high_risk"] += 1

        out_assets.append({
            "ip": ip,
            "asset_id": ctx.get("id"),
            "os_guess": pa.get("os_guess"),
            "os_type": pa.get("os_type"),
            "posture_score": pa.get("score"),
            "risk_index": risk_index,
            "environment": env,
            "internet_facing": internet,
            "criticality": crit,
            "ctx_mult": round(ctx_mult, 3),
            "kev_count": sum(1 for r in finding_rows if r["kev"]),
            "exposed_count": sum(1 for r in finding_rows if r["exposed"]),
            "sev_critical": pa.get("sev_critical") or 0,
            "sev_high": pa.get("sev_high") or 0,
            "findings": finding_rows,
        })

    out_assets.sort(key=lambda a: -a["risk_index"])
    return {
        "run_id": (run or {}).get("id"),
        "created_at": (run or {}).get("created_at"),
        "assets": out_assets,
        "summary": summary,
        "meta": {"epss": epss_ok, "kev": kev_ok, "probe": probe,
                 "kev_total": len(kev)},
    }


def compute_trend(runs: list, current: dict = None, previous: dict = None) -> dict:
    """
    Serie storica per il grafico di trend + delta fra le due run piu' recenti.

    - runs:     output di db.fetch_posture_runs() (id, created_at, avg_score,
                total_vulns, assets_scanned), ordinato dal piu' recente.
    - current/previous: run complete (fetch_posture) per il delta finding-level.

    Ritorna { series[], delta{new, resolved, ...} }.
    """
    series = []
    for r in reversed(runs or []):        # cronologico per il grafico
        series.append({
            "run_id": r.get("id"),
            "created_at": r.get("created_at"),
            "avg_score": r.get("avg_score"),
            "total_vulns": r.get("total_vulns"),
            "assets_scanned": r.get("assets_scanned"),
        })

    def _finding_keys(run):
        keys = set()
        for pa in (run or {}).get("posture_assets", []) or []:
            ip = pa.get("ip")
            for f in (pa.get("posture_findings") or []):
                keys.add((ip, (f.get("package") or "").lower(), f.get("version")))
        return keys

    delta = {"new": 0, "resolved": 0, "unchanged": 0,
             "prev_run_id": None, "curr_run_id": None}
    if current:
        curr_keys = _finding_keys(current)
        prev_keys = _finding_keys(previous) if previous else set()
        delta["curr_run_id"] = (current or {}).get("id")
        delta["prev_run_id"] = (previous or {}).get("id") if previous else None
        if previous:
            delta["new"] = len(curr_keys - prev_keys)
            delta["resolved"] = len(prev_keys - curr_keys)
            delta["unchanged"] = len(curr_keys & prev_keys)
        else:
            delta["new"] = len(curr_keys)
    return {"series": series, "delta": delta}
