"""
findings.py
-----------
Ciclo di vita UNIFICATO dei finding (capability ASPM: dedup + workflow + SLA).

Tutti i finding — postura interna (SCA) e report di scanner esterni ingeriti
via ingest.py — confluiscono nella tabella 'findings' con:

1) DEDUP per fingerprint
   Identita' stabile calcolata su (asset, pacchetto/regola, CVE primaria o
   titolo, location). La sorgente NON fa parte della chiave: lo stesso
   difetto riportato da Trivy e Grype e' UN solo finding. Ricomparire in una
   run successiva aggiorna last_seen/times_seen invece di duplicare.

2) STATI del workflow
   open -> triaged -> accepted | fixed  (transizioni libere via API).
   Un finding 'fixed' che riappare viene RIAPERTO automaticamente
   (status=open, reopened+1).

3) SLA per severita'
   Scadenza di remediation calcolata alla prima osservazione:
   critical 7g, high 30g, medium 90g, low 180g (configurabile, sezione 'sla'
   di config.json). 'breached' se oltre scadenza e non fixed/accepted.

Il modulo e' puro (nessun accesso a DB): prepara le righe, db.py le persiste.
"""

import hashlib
from datetime import datetime, timedelta, timezone

STATUSES = ("open", "triaged", "accepted", "fixed")

# Giorni di SLA per severita' (default; override da config.json sezione 'sla').
DEFAULT_SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "UNKNOWN": 90}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _parse_ts(raw) -> datetime | None:
    """Parsa i timestamp ISO restituiti da PostgREST (vari formati di offset)."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fingerprint(f: dict) -> str:
    """
    Identita' stabile del finding, indipendente dalla sorgente e dalla
    versione installata (l'upgrade parziale non crea un finding nuovo).

    Con CVE nota l'identita' e' (asset, pacchetto, CVE primaria): la location
    e' esclusa perche' ogni tool la descrive a modo suo (Trivy 'ubuntu 22.04',
    Grype il path) e romperebbe il dedup cross-tool dello stesso difetto.
    Senza CVE (es. SAST, template) la location distingue i finding.
    """
    cves = sorted(f.get("cve_ids") or [])
    key = "|".join([
        (f.get("asset_ip") or "").strip().lower(),
        (f.get("package") or "").strip().lower(),
        (cves[0] if cves else (f.get("title") or "").strip().lower()),
        ("" if cves else (f.get("location") or "").strip().lower()),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def sla_days(severity: str, cfg_sla: dict | None = None) -> int:
    sev = (severity or "UNKNOWN").upper()
    table = {**DEFAULT_SLA_DAYS, **{k.upper(): int(v) for k, v in (cfg_sla or {}).items()}}
    return table.get(sev, table["UNKNOWN"])


def posture_findings(report: dict) -> list:
    """
    Converte il report di postura di UN asset (scan_asset_posture) nello schema
    normalizzato di ingest.py, cosi' da confluire nello stesso ciclo di vita.
    """
    ip = report.get("ip") or ""
    out = []
    for f in (report.get("findings") or []):
        pkg = f.get("package") or ""
        out.append({
            "source": "posture",
            "asset_ip": ip,
            "title": f"{pkg} {f.get('version') or ''} vulnerable "
                     f"({f.get('vuln_count') or 0} CVE)".strip(),
            "package": pkg,
            "version": f.get("version") or "",
            "ecosystem": f.get("ecosystem") or "",
            "location": f"pkg:{f.get('ecosystem') or 'os'}",
            "severity": (f.get("max_severity") or "UNKNOWN").upper(),
            "cve_ids": f.get("cve_ids") or [],
            "cwe_ids": [],
            "detail": f"Category: {f.get('category') or 'n/a'}",
        })
    return out


def merge_findings(normalized: list, existing_by_fp: dict,
                   cfg_sla: dict | None = None) -> tuple:
    """
    Fonde i finding normalizzati con quelli gia' presenti a DB.

    Ritorna (rows, stats):
      rows  -> righe pronte per l'upsert (on_conflict=fingerprint)
      stats -> {"new": n, "updated": n, "reopened": n}

    Regole:
      - nuovo fingerprint            -> status 'open', sla_due da severita'
      - fingerprint esistente        -> last_seen/now, times_seen+1; severita'
                                        alzata se il nuovo report e' peggiore
      - esistente con status 'fixed' -> RIAPERTO (open, reopened+1, nuova SLA)
    """
    now = _now()
    stats = {"new": 0, "updated": 0, "reopened": 0}
    merged: dict = {}   # fp -> row (dedup anche DENTRO lo stesso report)

    for f in normalized:
        fp = fingerprint(f)
        sev = (f.get("severity") or "UNKNOWN").upper()
        if fp in merged:
            # Stesso finding ripetuto nel report: tieni la severita' peggiore.
            row = merged[fp]
            if SEV_ORDER.index(sev) < SEV_ORDER.index(row["severity"]):
                row["severity"] = sev
            continue

        prev = existing_by_fp.get(fp)
        if prev is None:
            merged[fp] = {
                "fingerprint": fp,
                "source": f.get("source") or "",
                "asset_ip": f.get("asset_ip") or "",
                "title": f.get("title") or "",
                "package": f.get("package") or "",
                "version": f.get("version") or "",
                "ecosystem": f.get("ecosystem") or "",
                "location": f.get("location") or "",
                "severity": sev,
                "cve_ids": f.get("cve_ids") or [],
                "cwe_ids": f.get("cwe_ids") or [],
                "detail": f.get("detail") or "",
                "status": "open",
                "status_note": "",
                "status_changed_at": _iso(now),
                "first_seen": _iso(now),
                "last_seen": _iso(now),
                "times_seen": 1,
                "reopened": 0,
                "sla_due": _iso(now + timedelta(days=sla_days(sev, cfg_sla))),
            }
            stats["new"] += 1
            continue

        # Fingerprint gia' noto: aggiorna osservazione, preserva workflow.
        prev_sev = (prev.get("severity") or "UNKNOWN").upper()
        worst = sev if SEV_ORDER.index(sev) < SEV_ORDER.index(prev_sev) else prev_sev
        row = {
            "fingerprint": fp,
            "source": prev.get("source") or f.get("source") or "",
            "asset_ip": prev.get("asset_ip") or "",
            "title": f.get("title") or prev.get("title") or "",
            "package": prev.get("package") or "",
            "version": f.get("version") or prev.get("version") or "",
            "ecosystem": prev.get("ecosystem") or f.get("ecosystem") or "",
            "location": prev.get("location") or "",
            "severity": worst,
            "cve_ids": sorted(set((prev.get("cve_ids") or []) + (f.get("cve_ids") or []))),
            "cwe_ids": sorted(set((prev.get("cwe_ids") or []) + (f.get("cwe_ids") or []))),
            "detail": f.get("detail") or prev.get("detail") or "",
            "status": prev.get("status") or "open",
            "status_note": prev.get("status_note") or "",
            "status_changed_at": prev.get("status_changed_at") or _iso(now),
            "first_seen": prev.get("first_seen") or _iso(now),
            "last_seen": _iso(now),
            "times_seen": int(prev.get("times_seen") or 1) + 1,
            "reopened": int(prev.get("reopened") or 0),
            "sla_due": prev.get("sla_due") or _iso(now + timedelta(days=sla_days(worst, cfg_sla))),
        }
        # Sorgente diversa che conferma lo stesso difetto: traccia entrambe.
        new_src = f.get("source") or ""
        if new_src and new_src not in (row["source"] or "").split("+"):
            row["source"] = "+".join(filter(None, [row["source"], new_src]))
        if row["status"] == "fixed":
            row["status"] = "open"
            row["reopened"] += 1
            row["status_changed_at"] = _iso(now)
            row["status_note"] = "Reopened: reappeared in a new report"
            row["sla_due"] = _iso(now + timedelta(days=sla_days(worst, cfg_sla)))
            stats["reopened"] += 1
        else:
            stats["updated"] += 1
        merged[fp] = row

    return list(merged.values()), stats


def is_breached(row: dict, now: datetime | None = None) -> bool:
    """SLA violata: oltre scadenza e ancora aperta/triaged."""
    if (row.get("status") or "open") in ("fixed", "accepted"):
        return False
    due = _parse_ts(row.get("sla_due"))
    return bool(due and (now or _now()) > due)


def summarize(rows: list) -> dict:
    """Aggregati per la UI: conteggi per stato/severita' + violazioni SLA."""
    now = _now()
    by_status = {s: 0 for s in STATUSES}
    by_sev = {s: 0 for s in SEV_ORDER}
    sources: dict = {}
    breached = 0
    for r in rows:
        st = (r.get("status") or "open")
        by_status[st] = by_status.get(st, 0) + 1
        if st in ("open", "triaged"):
            sev = (r.get("severity") or "UNKNOWN").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        if is_breached(r, now):
            breached += 1
        for s in (r.get("source") or "").split("+"):
            if s:
                sources[s] = sources.get(s, 0) + 1
    return {"total": len(rows), "by_status": by_status, "by_severity": by_sev,
            "sla_breached": breached, "sources": sources}
