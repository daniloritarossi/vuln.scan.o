"""
db.py
-----
Persistenza dei risultati di scansione su Supabase locale (PostgREST).

Usa il client ufficiale supabase-py, che parla con il gateway in stile Supabase
esposto in ./supabase (http://localhost:8001/rest/v1).

Filosofia "best-effort": come il resto dell'app, se Supabase non e' raggiungibile
la scansione NON si interrompe. Gli errori di persistenza vengono loggati e
ignorati, cosi' l'app resta usabile anche senza DB.

Variabili d'ambiente (con default per il locale):
    SUPABASE_URL          default http://localhost:8001
    SUPABASE_SERVICE_KEY  default chiave service_role demo (vedi supabase/.env)
    SUPABASE_PERSIST      "0" per disabilitare del tutto la scrittura
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("vfa.db")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "http://localhost:8001")
# Chiave demo service_role (firmata con il JWT_SECRET demo). Solo per uso locale.
SUPABASE_SERVICE_KEY = os.environ.get(
    "SUPABASE_SERVICE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UtZGVtbyIsImlhdCI6MTY0MTc2OTIwMCwiZXhwIjoxNzk5NTM1NjAwfQ."
    "5z-pJI1qwZg1LE5yavGLqum65WOnnaaI5eZ3V00pLww",
)
PERSIST_ENABLED = os.environ.get("SUPABASE_PERSIST", "1") != "0"

# Client creato una sola volta (lazy).
_client = None
_init_failed = False


def _get_client():
    """Ritorna il client Supabase, creandolo al primo uso. None se non disponibile."""
    global _client, _init_failed
    if _client is not None or _init_failed:
        return _client
    if not PERSIST_ENABLED:
        return None
    try:
        from supabase import create_client
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    except Exception as exc:  # libreria assente o URL non valido
        logger.warning("Supabase non inizializzato (persistenza disattivata): %s", exc)
        _init_failed = True
        _client = None
    return _client


def persist_scan(description: str, target: dict, cve: dict,
                 advisory: Optional[dict] = None) -> Optional[int]:
    """
    Inserisce la riga 'scans' (target identificato + sintesi CVE + advisory AI).
    Ritorna l'id della scansione, oppure None se la persistenza fallisce.

    'advisory' (opzionale): {affected_version, affected_source}. Tenuto DISTINTO
    dai campi CVE.
    """
    client = _get_client()
    if client is None:
        return None
    advisory = advisory or {}
    row = {
        "description": description,
        "product": target.get("product"),
        "version": target.get("version"),
        "matched_alias": target.get("matched_alias"),
        "source": target.get("source"),
        "candidates": target.get("candidates") or [],
        "dependencies": target.get("dependencies") or [],
        "cve_count": cve.get("count"),
        "cve_ids": cve.get("ids") or [],
        "cve_summary": cve.get("summary"),
        "cve_error": cve.get("error"),
        "affected_version": advisory.get("affected_version"),
        "affected_source": advisory.get("affected_source"),
    }
    try:
        resp = client.table("scans").insert(row).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("persist_scan fallita: %s", exc)
        return None


def persist_result(scan_id: Optional[int], rd: dict) -> None:
    """
    Inserisce una riga 'scan_results' (esito per singolo asset).
    No-op se scan_id e' None o se la persistenza non e' disponibile.
    """
    client = _get_client()
    if client is None:
        return
    row = {
        "scan_id": scan_id,
        "ip": rd.get("ip"),
        "auth_required": rd.get("auth_required"),
        "method": rd.get("method"),
        "product_found": rd.get("product_found"),
        "detected_version": rd.get("detected_version"),
        "raw_evidence": rd.get("raw_evidence"),
        "vuln_match": rd.get("vuln_match"),
        "cve_count": rd.get("cve_count"),
        "cve_ids": rd.get("cve_ids") or [],
        "cve_error": rd.get("cve_error"),
        "affected_version": rd.get("affected_version"),
        "match_basis": rd.get("match_basis"),
        "os_type": rd.get("os_type"),
        "os_major_version": rd.get("os_major_version"),
    }
    try:
        client.table("scan_results").insert(row).execute()
    except Exception as exc:
        logger.warning("persist_result fallita (ip=%s): %s", rd.get("ip"), exc)


def fetch_audit(limit: int = 200):
    """
    Legge lo storico scansioni con i risultati per-asset annidati (embedding
    PostgREST sulla FK scan_results.scan_id -> scans.id), piu' recenti prima.

    Ritorna:
      - lista di scans (ognuna con chiave 'scan_results')  se il DB risponde
      - None                                               se Supabase non e' raggiungibile
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (
            client.table("scans")
            .select("*, scan_results(*)")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_audit fallita: %s", exc)
        return None


def update_scan_summary(scan_id: Optional[int], cve: dict) -> None:
    """Aggiorna la riga 'scans' con la sintesi CVE finale (conteggio + LLM)."""
    client = _get_client()
    if client is None or scan_id is None:
        return
    try:
        client.table("scans").update({
            "version": cve.get("version"),
            "cve_count": cve.get("count"),
            "cve_ids": cve.get("ids") or [],
            "cve_summary": cve.get("summary"),
            "cve_error": cve.get("error"),
        }).eq("id", scan_id).execute()
    except Exception as exc:
        logger.warning("update_scan_summary fallita: %s", exc)


# ---------------------------------------------------------------------------
# FULL POSTURE (SCA)
# ---------------------------------------------------------------------------

def create_posture_run() -> Optional[int]:
    """Crea una riga posture_runs (vuota) e ritorna l'id. None se DB assente."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("posture_runs").insert({"assets_scanned": 0}).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("create_posture_run fallita: %s", exc)
        return None


def persist_posture_asset(run_id: Optional[int], report: dict) -> None:
    """Inserisce un asset di postura + i suoi finding per-pacchetto."""
    client = _get_client()
    if client is None or run_id is None:
        return
    try:
        row = {k: report.get(k) for k in (
            "ip", "os_guess", "method", "total_packages", "vulnerable_packages",
            "total_vulns", "score", "sev_critical", "sev_high", "sev_medium",
            "sev_low", "sev_unknown", "os_type", "os_major_version")}
        row["run_id"] = run_id
        resp = client.table("posture_assets").insert(row).execute()
        asset_id = resp.data[0]["id"] if resp.data else None
        findings = report.get("findings") or []
        if asset_id and findings:
            client.table("posture_findings").insert([{
                "asset_id": asset_id,
                "package": f["package"], "version": f["version"],
                "ecosystem": f["ecosystem"], "category": f["category"],
                "vuln_count": f["vuln_count"], "max_severity": f["max_severity"],
                "cve_ids": f["cve_ids"] or [],
            } for f in findings]).execute()
    except Exception as exc:
        logger.warning("persist_posture_asset fallita (ip=%s): %s", report.get("ip"), exc)


def finalize_posture_run(run_id: Optional[int], totals: dict) -> None:
    """Aggiorna gli aggregati della run a fine scansione."""
    client = _get_client()
    if client is None or run_id is None:
        return
    try:
        client.table("posture_runs").update({
            "assets_scanned": totals.get("assets_scanned"),
            "total_packages": totals.get("total_packages"),
            "total_vulnerable": totals.get("total_vulnerable"),
            "total_vulns": totals.get("total_vulns"),
            "avg_score": totals.get("avg_score"),
        }).eq("id", run_id).execute()
    except Exception as exc:
        logger.warning("finalize_posture_run fallita: %s", exc)


def fetch_posture(run_id: Optional[int] = None):
    """
    Ritorna una run di postura con asset + findings annidati.
    run_id None => ultima run. None se DB non raggiungibile, {} se nessuna run.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        q = client.table("posture_runs").select(
            "*, posture_assets(*, posture_findings(*))")
        if run_id is not None:
            q = q.eq("id", run_id)
        else:
            q = q.order("created_at", desc=True).limit(1)
        resp = q.execute()
        return (resp.data[0] if resp.data else {})
    except Exception as exc:
        logger.warning("fetch_posture fallita: %s", exc)
        return None


def fetch_posture_runs(limit: int = 30):
    """Elenco sintetico delle run (per il selettore storico)."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("posture_runs")
                .select("id, created_at, assets_scanned, total_vulns, avg_score")
                .order("created_at", desc=True).limit(limit).execute())
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_posture_runs fallita: %s", exc)
        return None
