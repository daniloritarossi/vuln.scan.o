"""
app.py
------
Server FastAPI del Vulnerability Feed Aggregator.

Endpoint:
  GET  /                -> pagina web (form + tabella risultati).
  POST /api/identify    -> dato il testo della vulnerabilita', ritorna il
                           "Software Target" identificato (OSINT/locale).
  GET  /api/scan        -> esegue la scansione dell'inventario e trasmette i
                           risultati in tempo reale via SSE (Server-Sent Events),
                           un asset alla volta.
  GET  /api/assets      -> elenco asset dell'inventario (senza password).

Avvio:
    uvicorn app:app --reload --port 8000
"""

import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from assets import (load_assets, get_asset, add_asset, update_asset,
                    set_asset_enabled, update_asset_fields, delete_asset,
                    Asset, AssetStoreError)
from crypto import encrypt_password, is_encrypted, decrypt_password
from config import load_config, save_config
from osint import identify_product, extract_local
from scanner import scan_asset, _get_simulate_auth as _simulate_auth, version_affected
from cve import (query_osv, summarize_cves, query_osv_ids, extract_affected_version,
                 query_osv_ecosystem, os_ecosystem, generate_remediation,
                 generate_triage_report)
from db import (persist_scan, persist_result, update_scan_summary, fetch_audit,
                create_posture_run, persist_posture_asset, finalize_posture_run,
                fetch_posture, fetch_posture_runs, fetch_posture_sbom,
                fetch_findings, fetch_findings_by_fps, upsert_findings,
                set_finding_status, close_stale_posture_findings)
from posture import scan_asset_posture
from sbom_export import sbom_rows, build_cyclonedx, build_spdx
from risk import assess_run_risk, compute_trend
from ingest import ingest_report, IngestError, SUPPORTED_TOOLS
from findings import (fingerprint, merge_findings, posture_findings,
                      summarize, is_breached, STATUSES)
from ticketing import create_ticket, TicketError
from localscan import run_gitleaks, run_trivy_image, LocalScanError
from compliance import derive_compliance, compliance_summary
from db import fetch_finding, set_finding_ticket

BASE_DIR = Path(__file__).parent
ASSETS_FILE = BASE_DIR / "assets.txt"

def _git_version() -> str:
    """Versione app dal tag git piu' recente (es. 'v1.0.1-alfa', o
    'v1.0.1-alfa-3-gabc1234' se HEAD e' oltre il tag). 'dev' se git assente."""
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            cwd=BASE_DIR, capture_output=True, text=True, timeout=3,
        )
        return out.stdout.strip() or "dev"
    except Exception:
        return "dev"


APP_VERSION = _git_version()

app = FastAPI(title="Vulnerability Feed Aggregator", version=APP_VERSION)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["app_version"] = APP_VERSION
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Serve la singola pagina dell'applicazione."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "simulate_auth": _simulate_auth()},
    )


@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request):
    """Pagina di gestione (CRUD) dell'inventario asset."""
    return templates.TemplateResponse("assets.html", {"request": request})


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    """Pagina AUDIT: storico dei risultati di scansione salvati su Supabase."""
    return templates.TemplateResponse("audit.html", {"request": request})


@app.get("/sbom", response_class=HTMLResponse)
def sbom_page(request: Request):
    """Pagina SBOM: Software Bill of Materials per asset dell'inventario."""
    return templates.TemplateResponse("sbom.html", {"request": request})


@app.get("/api/sbom")
def api_sbom(run_id: int | None = None):
    """
    Inventario software COMPLETO dell'ultima run di postura (tutti i componenti,
    non solo i vulnerabili). Ogni riga porta gli identificatori SBOM
    (purl, cpe, licenza, fornitore, sha256, relazioni).
    """
    run = fetch_posture_sbom(run_id)
    if not run:
        return {"rows": []}
    return {"rows": sbom_rows(run)}


@app.get("/api/sbom/export")
def api_sbom_export(format: str = "cyclonedx", run_id: int | None = None):
    """
    Esporta la SBOM in formato standard.
    format: 'cyclonedx' (CycloneDX 1.5) | 'spdx' (SPDX 2.3).
    Download come file JSON.
    """
    run = fetch_posture_sbom(run_id)
    fmt = (format or "cyclonedx").lower()
    if fmt == "spdx":
        doc = build_spdx(run or {})
        fname = "sbom.spdx.json"
    elif fmt == "cyclonedx":
        doc = build_cyclonedx(run or {})
        fname = "sbom.cdx.json"
    else:
        return JSONResponse({"error": f"formato non supportato: {format}"}, status_code=400)
    return JSONResponse(doc, headers={
        "Content-Disposition": f'attachment; filename="{fname}"',
    })


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request):
    """Pagina FINDINGS: ciclo di vita unificato (dedup + workflow + SLA)."""
    return templates.TemplateResponse("findings.html", {"request": request})


@app.get("/api/findings")
def api_findings(status: str | None = None, severity: str | None = None,
                 source: str | None = None, q: str | None = None):
    """
    Elenco finding unificati + aggregati per la UI.
    Filtri opzionali: status, severity, source (substring), q (testo libero).
    503 se il DB non e' raggiungibile.
    """
    rows = fetch_findings()
    if rows is None:
        return JSONResponse({"error": "Supabase unreachable", "findings": []},
                            status_code=503)
    summary = summarize(rows)   # aggregati sull'intero dataset, non sul filtro
    if status:
        rows = [r for r in rows if (r.get("status") or "open") == status]
    if severity:
        rows = [r for r in rows if (r.get("severity") or "").upper() == severity.upper()]
    if source:
        rows = [r for r in rows if source.lower() in (r.get("source") or "").lower()]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in json.dumps(r, default=str).lower()]
    for r in rows:
        r["sla_breached"] = is_breached(r)
        r["compliance"] = derive_compliance(r)
    summary["compliance"] = compliance_summary(rows)
    return {"findings": rows, "summary": summary}


@app.post("/api/findings/import")
async def api_findings_import(request: Request, tool: str = "auto",
                              asset_ip: str = ""):
    """
    Ingestione di un report di scanner ESTERNO (capability ASPM: aggregazione).
    Body: JSON grezzo del report (Trivy/Grype/Semgrep JSON, Nuclei JSON/JSONL).
    'tool' forza il parser ('auto' = riconoscimento dal contenuto).
    'asset_ip' (opzionale) attribuisce i finding a un asset dell'inventario.
    I finding confluiscono nel ciclo di vita unificato: dedup per fingerprint,
    riapertura automatica dei 'fixed' riapparsi, SLA per severita'.
    """
    raw = await request.body()
    try:
        detected, normalized = ingest_report(raw, tool=tool, asset_ip=asset_ip)
    except IngestError as exc:
        return JSONResponse({"error": str(exc),
                             "supported": list(SUPPORTED_TOOLS)}, status_code=400)
    if not normalized:
        return {"ok": True, "tool": detected, "parsed": 0,
                "new": 0, "updated": 0, "reopened": 0}
    fps = [fingerprint(f) for f in normalized]
    existing = fetch_findings_by_fps(list(set(fps)))
    if existing is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    rows, stats = merge_findings(normalized, {r["fingerprint"]: r for r in existing},
                                 cfg_sla=load_config().get("sla"))
    if not upsert_findings(rows):
        return JSONResponse({"error": "Persistenza fallita"}, status_code=503)
    return {"ok": True, "tool": detected, "parsed": len(normalized), **stats}


@app.patch("/api/findings/{finding_id}/status")
async def api_findings_status(finding_id: int, request: Request):
    """
    Transizione di stato del workflow. Body: {status, note?}.
    Stati validi: open | triaged | accepted | fixed.
    """
    body = await request.json()
    status = (body.get("status") or "").strip().lower()
    if status not in STATUSES:
        return JSONResponse(
            {"error": f"Stato non valido: {status}", "valid": list(STATUSES)},
            status_code=400)
    if not set_finding_status(finding_id, status, (body.get("note") or "").strip()):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    return {"ok": True, "status": status}


@app.post("/api/findings/{finding_id}/ticket")
def api_findings_ticket(finding_id: int):
    """
    Crea un ticket di remediation (GitHub Issue / Jira) per il finding e ne
    salva il riferimento. Provider e credenziali in config.json ('ticketing').
    """
    f = fetch_finding(finding_id)
    if f is None:
        return JSONResponse({"error": "Finding non trovato o DB non raggiungibile"},
                            status_code=404)
    if f.get("ticket_url"):
        return {"ok": True, "already": True,
                "ref": f.get("ticket_ref"), "url": f.get("ticket_url")}
    try:
        ticket = create_ticket(load_config().get("ticketing") or {}, f)
    except TicketError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    set_finding_ticket(finding_id, ticket["ref"], ticket["url"])
    return {"ok": True, "already": False, **ticket}


@app.post("/api/findings/scan-local")
async def api_findings_scan_local(request: Request):
    """
    Esegue uno scanner LOCALE (binario opzionale sul server) e ne ingerisce
    il report nel ciclo di vita unificato.
    Body: {"type": "secrets" | "image", "target": "<path|image-ref>",
           "asset_ip": "<opzionale>"}.
      - secrets -> gitleaks sulla directory 'target'
      - image   -> trivy (vuln + secret) sull'immagine container 'target'
    """
    body = await request.json()
    scan_type = (body.get("type") or "").strip().lower()
    target = (body.get("target") or "").strip()
    asset_ip = (body.get("asset_ip") or "").strip()
    if not target:
        return JSONResponse({"error": "Missing target"}, status_code=400)
    try:
        if scan_type == "secrets":
            raw, tool = run_gitleaks(target), "gitleaks"
        elif scan_type == "image":
            raw, tool = run_trivy_image(target), "trivy"
        else:
            return JSONResponse(
                {"error": f"Tipo non valido: {scan_type} (secrets|image)"},
                status_code=400)
    except LocalScanError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    try:
        _, normalized = ingest_report(raw, tool=tool, asset_ip=asset_ip or target)
    except IngestError as exc:
        return JSONResponse({"error": f"Parsing report {tool}: {exc}"}, status_code=502)
    if not normalized:
        return {"ok": True, "tool": tool, "parsed": 0,
                "new": 0, "updated": 0, "reopened": 0}
    fps = [fingerprint(f) for f in normalized]
    existing = fetch_findings_by_fps(list(set(fps)))
    if existing is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    rows, stats = merge_findings(normalized, {r["fingerprint"]: r for r in existing},
                                 cfg_sla=load_config().get("sla"))
    if not upsert_findings(rows):
        return JSONResponse({"error": "Persistenza fallita"}, status_code=503)
    return {"ok": True, "tool": tool, "parsed": len(normalized), **stats}


def _sync_posture_findings(report: dict) -> None:
    """
    Best-effort: versa i finding della postura di UN asset nel ciclo di vita
    unificato (dedup/riapertura) e auto-chiude quelli non piu' osservati.
    Non solleva mai: la scansione di postura non dipende da questo passo.
    """
    try:
        normalized = posture_findings(report)
        fps = [fingerprint(f) for f in normalized]
        existing = fetch_findings_by_fps(list(set(fps)))
        if existing is None:
            return
        rows, _ = merge_findings(normalized, {r["fingerprint"]: r for r in existing},
                                 cfg_sla=load_config().get("sla"))
        if rows:
            upsert_findings(rows)
        close_stale_posture_findings(report.get("ip") or "", fps)
    except Exception:
        pass


@app.get("/intel", response_class=HTMLResponse)
def intel_page(request: Request):
    """Pagina INTEL: dashboard Full Posture (ASPM-style)."""
    return templates.TemplateResponse("intel.html", {"request": request})


@app.get("/risk", response_class=HTMLResponse)
def risk_page(request: Request):
    """Pagina RISK: prioritizzazione contestuale (EPSS/KEV + contesto + trend)."""
    return templates.TemplateResponse("risk.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    """Pagina di configurazione dell'applicativo."""
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/api/settings")
def api_settings_get():
    """Legge la configurazione corrente."""
    cfg = load_config()
    # Non esporre mai la chiave API in chiaro: maschera se presente.
    masked = json.loads(json.dumps(cfg))
    if masked.get("ai", {}).get("claude_api_key"):
        masked["ai"]["claude_api_key"] = "••••••••"
    if masked.get("search_engine", {}).get("serper_api_key"):
        masked["search_engine"]["serper_api_key"] = "••••••••"
    if masked.get("ticketing", {}).get("github_token"):
        masked["ticketing"]["github_token"] = "••••••••"
    if masked.get("ticketing", {}).get("jira_api_token"):
        masked["ticketing"]["jira_api_token"] = "••••••••"
    return masked


@app.post("/api/settings")
async def api_settings_post(request: Request):
    """Aggiorna la configurazione. Merge parziale per sezione."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    cfg = load_config()

    # Aggiorna solo le sezioni/chiavi ricevute; non sovrascrivere le chiavi
    # API se il client invia il placeholder "••••••••".
    for section, values in body.items():
        if section not in cfg:
            continue
        if not isinstance(values, dict):
            continue
        for key, val in values.items():
            if key not in cfg[section]:
                continue
            # Preserva il valore originale se il frontend invia placeholder.
            if isinstance(val, str) and "••••" in val:
                continue
            cfg[section][key] = val

    save_config(cfg)
    return {"ok": True}


@app.get("/api/ollama/models")
def api_ollama_models():
    """Lista modelli disponibili su Ollama (GET /api/tags). [] se offline."""
    import requests as _req
    from urllib.parse import urlparse
    cfg = load_config()["ai"]
    base = urlparse(cfg.get("ollama_url", "http://localhost:11434/api/generate"))
    tags_url = f"{base.scheme}://{base.netloc}/api/tags"
    try:
        r = _req.get(tags_url, timeout=4)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        return {"models": sorted(models)}
    except Exception:
        return {"models": []}


@app.get("/api/posture/scan")
def api_posture_scan(ips: str | None = None):
    """
    Avvio MANUALE della Full Posture: per ogni asset raccoglie l'inventario
    pacchetti e lo valuta con OSV. Streaming SSE: 'run', 'asset'*, 'done'.
    Persistenza best-effort su Supabase (run -> asset -> findings).

    'ips' (opzionale): lista IP/host separati da virgola -> scansiona solo quelli.
    Assente/vuoto => tutti gli asset dell'inventario.
    """
    selected = {s.strip() for s in (ips or "").split(",") if s.strip()}

    def stream():
        try:
            assets = load_assets(ASSETS_FILE)
        except AssetStoreError as exc:
            yield _sse("error", {"message": str(exc)})
            return
        # Esclude gli asset disabilitati in inventario dalla scansione di postura.
        assets = [a for a in assets if a.enabled]
        if selected:
            assets = [a for a in assets if a.ip in selected]
        if not assets:
            yield _sse("error", {"message": "No asset selected."})
            return
        run_id = create_posture_run()
        yield _sse("run", {"run_id": run_id, "total_assets": len(assets)})

        n = pkgs = vuln = vulns = score_sum = 0
        for asset in assets:
            report = scan_asset_posture(asset)
            report["os_type"] = asset.os_type or None
            report["os_major_version"] = asset.os_major_version or None
            persist_posture_asset(run_id, report)
            # Ciclo di vita unificato: dedup + riaperture + auto-fix (best-effort).
            _sync_posture_findings(report)
            n += 1
            pkgs += report["total_packages"]
            vuln += report["vulnerable_packages"]
            vulns += report["total_vulns"]
            score_sum += report["score"]
            yield _sse("asset", report)

        avg = round(score_sum / n) if n else 100
        totals = {"assets_scanned": n, "total_packages": pkgs,
                  "total_vulnerable": vuln, "total_vulns": vulns, "avg_score": avg}
        finalize_posture_run(run_id, totals)
        yield _sse("done", {"run_id": run_id, **totals})

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/posture/cve")
def api_posture_cve(package: str, ecosystem: str | None = None, version: str | None = None):
    """Lista COMPLETA di id CVE per (pacchetto, ecosistema, versione) — 'show more' posture."""
    return query_osv_ecosystem(package, ecosystem, version)


@app.get("/api/posture")
def api_posture(run_id: int | None = None):
    """Ritorna una run di postura (ultima se run_id assente) con asset+findings."""
    data = fetch_posture(run_id)
    if data is None:
        return JSONResponse({"error": "Supabase unreachable", "run": {}}, status_code=503)
    return {"run": data}


@app.get("/api/posture/runs")
def api_posture_runs():
    """Elenco storico delle run di postura."""
    data = fetch_posture_runs()
    if data is None:
        return JSONResponse({"error": "Supabase unreachable", "runs": []}, status_code=503)
    return {"runs": data}


@app.get("/api/risk")
def api_risk(run_id: int | None = None, probe: bool = True):
    """
    Rischio CONTESTUALE di una run di postura (ultima se run_id assente).

    Combina: severita' della postura + exploitability (EPSS + CISA KEV) +
    reachability (porte di servizio aperte) + contesto business dell'asset
    (ambiente, internet-facing, criticita' dall'inventario).

    'probe=false' salta la sonda TCP delle porte (piu' veloce, no reachability).
    """
    run = fetch_posture(run_id)
    if run is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    if not run:
        return {"risk": {"assets": [], "summary": {}, "meta": {}}}
    try:
        assets = load_assets(ASSETS_FILE)
        ctx = {a.ip: {"id": a.id, "environment": a.environment,
                      "internet_facing": a.internet_facing,
                      "criticality": a.criticality} for a in assets}
    except AssetStoreError:
        ctx = {}
    return {"risk": assess_run_risk(run, ctx, probe=probe)}


@app.get("/api/risk/trend")
def api_risk_trend():
    """
    Serie storica del rischio (score/CVE per run) + delta finding-level fra le
    due run piu' recenti (nuove vs risolte). 503 se il DB non risponde.
    """
    runs = fetch_posture_runs()
    if runs is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    current = previous = None
    if len(runs) >= 1:
        current = fetch_posture(runs[0].get("id"))
    if len(runs) >= 2:
        previous = fetch_posture(runs[1].get("id"))
    return {"trend": compute_trend(runs, current, previous)}


@app.patch("/api/assets/{index}/context")
async def api_assets_context(index: int, request: Request):
    """
    Aggiorna il contesto business di un asset (per la prioritizzazione del rischio).
    Body (tutti opzionali): {environment, internet_facing, criticality}.
    """
    body = await request.json()
    row = {}
    if "environment" in body:
        env = (body.get("environment") or "unknown").strip().lower()
        if env not in ("production", "staging", "dev", "unknown"):
            env = "unknown"
        row["environment"] = env
    if "internet_facing" in body:
        row["internet_facing"] = bool(body.get("internet_facing"))
    if "criticality" in body:
        try:
            c = int(body.get("criticality"))
        except (TypeError, ValueError):
            c = 3
        row["criticality"] = max(1, min(5, c))
    if not row:
        return JSONResponse({"error": "No context fields"}, status_code=400)
    if not update_asset_fields(index, row):
        return JSONResponse({"error": "Invalid index or DB unreachable"}, status_code=404)
    return {"ok": True, **row}


@app.get("/api/audit")
def api_audit():
    """
    Storico scansioni (scans + scan_results annidati) letto da Supabase.
    503 se il DB non e' raggiungibile (la UI mostra un messaggio dedicato).
    """
    data = fetch_audit()
    if data is None:
        return JSONResponse(
            {"error": "Supabase unreachable", "scans": []},
            status_code=503,
        )
    return {"scans": data}


def _normalize_host(raw: str) -> str:
    """Estrae l'hostname/IP puro da una stringa asset (toglie schema, path, porta)."""
    raw = (raw or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0]              # via eventuale path
    # via porta (solo host:port, non IPv6 con piu' ':').
    if raw.count(":") == 1:
        raw = raw.split(":")[0]
    return raw.strip()


def _reachable(host: str, ports=(80, 443, 22, 8080), timeout: float = 1.5) -> bool:
    """True se una connessione TCP riesce su almeno una delle porte note.

    Le porte sono sondate in parallelo: il tempo totale resta ~`timeout`
    anche per host che filtrano/droppano i pacchetti, invece di sommare il
    timeout di ogni porta in sequenza.
    """
    def _probe(port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        futures = [pool.submit(_probe, p) for p in ports]
        for fut in as_completed(futures):
            if fut.result():
                for f in futures:
                    f.cancel()
                return True
    return False


def _check_ssh(asset: Asset, timeout: float = 3.0) -> bool:
    """Tenta login SSH reale con le credenziali dell'asset. True se ha successo."""
    import paramiko
    try:
        password = decrypt_password(asset.password)
    except RuntimeError:
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            asset.ip,
            username=asset.username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return True
    except Exception:
        return False
    finally:
        client.close()


@app.get("/api/asset/health")
def api_asset_health(host: str, index: int | None = None):
    """
    Raggiungibilita' TCP + (se index fornito e asset ha credenziali) login SSH.
    Risposta: {reachable, ssh_ok}  — ssh_ok=null se nessuna credenziale.
    """
    h = _normalize_host(host)
    if not h:
        return {"host": host, "reachable": False, "ssh_ok": None}

    reachable = _reachable(h)
    ssh_ok = None

    if reachable and index is not None:
        try:
            asset = get_asset(index, ASSETS_FILE)  # 'index' = id riga Supabase
        except AssetStoreError:
            asset = None
        if asset and asset.auth_required:
            if is_encrypted(asset.password):
                ssh_ok = _check_ssh(asset)
            else:
                ssh_ok = False  # password in chiaro: login rifiutato

    return {"host": host, "reachable": reachable, "ssh_ok": ssh_ok}


@app.get("/api/cve")
def api_cve(product: str, version: str | None = None,
            os_type: str | None = None, os_major_version: str | None = None):
    """
    Lista COMPLETA di id CVE (OSV) per (prodotto, versione).
    Usato dal 'show more' della pagina Audit per espandere oltre i 10 salvati.

    L'ecosistema OSV (richiesto dall'API) e' dedotto dal SO se fornito,
    altrimenti default Debian.
    """
    eco = os_ecosystem(os_type, os_major_version) or "Debian"
    return query_osv_ids(product, version, ecosystem=eco)


@app.get("/api/assets")
def api_assets():
    """Ritorna l'inventario interpretato (senza password)."""
    try:
        assets = load_assets(ASSETS_FILE)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    return {"assets": [a.to_dict() for a in assets]}


def _asset_full(a: Asset) -> dict:
    """Serializzazione per la pagina CRUD. La password non viene mai esposta.

    'index' = id riga Supabase (nome mantenuto per compatibilita' frontend).
    """
    return {
        "index": a.id,
        "ip": a.ip,
        "username": a.username,
        "has_password": bool(a.password),
        "password_encrypted": is_encrypted(a.password) if a.password else True,
        "auth_required": a.auth_required,
        "os_type": a.os_type,
        "os_major_version": a.os_major_version,
        "enabled": a.enabled,
    }


@app.get("/api/assets/all")
def api_assets_all():
    """Inventario completo (password inclusa) per la gestione CRUD."""
    try:
        assets = load_assets(ASSETS_FILE)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    return {"assets": [_asset_full(a) for a in assets]}


@app.post("/api/assets")
async def api_assets_create(request: Request):
    """Aggiunge un asset all'inventario. Body: {ip, username, password}."""
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    os_type = (body.get("os_type") or "").strip().lower()
    if os_type not in ("linux", "windows"):
        return JSONResponse({"error": "OS type required (linux or windows)"}, status_code=400)
    plain_pw = (body.get("password") or "").strip()
    try:
        stored_pw = encrypt_password(plain_pw) if plain_pw else ""
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    new_id = add_asset(Asset(
        ip=ip,
        username=(body.get("username") or "").strip(),
        password=stored_pw,
        os_type=os_type,
        os_major_version=(body.get("os_major_version") or "").strip(),
        enabled=bool(body.get("enabled", True)),
    ))
    if new_id is None:
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    return {"ok": True, "index": new_id}


@app.put("/api/assets/{index}")
async def api_assets_update(index: int, request: Request):
    """Aggiorna l'asset indicato (index = id Supabase). Body: {ip, username, password}."""
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    os_type = (body.get("os_type") or "").strip().lower()
    if os_type not in ("linux", "windows"):
        return JSONResponse({"error": "OS type required (linux or windows)"}, status_code=400)
    try:
        current = get_asset(index, ASSETS_FILE)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    if current is None:
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    plain_pw = (body.get("password") or "").strip()
    if plain_pw:
        try:
            stored_pw = encrypt_password(plain_pw)
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)
    else:
        stored_pw = current.password  # mantiene password cifrata esistente
    # 'enabled' opzionale: se assente, preserva lo stato corrente.
    enabled = body.get("enabled")
    enabled = current.enabled if enabled is None else bool(enabled)
    ok = update_asset(index, Asset(
        ip=ip,
        username=(body.get("username") or "").strip(),
        password=stored_pw,
        os_type=os_type,
        os_major_version=(body.get("os_major_version") or "").strip(),
        enabled=enabled,
        # Preserva il contesto business: non fa parte del form CRUD e verrebbe
        # altrimenti resettato ai default a ogni salvataggio dell'asset.
        environment=current.environment,
        internet_facing=current.internet_facing,
        criticality=current.criticality,
    ))
    if not ok:
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    return {"ok": True}


@app.patch("/api/assets/{index}/enabled")
async def api_assets_toggle(index: int, request: Request):
    """Abilita/disabilita un asset per le scansioni. Body: {enabled: bool}."""
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    if not set_asset_enabled(index, enabled):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    return {"ok": True, "enabled": enabled}


@app.delete("/api/assets/{index}")
def api_assets_delete(index: int):
    """Elimina l'asset indicato (index = id Supabase)."""
    if not delete_asset(index):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    return {"ok": True}


@app.post("/api/identify")
async def api_identify(request: Request):
    """
    Identifica il software impattato dalla descrizione testuale.
    Body JSON: {"description": "...", "use_osint": true|false}
    """
    body = await request.json()
    description = (body.get("description") or "").strip()
    use_osint = bool(body.get("use_osint", True))
    if not description:
        return JSONResponse({"error": "Missing description"}, status_code=400)

    info = identify_product(description, use_osint=use_osint)
    return {"description": description, "target": info.to_dict()}


@app.get("/api/scan")
def api_scan(description: str, use_osint: bool = True, lang: str = "en",
             deep: bool = False):
    """
    Esegue la scansione e trasmette i risultati in streaming (SSE).
    Ogni messaggio 'data:' e' un JSON con l'esito di un singolo asset.
    Eventi finali: 'target' (prodotto identificato) e 'done'.

    'lang' (default 'en') seleziona la lingua della sintesi CVE generata dall'LLM.
    """
    def event_stream():
        try:
            yield from _event_stream_inner()
        except Exception as exc:
            yield _sse("error", {"message": f"Internal error: {exc}"})

    def _event_stream_inner():
        # 1. Identificazione prodotto.
        # Punto 1: se il dizionario locale non trova nulla, l'LLM sarà invocato.
        _local_peek = extract_local(description)
        if not _local_peek.product and use_osint:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "extract"})
        target = identify_product(description, use_osint=use_osint)
        yield _sse("target", target.to_dict())

        if not target.product:
            yield _sse("done", {"scanned": 0, "note": "No product identified."})
            return

        # 2. Caricamento inventario.
        try:
            assets = load_assets(ASSETS_FILE)
        except AssetStoreError as exc:
            yield _sse("error", {"message": str(exc)})
            return
        # Esclude gli asset disabilitati in inventario dalla scansione.
        assets = [a for a in assets if a.enabled]

        # 2b. ADVISORY AI: se il prodotto e' noto ma l'input NON contiene una
        #     versione (vulnerabilita' generica senza CVE), chiedo all'LLM di
        #     dedurre il RANGE di versione affetto, da confrontare con quella
        #     installata su ciascun asset. Best-effort ('' se Ollama offline).
        if not target.version:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "advisory"})
            yield ": keepalive\n\n"
            advisory_expr = extract_affected_version(target.product, description)
            affected_source = "ai" if advisory_expr else None
        else:
            advisory_expr = ""              # versione gia' nota dall'input
            affected_source = "input"
        if advisory_expr:
            yield _sse("advisory", {
                "product": target.product,
                "affected_version": advisory_expr,
                "source": "ai",
            })

        # 2c. Apertura della scansione su Supabase (best-effort: None se DB assente).
        scan_id = persist_scan(
            description, target.to_dict(), {},
            advisory={"affected_version": advisory_expr or None,
                      "affected_source": affected_source},
        )

        # 3. Scansione asset per asset (risultati in tempo reale), con
        #    arricchimento CVE (OSV) sulla versione realmente rilevata.
        ai_remediation = bool(load_config()["ai"].get("ai_remediation", False))
        all_results: list[dict] = []
        summary_version = None
        summary_eco = None
        for asset in assets:
            result = scan_asset(asset, target, deep=deep)
            rd = result.to_dict()
            rd["affected_version"] = None
            rd["match_basis"] = "none"
            # Ecosistema OSV dedotto dal SO dell'asset (OSV richiede sempre
            # package.ecosystem; senza, la query e' rifiutata con 400).
            eco = os_ecosystem(asset.os_type, asset.os_major_version)
            # La query OSV e' a livello prodotto+ecosistema (la versione upstream
            # non e' usata: gli ecosistemi distro usano stringhe native). Percio'
            # basta che il prodotto sia PRESENTE: cosi' la colonna CVE si popola
            # anche per asset senza versione rilevata (es. auth simulato).
            if rd["product_found"]:
                # Fallback Debian se l'ecosistema non e' deducibile: mantiene la
                # colonna CVE per-asset coerente col conteggio di sintesi (che usa
                # lo stesso fallback), evitando header 304 e righe vuote.
                asset_eco = eco or "Debian"
                info = query_osv(target.product, rd["detected_version"], ecosystem=asset_eco)
                rd["cve_count"] = info["count"]
                rd["cve_ids"] = info["ids"]
                rd["cve_error"] = info["error"]
                if summary_version is None and rd["detected_version"]:
                    summary_version = rd["detected_version"]
                if summary_eco is None:
                    summary_eco = asset_eco
                # Verdetto advisory AI (vulnerabilita' senza CVE): sovrascrive
                # vuln_match confrontando la versione installata col range affetto.
                if advisory_expr:
                    imp = version_affected(rd["detected_version"], advisory_expr)
                    rd["vuln_match"] = ("VULNERABILE" if imp is True
                                        else "NON VULNERABILE" if imp is False
                                        else "INCERTO")
                    rd["match_basis"] = "ai-advisory"
                    rd["affected_version"] = advisory_expr
                elif target.version:
                    rd["match_basis"] = "input-version"
            else:
                rd["cve_count"] = None
                rd["cve_ids"] = []
                rd["cve_error"] = None
            # Arricchimento con OS info dall'inventario asset.
            rd["os_type"] = asset.os_type or None
            rd["os_major_version"] = asset.os_major_version or None
            # Punto 4: remediation AI (solo se abilitato in config e asset vulnerabile).
            rd["remediation"] = ""
            if ai_remediation and rd["vuln_match"] == "VULNERABILE" and rd.get("cve_count"):
                rd["remediation"] = generate_remediation(
                    target.product, rd.get("detected_version"),
                    rd.get("cve_ids", []), rd.get("cve_count", 0), lang=lang,
                )
            all_results.append(rd)
            # Persistenza del singolo esito (best-effort).
            persist_result(scan_id, rd)
            yield _sse("result", rd)

        # 3b. Grafo dipendenze REALI: unione delle dipendenze runtime rilevate
        #     (ldd -> pacchetto) su tutti gli asset dove il prodotto e' presente.
        #     Nessuna tabella di assunzioni: solo cio' che e' linkato sui target.
        runtime_deps = sorted({
            d for r in all_results for d in (r.get("dependencies") or [])
        })
        contributing = sum(1 for r in all_results if r.get("dependencies"))
        # Archi inter-dipendenza reali: unione deduplicata (non orientata), con
        # entrambi gli estremi fra le dipendenze risolte.
        _dep_set = set(runtime_deps)
        _seen_edges: set = set()
        runtime_edges: list[list[str]] = []
        for r in all_results:
            for a, b in (r.get("dep_edges") or []):
                if a not in _dep_set or b not in _dep_set or a == b:
                    continue
                key = tuple(sorted((a, b)))
                if key not in _seen_edges:
                    _seen_edges.add(key)
                    runtime_edges.append([a, b])
        yield _sse("deps", {
            "product": target.product,
            "dependencies": runtime_deps,
            "edges": runtime_edges,
            "source": "runtime-ldd",
            "asset_count": contributing,
        })

        # 4. Sintesi CVE (OSV per il conteggio ufficiale + LLM locale per il testo).
        ver = summary_version or target.version
        # Ecosistema: quello dell'asset che ha fornito la versione di sintesi;
        # fallback Debian (copertura OS-package piu' ampia in OSV) se ignoto.
        osv = query_osv(target.product, ver, ecosystem=summary_eco or "Debian")
        if osv["ids"]:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "summary"})
            yield ": keepalive\n\n"
        summary = summarize_cves(target.product, ver, osv["ids"], count=osv["count"], lang=lang)
        cve_payload = {
            "product": target.product,
            "version": ver,
            "count": osv["count"],
            "ids": osv["ids"],
            "summary": summary,
            "error": osv["error"],
        }
        # Aggiorna la riga 'scans' con la sintesi CVE finale (best-effort).
        update_scan_summary(scan_id, cve_payload)
        yield _sse("cve", cve_payload)

        # Punto 2: triage AI post-scan — top-3 asset critici con motivazione e azione.
        if all_results:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "triage"})
            yield ": keepalive\n\n"
            triage_text = generate_triage_report(all_results, target.product, lang=lang)
            if triage_text:
                yield _sse("triage", {"report": triage_text, "product": target.product})

        yield _sse("done", {"scanned": len(assets)})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sse(event: str, payload: dict) -> str:
    """Formatta un messaggio Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def _ai_tag() -> dict:
    """Provider e modello LLM correnti per i log SSE."""
    ai = load_config()["ai"]
    provider = ai.get("provider", "ollama")
    model = (ai.get("claude_model") if provider == "claude"
             else ai.get("ollama_model", "qwen2.5:7b"))
    return {"provider": provider, "model": model}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
