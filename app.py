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
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from assets import load_assets, save_assets, Asset
from osint import identify_product
from scanner import scan_asset, SIMULATE_AUTH, version_affected
from cve import (query_osv, summarize_cves, query_osv_ids, extract_affected_version,
                 query_osv_ecosystem)
from db import (persist_scan, persist_result, update_scan_summary, fetch_audit,
                create_posture_run, persist_posture_asset, finalize_posture_run,
                fetch_posture, fetch_posture_runs)
from posture import scan_asset_posture

BASE_DIR = Path(__file__).parent
ASSETS_FILE = BASE_DIR / "assets.txt"

app = FastAPI(title="Vulnerability Feed Aggregator")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Serve la singola pagina dell'applicazione."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "simulate_auth": SIMULATE_AUTH},
    )


@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request):
    """Pagina di gestione (CRUD) dell'inventario asset."""
    return templates.TemplateResponse("assets.html", {"request": request})


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    """Pagina AUDIT: storico dei risultati di scansione salvati su Supabase."""
    return templates.TemplateResponse("audit.html", {"request": request})


@app.get("/intel", response_class=HTMLResponse)
def intel_page(request: Request):
    """Pagina INTEL: dashboard Full Posture (ASPM-style)."""
    return templates.TemplateResponse("intel.html", {"request": request})


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
        except FileNotFoundError as exc:
            yield _sse("error", {"message": str(exc)})
            return
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
            persist_posture_asset(run_id, report)
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
    """True se una connessione TCP riesce su almeno una delle porte note."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            continue
    return False


@app.get("/api/asset/health")
def api_asset_health(host: str):
    """
    Test di raggiungibilita' runtime di un asset (connessione TCP su porte note).
    Usato dalla colonna ACTIVE della pagina Asset Inventory.
    """
    h = _normalize_host(host)
    if not h:
        return {"host": host, "reachable": False}
    return {"host": host, "reachable": _reachable(h)}


@app.get("/api/cve")
def api_cve(product: str, version: str | None = None):
    """
    Lista COMPLETA di id CVE (OSV) per (prodotto, versione).
    Usato dal 'show more' della pagina Audit per espandere oltre i 10 salvati.
    """
    return query_osv_ids(product, version)


@app.get("/api/assets")
def api_assets():
    """Ritorna l'inventario interpretato (senza password)."""
    try:
        assets = load_assets(ASSETS_FILE)
    except FileNotFoundError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    return {"assets": [a.to_dict() for a in assets]}


def _asset_full(index: int, a: Asset) -> dict:
    """Serializzazione completa per la pagina di gestione (password inclusa)."""
    return {
        "index": index,
        "ip": a.ip,
        "username": a.username,
        "password": a.password,
        "auth_required": a.auth_required,
    }


@app.get("/api/assets/all")
def api_assets_all():
    """Inventario completo (password inclusa) per la gestione CRUD."""
    try:
        assets = load_assets(ASSETS_FILE)
    except FileNotFoundError:
        assets = []
    return {"assets": [_asset_full(i, a) for i, a in enumerate(assets)]}


@app.post("/api/assets")
async def api_assets_create(request: Request):
    """Aggiunge un asset all'inventario. Body: {ip, username, password}."""
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    try:
        assets = load_assets(ASSETS_FILE)
    except FileNotFoundError:
        assets = []
    assets.append(Asset(
        ip=ip,
        username=(body.get("username") or "").strip(),
        password=(body.get("password") or "").strip(),
    ))
    save_assets(assets, ASSETS_FILE)
    return {"ok": True, "index": len(assets) - 1}


@app.put("/api/assets/{index}")
async def api_assets_update(index: int, request: Request):
    """Aggiorna l'asset all'indice indicato. Body: {ip, username, password}."""
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    try:
        assets = load_assets(ASSETS_FILE)
    except FileNotFoundError:
        assets = []
    if index < 0 or index >= len(assets):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    assets[index] = Asset(
        ip=ip,
        username=(body.get("username") or "").strip(),
        password=(body.get("password") or "").strip(),
    )
    save_assets(assets, ASSETS_FILE)
    return {"ok": True}


@app.delete("/api/assets/{index}")
def api_assets_delete(index: int):
    """Elimina l'asset all'indice indicato."""
    try:
        assets = load_assets(ASSETS_FILE)
    except FileNotFoundError:
        assets = []
    if index < 0 or index >= len(assets):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    assets.pop(index)
    save_assets(assets, ASSETS_FILE)
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
        # 1. Identificazione prodotto.
        target = identify_product(description, use_osint=use_osint)
        yield _sse("target", target.to_dict())

        if not target.product:
            yield _sse("done", {"scanned": 0, "note": "No product identified."})
            return

        # 2. Caricamento inventario.
        try:
            assets = load_assets(ASSETS_FILE)
        except FileNotFoundError as exc:
            yield _sse("error", {"message": str(exc)})
            return

        # 2b. ADVISORY AI: se il prodotto e' noto ma l'input NON contiene una
        #     versione (vulnerabilita' generica senza CVE), chiedo all'LLM di
        #     dedurre il RANGE di versione affetto, da confrontare con quella
        #     installata su ciascun asset. Best-effort ('' se Ollama offline).
        if not target.version:
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
        summary_version = None
        for asset in assets:
            result = scan_asset(asset, target, deep=deep)
            rd = result.to_dict()
            rd["affected_version"] = None
            rd["match_basis"] = "none"
            if rd["product_found"] and rd["detected_version"]:
                info = query_osv(target.product, rd["detected_version"])
                rd["cve_count"] = info["count"]
                rd["cve_ids"] = info["ids"]
                rd["cve_error"] = info["error"]
                if summary_version is None:
                    summary_version = rd["detected_version"]
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
            # Persistenza del singolo esito (best-effort).
            persist_result(scan_id, rd)
            yield _sse("result", rd)

        # 4. Sintesi CVE (OSV per il conteggio ufficiale + LLM locale per il testo).
        ver = summary_version or target.version
        osv = query_osv(target.product, ver)
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

        yield _sse("done", {"scanned": len(assets)})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sse(event: str, payload: dict) -> str:
    """Formatta un messaggio Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
