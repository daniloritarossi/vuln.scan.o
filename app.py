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
import logging
import os
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Request
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               StreamingResponse)
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
                 generate_triage_report, compute_fix_plan)
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
import db
from auth import (AuthRequired, Forbidden, PasswordChangeRequired, CurrentUser,
                  get_current_user, require_roles, visible_asset_ids,
                  visible_asset_ips, make_session_token, verify_password,
                  hash_password, ensure_default_admin, create_onetime_token,
                  consume_onetime_token, set_user_password,
                  password_policy_error, SESSION_COOKIE, SESSION_TTL, ROLES)
from mailer import (send_activation, send_reset, activation_link,
                    smtp_enabled, MailError)

logger = logging.getLogger("vfa.app")

BASE_DIR = Path(__file__).parent
ASSETS_FILE = BASE_DIR / "assets.txt"

# Flag 'Secure' del cookie di sessione: attivo di default, disattivabile solo
# per lo sviluppo locale su http (VFA_COOKIE_SECURE=0). In produzione (dietro
# TLS) il cookie NON deve mai viaggiare in chiaro.
COOKIE_SECURE = os.environ.get("VFA_COOKIE_SECURE", "1") != "0"


def _set_session_cookie(resp, user_id: int) -> None:
    """Imposta il cookie di sessione firmato con i flag di sicurezza uniformi."""
    resp.set_cookie(SESSION_COOKIE, make_session_token(user_id),
                    max_age=SESSION_TTL, httponly=True,
                    samesite="lax", secure=COOKIE_SECURE)

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

# Repo GitHub per il check aggiornamenti (override con VFA_GITHUB_REPO).
GITHUB_REPO = os.environ.get("VFA_GITHUB_REPO", "daniloritarossi/vuln.scan.o")


def _base_tag(version: str) -> str:
    """'v1.0.11-alfa-3-gabc1234' -> 'v1.0.11-alfa' (output di git describe)."""
    import re
    return re.sub(r"-\d+-g[0-9a-f]+$", "", (version or "").strip())


def _version_tuple(tag: str):
    """'v1.0.11-alfa' -> (1, 0, 11) per il confronto numerico. None se non parsabile."""
    import re
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", tag or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


# Cache del check remoto: 1 chiamata GitHub ogni 6 ore, non a ogni pagina.
_version_cache = {"at": 0.0, "latest": None}


def _fetch_latest_tag() -> Optional[str]:
    """Tag piu' recente su GitHub (max per versione). None se irraggiungibile."""
    import time as _time
    import requests as _req
    now = _time.time()
    if _version_cache["latest"] and now - _version_cache["at"] < 6 * 3600:
        return _version_cache["latest"]
    try:
        r = _req.get(f"https://api.github.com/repos/{GITHUB_REPO}/tags",
                     params={"per_page": 30},
                     headers={"Accept": "application/vnd.github+json"},
                     timeout=6)
        r.raise_for_status()
        tags = [t.get("name") for t in r.json() if t.get("name")]
        parsed = [(v, t) for t in tags if (v := _version_tuple(t))]
        latest = max(parsed)[1] if parsed else None
        _version_cache.update({"at": now, "latest": latest})
        return latest
    except Exception as exc:
        logger.info("check versione GitHub fallito: %s", exc)
        return None

app = FastAPI(title="Vulnerability Feed Aggregator", version=APP_VERSION)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["app_version"] = APP_VERSION
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------------------------------------------------------------------
# AUTENTICAZIONE / RBAC (cono di visibilita')
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _seed_default_admin():
    """Crea admin/admin al primo avvio (best-effort, vedi auth.py)."""
    ensure_default_admin()


@app.exception_handler(AuthRequired)
async def _auth_required_handler(request: Request, exc: AuthRequired):
    """API -> 401 JSON; pagine -> redirect alla login."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Autenticazione richiesta"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(Forbidden)
async def _forbidden_handler(request: Request, exc: Forbidden):
    """Ruolo/scope insufficiente: 403 per le API, home per le pagine."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": exc.detail}, status_code=403)
    return RedirectResponse("/", status_code=303)


@app.exception_handler(PasswordChangeRequired)
async def _pwchange_handler(request: Request, exc: PasswordChangeRequired):
    """Cambio password obbligatorio: blocca tutto tranne /change-password."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Cambio password obbligatorio",
                             "code": "password_change_required"},
                            status_code=403)
    return RedirectResponse("/change-password", status_code=303)


# Dependency riutilizzabili per la matrice dei ruoli.
_admin_only = require_roles("admin")
_admin_manager = require_roles("admin", "manager")
_writer = require_roles("admin", "manager", "editor")   # tutto tranne viewer


def _require_asset_in_scope(user: CurrentUser, asset_id: int) -> None:
    """403 se l'editor tenta di operare su un asset fuori dal suo cono."""
    ids = visible_asset_ids(user)
    if ids is not None and asset_id not in ids:
        raise Forbidden("Asset fuori dal tuo cono di visibilita'")


def _require_ip_in_scope(user: CurrentUser, ip: str) -> None:
    """403 se l'editor tenta di operare su un finding di un host fuori scope."""
    ips = visible_asset_ips(user)
    if ips is not None and (ip or "") not in ips:
        raise Forbidden("Asset fuori dal tuo cono di visibilita'")


def _filter_posture_run(run: dict, ips) -> dict:
    """Copia della run di postura limitata agli asset con ip nel set indicato."""
    if not run or ips is None:
        return run
    filtered = dict(run)
    filtered["posture_assets"] = [
        pa for pa in (run.get("posture_assets") or []) if pa.get("ip") in ips
    ]
    return filtered


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Pagina di login (unica pagina accessibile senza sessione)."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/api/login")
async def api_login(request: Request):
    """Verifica credenziali e apre la sessione (cookie HttpOnly firmato)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    row = db.fetch_user_by_username(username) if username else None
    # Account invitato ma mai attivato: password_hash assente o is_active falso.
    # Risposta identica alle credenziali errate (no enumeration).
    if (not row or not row.get("password_hash")
            or not row.get("is_active", True)
            or not verify_password(password, row["password_hash"])):
        return JSONResponse({"error": "Credenziali non valide"}, status_code=401)
    resp = JSONResponse({"ok": True, "username": row["username"], "role": row["role"],
                         "must_change_password": bool(row.get("must_change_password"))})
    _set_session_cookie(resp, row["id"])
    return resp


@app.get("/logout")
def logout():
    """Chiude la sessione e torna alla login."""
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/me")
def api_me(user: CurrentUser = Depends(get_current_user)):
    """Utente corrente (per la UI: chip utente, visibilita' voci di menu)."""
    return user.to_dict()


@app.get("/api/version/check")
def api_version_check(user: CurrentUser = Depends(get_current_user)):
    """
    Confronta la versione locale (tag git) con l'ultimo tag su GitHub.
    Risposta cache-ata lato server (6h) per non consumare rate limit.
    {current, latest, update_available, repo_url}
    """
    # Riletta a ogni chiamata: APP_VERSION e' congelata all'avvio del processo
    # e diventa stantia se nel frattempo viene creato/checkout-ato un tag.
    current = _base_tag(_git_version())
    latest = _fetch_latest_tag()
    update = False
    if latest and latest != current:
        cur_v, lat_v = _version_tuple(current), _version_tuple(latest)
        # Confronto numerico se possibile; fallback: diverso = aggiornabile.
        update = (lat_v > cur_v) if (cur_v and lat_v) else True
    return {"current": current, "latest": latest, "update_available": update,
            "repo_url": f"https://github.com/{GITHUB_REPO}"}


# ---------------------------------------------------------------------------
# Onboarding via email: attivazione account, reset e cambio password.
# ---------------------------------------------------------------------------

@app.get("/activate", response_class=HTMLResponse)
def activate_page(request: Request, token: str = ""):
    """Pagina di attivazione/reset: l'utente sceglie la propria password.
    Raggiungibile senza sessione (il token one-time E' la credenziale)."""
    return templates.TemplateResponse("activate.html",
                                      {"request": request, "token": token})


@app.post("/api/activate")
async def api_activate(request: Request):
    """
    Consuma un token one-time (attivazione o reset) e imposta la password
    scelta dall'utente. L'attivazione verifica implicitamente l'email.
    Body: {token, password}.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    token = (body.get("token") or "").strip()
    password = body.get("password") or ""
    err = password_policy_error(password)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    # Prova entrambi i purpose: il token e' one-time e legato all'utente.
    user_row = consume_onetime_token(token, "activation")
    verified = user_row is not None
    if user_row is None:
        user_row = consume_onetime_token(token, "reset")
    if user_row is None:
        return JSONResponse({"error": "Token non valido o scaduto"}, status_code=400)
    if not set_user_password(user_row["id"], password):
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    if verified and user_row.get("email") and not user_row.get("email_verified_at"):
        db.update_user(user_row["id"], {"email_verified_at": "now()"})
    return {"ok": True, "username": user_row["username"]}


@app.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request,
                         user: CurrentUser = Depends(get_current_user)):
    """Pagina di cambio password (anche in modalita' forzata)."""
    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "forced": user.must_change_password})


@app.post("/api/change-password")
async def api_change_password(request: Request,
                              user: CurrentUser = Depends(get_current_user)):
    """
    Cambio password dell'utente corrente. Body: {old_password, new_password}.
    Richiede la password attuale; invalida tutte le sessioni emesse prima
    (il nuovo cookie viene reimpostato in risposta).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    old_pw = body.get("old_password") or ""
    new_pw = body.get("new_password") or ""
    err = password_policy_error(new_pw)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    row = db.fetch_user(user.id)
    if not row or not verify_password(old_pw, row.get("password_hash") or ""):
        return JSONResponse({"error": "Password attuale errata"}, status_code=400)
    if old_pw == new_pw:
        return JSONResponse({"error": "La nuova password deve essere diversa"},
                            status_code=400)
    if not set_user_password(user.id, new_pw):
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    # Nuovo cookie: quello corrente e' invalidato da password_changed_at.
    resp = JSONResponse({"ok": True})
    _set_session_cookie(resp, user.id)
    return resp


@app.post("/api/forgot")
async def api_forgot(request: Request):
    """
    "Password dimenticata": invia un link di reset se l'email corrisponde a
    un utente attivo. Risposta SEMPRE identica (no enumeration).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    email = (body.get("email") or "").strip().lower()
    generic = {"ok": True,
               "message": "Se l'email corrisponde a un account, riceverai un link di reset."}
    if not email or not smtp_enabled():
        return generic
    row = db.fetch_user_by_email(email)
    if row and row.get("is_active"):
        token = create_onetime_token(row["id"], "reset")
        if token:
            try:
                send_reset(email, row["username"], token)
            except MailError as exc:
                logger.warning("send_reset fallita: %s", exc)
    return generic


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Serve la singola pagina dell'applicazione."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "simulate_auth": _simulate_auth()},
    )


@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina di gestione (CRUD) dell'inventario asset."""
    return templates.TemplateResponse("assets.html", {"request": request})


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, user: CurrentUser = Depends(_writer)):
    """Pagina AUDIT: storico dei risultati di scansione salvati su Supabase."""
    return templates.TemplateResponse("audit.html", {"request": request})


@app.get("/sbom", response_class=HTMLResponse)
def sbom_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina SBOM: Software Bill of Materials per asset dell'inventario."""
    return templates.TemplateResponse("sbom.html", {"request": request})


@app.get("/api/sbom")
def api_sbom(run_id: int | None = None,
             user: CurrentUser = Depends(get_current_user)):
    """
    Inventario software COMPLETO dell'ultima run di postura (tutti i componenti,
    non solo i vulnerabili). Ogni riga porta gli identificatori SBOM
    (purl, cpe, licenza, fornitore, sha256, relazioni).
    Editor: limitato agli asset del proprio cono di visibilita'.
    """
    run = fetch_posture_sbom(run_id)
    if not run:
        return {"rows": []}
    run = _filter_posture_run(run, visible_asset_ips(user))
    return {"rows": sbom_rows(run)}


@app.get("/api/sbom/export")
def api_sbom_export(format: str = "cyclonedx", run_id: int | None = None,
                    user: CurrentUser = Depends(_writer)):
    """
    Esporta la SBOM in formato standard.
    format: 'cyclonedx' (CycloneDX 1.5) | 'spdx' (SPDX 2.3).
    Download come file JSON.
    """
    run = fetch_posture_sbom(run_id)
    run = _filter_posture_run(run or {}, visible_asset_ips(user))
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
def findings_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina FINDINGS: ciclo di vita unificato (dedup + workflow + SLA)."""
    return templates.TemplateResponse("findings.html", {"request": request})


@app.get("/api/findings")
def api_findings(status: str | None = None, severity: str | None = None,
                 source: str | None = None, q: str | None = None,
                 user: CurrentUser = Depends(get_current_user)):
    """
    Elenco finding unificati + aggregati per la UI.
    Filtri opzionali: status, severity, source (substring), q (testo libero).
    Editor: solo i finding degli asset nel proprio cono di visibilita'
    (anche gli aggregati sono ricalcolati sul sottoinsieme, niente leak).
    503 se il DB non e' raggiungibile.
    """
    rows = fetch_findings()
    if rows is None:
        return JSONResponse({"error": "Supabase unreachable", "findings": []},
                            status_code=503)
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        rows = [r for r in rows if (r.get("asset_ip") or "") in scope_ips]
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
                              asset_ip: str = "",
                              user: CurrentUser = Depends(_writer)):
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
    # Editor: scarta (con conteggio) i finding riferiti ad asset fuori dal cono
    # di visibilita', invece di rifiutare l'intero batch (le pipeline CI non
    # si rompono su report a host misti).
    skipped_out_of_scope = 0
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        in_scope = [f for f in normalized if (f.get("asset_ip") or "") in scope_ips]
        skipped_out_of_scope = len(normalized) - len(in_scope)
        normalized = in_scope
    if not normalized:
        return {"ok": True, "tool": detected, "parsed": 0,
                "new": 0, "updated": 0, "reopened": 0,
                "skipped_out_of_scope": skipped_out_of_scope}
    fps = [fingerprint(f) for f in normalized]
    existing = fetch_findings_by_fps(list(set(fps)))
    if existing is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    rows, stats = merge_findings(normalized, {r["fingerprint"]: r for r in existing},
                                 cfg_sla=load_config().get("sla"))
    if not upsert_findings(rows):
        return JSONResponse({"error": "Persistenza fallita"}, status_code=503)
    return {"ok": True, "tool": detected, "parsed": len(normalized),
            "skipped_out_of_scope": skipped_out_of_scope, **stats}


@app.patch("/api/findings/{finding_id}/status")
async def api_findings_status(finding_id: int, request: Request,
                              user: CurrentUser = Depends(_writer)):
    """
    Transizione di stato del workflow. Body: {status, note?}.
    Stati validi: open | triaged | accepted | fixed.
    Editor: solo su finding di asset nel proprio cono di visibilita'.
    """
    if user.scoped:
        f = fetch_finding(finding_id)
        if f is None:
            return JSONResponse({"error": "Invalid id or DB unreachable"},
                                status_code=404)
        _require_ip_in_scope(user, f.get("asset_ip") or "")
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
def api_findings_ticket(finding_id: int, user: CurrentUser = Depends(_writer)):
    """
    Crea un ticket di remediation (GitHub Issue / Jira) per il finding e ne
    salva il riferimento. Provider e credenziali in config.json ('ticketing').
    Editor: solo su finding di asset nel proprio cono di visibilita'.
    """
    f = fetch_finding(finding_id)
    if f is None:
        return JSONResponse({"error": "Finding non trovato o DB non raggiungibile"},
                            status_code=404)
    _require_ip_in_scope(user, f.get("asset_ip") or "")
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
async def api_findings_scan_local(request: Request,
                                  user: CurrentUser = Depends(_writer)):
    """
    Esegue uno scanner LOCALE (binario opzionale sul server) e ne ingerisce
    il report nel ciclo di vita unificato.
    Body: {"type": "secrets" | "image", "target": "<path|image-ref>",
           "asset_ip": "<opzionale>"}.
      - secrets -> gitleaks sulla directory 'target'
      - image   -> trivy (vuln + secret) sull'immagine container 'target'
    Editor: 'asset_ip' obbligatorio e dentro il cono di visibilita' (i finding
    devono restare attribuibili a un asset assegnato).
    """
    body = await request.json()
    scan_type = (body.get("type") or "").strip().lower()
    target = (body.get("target") or "").strip()
    asset_ip = (body.get("asset_ip") or "").strip()
    if not target:
        return JSONResponse({"error": "Missing target"}, status_code=400)
    if user.scoped:
        if not asset_ip:
            raise Forbidden("Per il ruolo editor 'asset_ip' e' obbligatorio "
                            "(deve essere un asset assegnato)")
        _require_ip_in_scope(user, asset_ip)
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
def intel_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina INTEL: dashboard Full Posture (ASPM-style)."""
    return templates.TemplateResponse("intel.html", {"request": request})


@app.get("/risk", response_class=HTMLResponse)
def risk_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina RISK: prioritizzazione contestuale (EPSS/KEV + contesto + trend)."""
    return templates.TemplateResponse("risk.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: CurrentUser = Depends(_admin_manager)):
    """Pagina di configurazione dell'applicativo (admin: scrittura; manager: lettura)."""
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/api/settings")
def api_settings_get(user: CurrentUser = Depends(_admin_manager)):
    """Legge la configurazione corrente (admin e manager)."""
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
    if masked.get("smtp", {}).get("password"):
        masked["smtp"]["password"] = "••••••••"
    return masked


@app.post("/api/settings")
async def api_settings_post(request: Request,
                            user: CurrentUser = Depends(_admin_only)):
    """Aggiorna la configurazione. Merge parziale per sezione. SOLO admin."""
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
def api_ollama_models(user: CurrentUser = Depends(_admin_manager)):
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
def api_posture_scan(ips: str | None = None,
                     user: CurrentUser = Depends(_writer)):
    """
    Avvio MANUALE della Full Posture: per ogni asset raccoglie l'inventario
    pacchetti e lo valuta con OSV. Streaming SSE: 'run', 'asset'*, 'done'.
    Persistenza best-effort su Supabase (run -> asset -> findings).

    'ips' (opzionale): lista IP/host separati da virgola -> scansiona solo quelli.
    Assente/vuoto => tutti gli asset dell'inventario.
    Editor: scansiona solo gli asset del proprio cono di visibilita'.
    """
    selected = {s.strip() for s in (ips or "").split(",") if s.strip()}
    scope_ids = visible_asset_ids(user)

    def stream():
        try:
            assets = load_assets(ASSETS_FILE)
        except AssetStoreError as exc:
            yield _sse("error", {"message": str(exc)})
            return
        # Esclude gli asset disabilitati in inventario dalla scansione di postura.
        assets = [a for a in assets if a.enabled]
        if scope_ids is not None:
            assets = [a for a in assets if a.id in scope_ids]
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
def api_posture_cve(package: str, ecosystem: str | None = None,
                    version: str | None = None,
                    user: CurrentUser = Depends(get_current_user)):
    """Lista COMPLETA di id CVE per (pacchetto, ecosistema, versione) — 'show more' posture."""
    return query_osv_ecosystem(package, ecosystem, version)


@app.get("/api/posture/fixplan")
def api_posture_fixplan(package: str, ecosystem: str | None = None,
                        version: str | None = None,
                        user: CurrentUser = Depends(get_current_user)):
    """Fix plan OSV: per-CVE versione 'fixed' + versione minima che risolve tutto (resolver UI)."""
    return compute_fix_plan(package, ecosystem, version)


@app.get("/api/posture")
def api_posture(run_id: int | None = None,
                user: CurrentUser = Depends(get_current_user)):
    """
    Ritorna una run di postura (ultima se run_id assente) con asset+findings.
    Editor: solo gli asset del proprio cono di visibilita'.
    """
    data = fetch_posture(run_id)
    if data is None:
        return JSONResponse({"error": "Supabase unreachable", "run": {}}, status_code=503)
    data = _filter_posture_run(data, visible_asset_ips(user))
    return {"run": data}


@app.get("/api/posture/runs")
def api_posture_runs(user: CurrentUser = Depends(get_current_user)):
    """Elenco storico delle run di postura."""
    data = fetch_posture_runs()
    if data is None:
        return JSONResponse({"error": "Supabase unreachable", "runs": []}, status_code=503)
    return {"runs": data}


@app.get("/api/risk")
def api_risk(run_id: int | None = None, probe: bool = True,
             user: CurrentUser = Depends(get_current_user)):
    """
    Rischio CONTESTUALE di una run di postura (ultima se run_id assente).

    Combina: severita' della postura + exploitability (EPSS + CISA KEV) +
    reachability (porte di servizio aperte) + contesto business dell'asset
    (ambiente, internet-facing, criticita' dall'inventario).

    'probe=false' salta la sonda TCP delle porte (piu' veloce, no reachability).
    Editor: il rischio e' RICALCOLATO sul solo cono di visibilita' (gli
    aggregati non rivelano nulla degli asset non assegnati).
    """
    run = fetch_posture(run_id)
    if run is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    if not run:
        return {"risk": {"assets": [], "summary": {}, "meta": {}}}
    scope_ips = visible_asset_ips(user)
    run = _filter_posture_run(run, scope_ips)
    try:
        assets = load_assets(ASSETS_FILE)
        ctx = {a.ip: {"id": a.id, "environment": a.environment,
                      "internet_facing": a.internet_facing,
                      "criticality": a.criticality} for a in assets
               if scope_ips is None or a.ip in scope_ips}
    except AssetStoreError:
        ctx = {}
    return {"risk": assess_run_risk(run, ctx, probe=probe)}


@app.get("/api/risk/trend")
def api_risk_trend(user: CurrentUser = Depends(get_current_user)):
    """
    Serie storica del rischio (score/CVE per run) + delta finding-level fra le
    due run piu' recenti (nuove vs risolte). 503 se il DB non risponde.
    Editor: il delta e' calcolato sul solo cono di visibilita'; nella serie
    storica i contatori globali per-run vengono omessi (nessun leak indiretto).
    """
    runs = fetch_posture_runs()
    if runs is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        # Gli aggregati per-run (avg_score, total_vulns) sono globali: per gli
        # editor si mantengono solo id/data delle run nella serie.
        runs = [{"id": r.get("id"), "created_at": r.get("created_at")}
                for r in runs]
    current = previous = None
    if len(runs) >= 1:
        current = _filter_posture_run(fetch_posture(runs[0].get("id")), scope_ips)
    if len(runs) >= 2:
        previous = _filter_posture_run(fetch_posture(runs[1].get("id")), scope_ips)
    return {"trend": compute_trend(runs, current, previous)}


@app.patch("/api/assets/{index}/context")
async def api_assets_context(index: int, request: Request,
                             user: CurrentUser = Depends(_writer)):
    """
    Aggiorna il contesto business di un asset (per la prioritizzazione del rischio).
    Body (tutti opzionali): {environment, internet_facing, criticality}.
    Editor: solo su asset del proprio cono di visibilita'.
    """
    _require_asset_in_scope(user, index)
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
def api_audit(user: CurrentUser = Depends(_writer)):
    """
    Storico scansioni (scans + scan_results annidati) letto da Supabase.
    Admin e manager: tutto. Editor: solo i risultati relativi agli asset del
    proprio cono di visibilita'. Viewer: 403.
    503 se il DB non e' raggiungibile (la UI mostra un messaggio dedicato).
    """
    data = fetch_audit()
    if data is None:
        return JSONResponse(
            {"error": "Supabase unreachable", "scans": []},
            status_code=503,
        )
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        filtered = []
        for scan in data:
            results = [r for r in (scan.get("scan_results") or [])
                       if (r.get("ip") or "") in scope_ips]
            if results:
                filtered.append({**scan, "scan_results": results})
        data = filtered
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
    # Coerente con lo scan autenticato reale (scanner.py): carica i known_hosts
    # e RIFIUTA host key sconosciute. AutoAddPolicy accetterebbe qualunque
    # chiave, esponendo le credenziali dell'asset a un MITM.
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
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
def api_asset_health(host: str, index: int,
                     user: CurrentUser = Depends(get_current_user)):
    """
    Raggiungibilita' TCP + (se asset ha credenziali) login SSH.
    Risposta: {reachable, ssh_ok}  — ssh_ok=null se nessuna credenziale.
    'host' deve combaciare con l'IP dell'asset indicato da 'index' (nel cono
    di visibilita' dell'utente): impedisce di usare l'endpoint come sonda di
    rete verso host arbitrari (era sfruttabile anche da 'viewer').
    """
    _require_asset_in_scope(user, index)
    try:
        asset = get_asset(index, ASSETS_FILE)  # 'index' = id riga Supabase
    except AssetStoreError:
        asset = None
    h = _normalize_host(host)
    if not asset or not h or h != _normalize_host(asset.ip):
        raise Forbidden("Host non corrisponde all'asset indicato")

    reachable = _reachable(h)
    ssh_ok = None

    if reachable and asset.auth_required:
        if is_encrypted(asset.password):
            ssh_ok = _check_ssh(asset)
        else:
            ssh_ok = False  # password in chiaro: login rifiutato

    return {"host": host, "reachable": reachable, "ssh_ok": ssh_ok}


@app.get("/api/cve")
def api_cve(product: str, version: str | None = None,
            os_type: str | None = None, os_major_version: str | None = None,
            user: CurrentUser = Depends(get_current_user)):
    """
    Lista COMPLETA di id CVE (OSV) per (prodotto, versione).
    Usato dal 'show more' della pagina Audit per espandere oltre i 10 salvati.

    L'ecosistema OSV (richiesto dall'API) e' dedotto dal SO se fornito,
    altrimenti default Debian.
    """
    eco = os_ecosystem(os_type, os_major_version) or "Debian"
    return query_osv_ids(product, version, ecosystem=eco)


def _scope_filter_assets(assets: list, user: CurrentUser) -> list:
    """Applica il cono di visibilita' all'inventario (editor: solo assegnati)."""
    ids = visible_asset_ids(user)
    if ids is None:
        return assets
    return [a for a in assets if a.id in ids]


def _assignments_by_asset() -> dict:
    """{asset_id: [{'type','id','name'}]} per la colonna ASSEGNATO A della UI."""
    rows = db.fetch_all_assignments() or []
    out: dict = {}
    for r in rows:
        if r.get("user_id") is not None:
            entry = {"type": "user", "id": r["user_id"],
                     "name": (r.get("users") or {}).get("username", "?")}
        else:
            entry = {"type": "group", "id": r["group_id"],
                     "name": (r.get("groups") or {}).get("name", "?")}
        out.setdefault(r["asset_id"], []).append(entry)
    return out


@app.get("/api/assets")
def api_assets(user: CurrentUser = Depends(get_current_user)):
    """
    Ritorna l'inventario interpretato (senza password).
    Editor: solo asset assegnati. Viewer: username redatto.
    """
    try:
        assets = _scope_filter_assets(load_assets(ASSETS_FILE), user)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    out = [a.to_dict() for a in assets]
    if user.role == "viewer":
        for d in out:
            d["username"] = None
    return {"assets": out}


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
def api_assets_all(user: CurrentUser = Depends(get_current_user)):
    """
    Inventario completo per la gestione CRUD, con le assegnazioni
    utente/gruppo di ogni asset (cono di visibilita').
    Editor: solo asset assegnati. Viewer: username redatto.
    """
    try:
        assets = _scope_filter_assets(load_assets(ASSETS_FILE), user)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    assign = _assignments_by_asset()
    out = []
    for a in assets:
        d = _asset_full(a)
        d["assignments"] = assign.get(a.id, [])
        if user.role == "viewer":
            d["username"] = ""
            d["has_password"] = False
        out.append(d)
    return {"assets": out}


@app.post("/api/assets")
async def api_assets_create(request: Request,
                            user: CurrentUser = Depends(_writer)):
    """
    Aggiunge un asset all'inventario. Body: {ip, username, password}.
    Editor: l'asset creato viene AUTO-ASSEGNATO a lui (o a un suo gruppo se il
    body indica 'assign_group_id'), cosi' non puo' creare asset orfani ne'
    fuori dal proprio cono di visibilita'.
    """
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    os_type = (body.get("os_type") or "").strip().lower()
    if os_type not in ("linux", "windows"):
        return JSONResponse({"error": "OS type required (linux or windows)"}, status_code=400)
    assign_group = body.get("assign_group_id")
    if user.scoped and assign_group is not None \
            and int(assign_group) not in user.group_ids:
        raise Forbidden("Non appartieni al gruppo indicato")
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
    if user.scoped:
        if assign_group is not None:
            db.add_asset_assignment(new_id, group_id=int(assign_group))
        else:
            db.add_asset_assignment(new_id, user_id=user.id)
    return {"ok": True, "index": new_id}


@app.put("/api/assets/{index}/assignments")
async def api_assets_assignments(index: int, request: Request,
                                 user: CurrentUser = Depends(_admin_manager)):
    """
    Sostituisce le assegnazioni utente/gruppo dell'asset (cono di visibilita').
    Body: {"user_ids": [..], "group_ids": [..]}. Solo admin e manager:
    l'editor non puo' riassegnare (rischio self-escalation su asset altrui).
    """
    body = await request.json()
    user_ids = body.get("user_ids") or []
    group_ids = body.get("group_ids") or []
    try:
        current = get_asset(index, ASSETS_FILE)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    if current is None:
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    if not db.set_asset_assignments(index, user_ids, group_ids):
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    return {"ok": True, "user_ids": user_ids, "group_ids": group_ids}


@app.put("/api/assets/{index}")
async def api_assets_update(index: int, request: Request,
                            user: CurrentUser = Depends(_writer)):
    """Aggiorna l'asset indicato (index = id Supabase). Body: {ip, username, password}.
    Editor: solo asset del proprio cono di visibilita'."""
    _require_asset_in_scope(user, index)
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
async def api_assets_toggle(index: int, request: Request,
                            user: CurrentUser = Depends(_writer)):
    """Abilita/disabilita un asset per le scansioni. Body: {enabled: bool}.
    Editor: solo asset del proprio cono di visibilita'."""
    _require_asset_in_scope(user, index)
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    if not set_asset_enabled(index, enabled):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    return {"ok": True, "enabled": enabled}


@app.delete("/api/assets/{index}")
def api_assets_delete(index: int, user: CurrentUser = Depends(_writer)):
    """Elimina l'asset indicato (index = id Supabase).
    Editor: solo asset del proprio cono di visibilita'."""
    _require_asset_in_scope(user, index)
    if not delete_asset(index):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    return {"ok": True}


# ---------------------------------------------------------------------------
# AMMINISTRAZIONE UTENTI E GRUPPI (cono di visibilita')
# ---------------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: CurrentUser = Depends(_admin_only)):
    """Pagina ADMIN: gestione utenti, gruppi e membership. Solo admin."""
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/api/users")
def api_users_list(user: CurrentUser = Depends(_admin_manager)):
    """Elenco utenti (senza hash password). Admin e manager (il manager ne ha
    bisogno per assegnare gli asset); le scritture restano solo admin."""
    users = db.fetch_users()
    if users is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    return {"users": users}


def _send_invite(user_row: dict) -> dict:
    """
    Genera il token di attivazione e invia (o espone) il link.
    SMTP configurato -> email; SMTP assente -> il link torna all'admin nella
    risposta per la consegna manuale. La password non viaggia MAI via email.
    """
    token = create_onetime_token(user_row["id"], "activation")
    if token is None:
        return {"error": "Supabase non raggiungibile"}
    link = activation_link(token)
    if smtp_enabled() and user_row.get("email"):
        try:
            send_activation(user_row["email"], user_row["username"], token)
            return {"sent": True, "email": user_row["email"]}
        except MailError as exc:
            logger.warning("send_activation fallita: %s", exc)
            return {"sent": False, "activation_link": link,
                    "warning": f"Email non inviata ({exc}); consegna il link manualmente."}
    return {"sent": False, "activation_link": link,
            "warning": "SMTP non configurato: consegna il link manualmente."}


@app.post("/api/users")
async def api_users_create(request: Request,
                           user: CurrentUser = Depends(_admin_only)):
    """
    Crea un utente INVITATO. Body: {username, email, role}.
    Nessuna password: l'utente la sceglie via link di attivazione one-time
    (l'apertura del link valida anche l'email). Solo admin.
    Retro-compatibilita': se il body contiene 'password' l'utente e' creato
    attivo, ma con cambio password forzato al primo accesso.
    """
    body = await request.json()
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role = (body.get("role") or "viewer").strip().lower()
    if not username:
        return JSONResponse({"error": "username obbligatorio"}, status_code=400)
    if role not in ROLES:
        return JSONResponse({"error": f"Ruolo non valido: {role}",
                             "valid": list(ROLES)}, status_code=400)
    if not password and (not email or "@" not in email):
        return JSONResponse({"error": "email valida obbligatoria per l'invito "
                             "(oppure fornisci una password provvisoria)"},
                            status_code=400)
    row = {"username": username, "role": role, "email": email or None}
    if password:
        row.update({"password_hash": hash_password(password),
                    "is_active": True, "must_change_password": True})
    else:
        row.update({"password_hash": None, "is_active": False})
    new_id = db.insert_user(row)
    if new_id is None:
        return JSONResponse({"error": "Creazione fallita (username/email duplicati o DB non raggiungibile)"},
                            status_code=409)
    out = {"ok": True, "id": new_id}
    if not password:
        invite = _send_invite({"id": new_id, "username": username, "email": email})
        if "error" in invite:
            return JSONResponse(invite, status_code=503)
        out.update(invite)
    return out


@app.post("/api/users/{user_id}/invite")
def api_users_reinvite(user_id: int, user: CurrentUser = Depends(_admin_only)):
    """Reinvia l'invito di attivazione (brucia i token precedenti). Solo admin."""
    target = db.fetch_user(user_id)
    if not target:
        return JSONResponse({"error": "Utente non trovato"}, status_code=404)
    if target.get("is_active") and target.get("password_hash"):
        return JSONResponse({"error": "Utente gia' attivo"}, status_code=400)
    invite = _send_invite(target)
    if "error" in invite:
        return JSONResponse(invite, status_code=503)
    return {"ok": True, **invite}


@app.post("/api/users/{user_id}/reset")
def api_users_reset(user_id: int, user: CurrentUser = Depends(_admin_only)):
    """
    Invia un link di reset password all'utente (l'admin non conosce mai la
    password altrui). Solo admin.
    """
    target = db.fetch_user(user_id)
    if not target:
        return JSONResponse({"error": "Utente non trovato"}, status_code=404)
    if not target.get("is_active"):
        return JSONResponse({"error": "Utente non attivo: usa il reinvio invito"},
                            status_code=400)
    token = create_onetime_token(user_id, "reset")
    if token is None:
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    link = activation_link(token)
    if smtp_enabled() and target.get("email"):
        try:
            send_reset(target["email"], target["username"], token)
            return {"ok": True, "sent": True, "email": target["email"]}
        except MailError as exc:
            logger.warning("send_reset fallita: %s", exc)
            return {"ok": True, "sent": False, "reset_link": link,
                    "warning": f"Email non inviata ({exc}); consegna il link manualmente."}
    return {"ok": True, "sent": False, "reset_link": link,
            "warning": "SMTP non configurato o email assente: consegna il link manualmente."}


@app.put("/api/users/{user_id}")
async def api_users_update(user_id: int, request: Request,
                           user: CurrentUser = Depends(_admin_only)):
    """Aggiorna ruolo e/o password di un utente. Body: {role?, password?}."""
    body = await request.json()
    row = {}
    role = (body.get("role") or "").strip().lower()
    if role:
        if role not in ROLES:
            return JSONResponse({"error": f"Ruolo non valido: {role}",
                                 "valid": list(ROLES)}, status_code=400)
        row["role"] = role
    if body.get("password"):
        # Password impostata dall'admin = provvisoria: cambio forzato al
        # prossimo accesso (l'admin non deve conoscere la password d'uso).
        row["password_hash"] = hash_password(body["password"])
        row["must_change_password"] = True
        row["is_active"] = True
    if not row:
        return JSONResponse({"error": "Niente da aggiornare"}, status_code=400)
    # L'ultimo admin non puo' auto-degradarsi: lockout garantito.
    if row.get("role") and row["role"] != "admin":
        target = db.fetch_user(user_id)
        if target and target["role"] == "admin":
            admins = [u for u in (db.fetch_users() or []) if u["role"] == "admin"]
            if len(admins) <= 1:
                return JSONResponse({"error": "Impossibile rimuovere l'ultimo admin"},
                                    status_code=400)
    if not db.update_user(user_id, row):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def api_users_delete(user_id: int, user: CurrentUser = Depends(_admin_only)):
    """Elimina un utente (assegnazioni e membership cascano). Solo admin."""
    if user_id == user.id:
        return JSONResponse({"error": "Non puoi eliminare il tuo stesso utente"},
                            status_code=400)
    target = db.fetch_user(user_id)
    if target and target["role"] == "admin":
        admins = [u for u in (db.fetch_users() or []) if u["role"] == "admin"]
        if len(admins) <= 1:
            return JSONResponse({"error": "Impossibile eliminare l'ultimo admin"},
                                status_code=400)
    if not db.delete_user(user_id):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    return {"ok": True}


@app.get("/api/groups")
def api_groups_list(user: CurrentUser = Depends(_writer)):
    """
    Elenco gruppi con membri. Admin e manager: tutti i gruppi.
    Editor: solo i gruppi a cui appartiene.
    """
    groups = db.fetch_groups()
    if groups is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    out = [{"id": g["id"], "name": g["name"],
            "member_ids": [m["user_id"] for m in (g.get("user_groups") or [])]}
           for g in groups]
    if user.scoped:
        out = [g for g in out if g["id"] in user.group_ids]
    return {"groups": out}


@app.post("/api/groups")
async def api_groups_create(request: Request,
                            user: CurrentUser = Depends(_admin_only)):
    """Crea un gruppo. Body: {name}. Solo admin."""
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "Nome gruppo obbligatorio"}, status_code=400)
    new_id = db.insert_group(name)
    if new_id is None:
        return JSONResponse({"error": "Creazione fallita (nome duplicato o DB non raggiungibile)"},
                            status_code=409)
    return {"ok": True, "id": new_id}


@app.delete("/api/groups/{group_id}")
def api_groups_delete(group_id: int, user: CurrentUser = Depends(_admin_only)):
    """Elimina un gruppo (membership e assegnazioni cascano). Solo admin."""
    if not db.delete_group(group_id):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    return {"ok": True}


@app.put("/api/groups/{group_id}/members")
async def api_groups_members(group_id: int, request: Request,
                             user: CurrentUser = Depends(_admin_only)):
    """Sostituisce la membership del gruppo. Body: {user_ids: [..]}. Solo admin."""
    body = await request.json()
    if not db.set_group_members(group_id, body.get("user_ids") or []):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=503)
    return {"ok": True}


@app.post("/api/identify")
async def api_identify(request: Request,
                       user: CurrentUser = Depends(_writer)):
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
             deep: bool = False, user: CurrentUser = Depends(_writer)):
    """
    Esegue la scansione e trasmette i risultati in streaming (SSE).
    Ogni messaggio 'data:' e' un JSON con l'esito di un singolo asset.
    Eventi finali: 'target' (prodotto identificato) e 'done'.

    'lang' (default 'en') seleziona la lingua della sintesi CVE generata dall'LLM.
    Editor: scansiona solo gli asset del proprio cono di visibilita'.
    """
    scope_ids = visible_asset_ids(user)

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
        # Cono di visibilita': l'editor scansiona solo gli asset assegnati.
        if scope_ids is not None:
            assets = [a for a in assets if a.id in scope_ids]

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
