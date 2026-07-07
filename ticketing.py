"""
ticketing.py
------------
Integrazione ticketing (capability ASPM: remediation workflow).

Crea un ticket di remediation per un finding su:

  - GitHub Issues  (token PAT + repo 'owner/repo')
  - Jira Cloud     (email + API token + project key)

Configurazione in config.json, sezione 'ticketing':

    "ticketing": {
      "provider": "github" | "jira" | "",   // "" = disabilitato
      "github_token": "", "github_repo": "owner/repo",
      "jira_url": "https://org.atlassian.net", "jira_email": "",
      "jira_api_token": "", "jira_project_key": ""
    }

Filosofia best-effort: errori di rete/credenziali tornano come TicketError con
messaggio leggibile; nessun crash sul percorso HTTP. La chiave/token non viene
mai loggata ne' esposta nelle risposte.
"""

import json

import requests

TIMEOUT = 20


class TicketError(RuntimeError):
    """Creazione ticket fallita (config mancante, rete, credenziali)."""


def _finding_body(f: dict) -> str:
    """Corpo del ticket in markdown (GitHub) / testo (Jira)."""
    cves = ", ".join(f.get("cve_ids") or []) or "-"
    lines = [
        f"**Severity:** {f.get('severity') or 'UNKNOWN'}",
        f"**Asset:** {f.get('asset_ip') or '-'}",
        f"**Package:** {f.get('package') or '-'} {f.get('version') or ''}".rstrip(),
        f"**Location:** {f.get('location') or '-'}",
        f"**CVE:** {cves}",
        f"**Source:** {f.get('source') or '-'}",
        f"**First seen:** {f.get('first_seen') or '-'}",
        f"**SLA due:** {f.get('sla_due') or '-'}",
        "",
        (f.get("detail") or "").strip(),
        "",
        "_Created by Vulnerability Feed Aggregator (finding "
        f"#{f.get('id')}, fingerprint {f.get('fingerprint')})_",
    ]
    return "\n".join(lines)


def _ticket_title(f: dict) -> str:
    sev = (f.get("severity") or "UNKNOWN").upper()
    return f"[{sev}] {f.get('title') or 'Security finding'}"[:200]


def create_github_issue(cfg: dict, f: dict) -> dict:
    token = (cfg.get("github_token") or "").strip()
    repo = (cfg.get("github_repo") or "").strip()
    if not token or "/" not in repo:
        raise TicketError("Ticketing GitHub non configurato (token o repo mancanti)")
    labels = ["security", (f.get("severity") or "unknown").lower()]
    try:
        resp = requests.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"title": _ticket_title(f), "body": _finding_body(f),
                  "labels": labels},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise TicketError(f"GitHub non raggiungibile: {exc}") from exc
    if resp.status_code != 201:
        detail = ""
        try:
            detail = (resp.json().get("message") or "")[:120]
        except json.JSONDecodeError:
            pass
        raise TicketError(f"GitHub HTTP {resp.status_code}: {detail}")
    data = resp.json()
    return {"provider": "github", "ref": f"#{data.get('number')}",
            "url": data.get("html_url") or ""}


def create_jira_issue(cfg: dict, f: dict) -> dict:
    base = (cfg.get("jira_url") or "").strip().rstrip("/")
    email = (cfg.get("jira_email") or "").strip()
    token = (cfg.get("jira_api_token") or "").strip()
    project = (cfg.get("jira_project_key") or "").strip()
    if not (base and email and token and project):
        raise TicketError("Ticketing Jira non configurato (url/email/token/project)")
    # Corpo in Atlassian Document Format (richiesto dalla API v3).
    body_adf = {
        "type": "doc", "version": 1,
        "content": [{"type": "paragraph",
                     "content": [{"type": "text",
                                  "text": _finding_body(f).replace("**", "")}]}],
    }
    try:
        resp = requests.post(
            f"{base}/rest/api/3/issue",
            auth=(email, token),
            json={"fields": {
                "project": {"key": project},
                "issuetype": {"name": "Task"},
                "summary": _ticket_title(f),
                "description": body_adf,
                "labels": ["security", (f.get("severity") or "unknown").lower()],
            }},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise TicketError(f"Jira non raggiungibile: {exc}") from exc
    if resp.status_code not in (200, 201):
        raise TicketError(f"Jira HTTP {resp.status_code}: {resp.text[:120]}")
    data = resp.json()
    key = data.get("key") or ""
    return {"provider": "jira", "ref": key, "url": f"{base}/browse/{key}"}


def create_ticket(cfg_ticketing: dict, finding: dict) -> dict:
    """
    Crea il ticket con il provider configurato.
    Ritorna {provider, ref, url}. TicketError se disabilitato o fallito.
    """
    provider = (cfg_ticketing.get("provider") or "").strip().lower()
    if provider == "github":
        return create_github_issue(cfg_ticketing, finding)
    if provider == "jira":
        return create_jira_issue(cfg_ticketing, finding)
    raise TicketError("Ticketing disabilitato: configura il provider in Settings")
