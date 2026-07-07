"""
ingest.py
---------
Ingestione di report da scanner ESTERNI (capability ASPM: aggregazione).

Parser per i formati JSON nativi dei tool piu' diffusi:

  - Trivy      (`trivy ... -f json`)          -> vulnerabilita' pacchetti/immagini
                                                 + secret nei layer (Results[].Secrets)
  - Grype      (`grype ... -o json`)          -> vulnerabilita' pacchetti/immagini
  - Nuclei     (`nuclei -je out.json` o JSONL)-> finding template-based su host
  - Semgrep    (`semgrep --json`)             -> finding SAST su codice
  - Gitleaks   (`gitleaks detect -f json`)    -> secret hardcoded in repo/directory
  - Trufflehog (`trufflehog ... --json`)      -> secret (CRITICAL se verificata)

Ogni report viene normalizzato in una lista di "finding" con lo stesso schema
usato dalla postura interna, cosi' da confluire nel ciclo di vita unificato
(vedi findings.py):

    {
      "source":   "trivy" | "grype" | "nuclei" | "semgrep",
      "asset_ip": str,        # host/target (override dal chiamante se fornito)
      "title":    str,        # titolo leggibile del finding
      "package":  str,        # pacchetto/regola ('' se non applicabile)
      "version":  str,        # versione installata ('' se non applicabile)
      "ecosystem": str,       # ecosistema/tipo ('' se non applicabile)
      "location": str,        # target/percorso/URL del finding
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN",
      "cve_ids":  [str],      # CVE associate (eventualmente vuota)
      "cwe_ids":  [str],      # CWE associate (per il compliance tagging)
      "detail":   str,        # descrizione breve
    }

Il formato viene riconosciuto automaticamente (detect_tool) oppure puo' essere
forzato dal chiamante. Errori di parsing sollevano IngestError con messaggio
leggibile: nessun crash sul percorso HTTP.
"""

import json

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

# Severita' Semgrep -> scala comune.
_SEMGREP_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

SUPPORTED_TOOLS = ("trivy", "grype", "nuclei", "semgrep", "gitleaks", "trufflehog")


class IngestError(ValueError):
    """Report non riconosciuto o malformato."""


def _norm_sev(raw: str) -> str:
    s = (raw or "").strip().upper()
    return s if s in SEVERITIES else _SEMGREP_SEV.get(s, "UNKNOWN")


def _cves(seq) -> list:
    """Filtra/normalizza una lista di id mantenendo solo i CVE-*."""
    out = []
    for v in (seq or []):
        v = (str(v) or "").strip().upper()
        if v.startswith("CVE-") and v not in out:
            out.append(v)
    return out


def _cwes(seq) -> list:
    """Normalizza una lista di CWE ('79', 'CWE-79') in ['CWE-79'] dedup."""
    if isinstance(seq, str):
        seq = [seq]
    out = []
    for v in (seq or []):
        v = str(v).strip().upper()
        if v.isdigit():
            v = f"CWE-{int(v)}"
        if v.startswith("CWE-") and v not in out:
            out.append(v)
    return out


# --- parsing del corpo ------------------------------------------------------

def parse_payload(raw: bytes | str):
    """
    Decodifica il corpo caricato: JSON singolo, array JSON oppure JSONL
    (una riga JSON per finding, formato di default di nuclei).
    Ritorna l'oggetto Python decodificato (dict o list).
    """
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else (raw or "")
    text = text.strip()
    if not text:
        raise IngestError("Report vuoto")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fallback JSONL: una riga JSON per record.
    rows = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise IngestError(f"JSON non valido (riga {i + 1}): {exc}") from exc
    if not rows:
        raise IngestError("JSON non valido")
    return rows


def detect_tool(doc) -> str:
    """Riconosce il tool dal contenuto del report. IngestError se ignoto."""
    if isinstance(doc, dict):
        if "Results" in doc and ("SchemaVersion" in doc or "ArtifactName" in doc):
            return "trivy"
        if "matches" in doc and isinstance(doc.get("matches"), list):
            return "grype"
        results = doc.get("results")
        if isinstance(results, list) and (not results or "check_id" in results[0]):
            return "semgrep"
    if isinstance(doc, list) and doc and isinstance(doc[0], dict):
        first = doc[0]
        if "template-id" in first or "templateID" in first or "template" in first:
            return "nuclei"
        if "check_id" in first:
            return "semgrep"
        if "RuleID" in first and ("Secret" in first or "Match" in first):
            return "gitleaks"
        if "DetectorName" in first or "SourceMetadata" in first:
            return "trufflehog"
    raise IngestError(
        "Formato report non riconosciuto. Supportati: " + ", ".join(SUPPORTED_TOOLS))


# --- parser per tool --------------------------------------------------------

def parse_trivy(doc: dict, asset_ip: str = "") -> list:
    """Trivy JSON (SchemaVersion 2): Results[].Vulnerabilities[] + Secrets[]."""
    findings = []
    artifact = doc.get("ArtifactName") or ""
    for res in (doc.get("Results") or []):
        target = res.get("Target") or artifact
        eco = res.get("Type") or ""
        for v in (res.get("Vulnerabilities") or []):
            vid = (v.get("VulnerabilityID") or "").upper()
            pkg = v.get("PkgName") or ""
            findings.append({
                "source": "trivy",
                "asset_ip": asset_ip or artifact or target,
                "title": v.get("Title") or f"{vid} in {pkg}".strip(),
                "package": pkg,
                "version": v.get("InstalledVersion") or "",
                "ecosystem": eco,
                "location": target,
                "severity": _norm_sev(v.get("Severity")),
                "cve_ids": _cves([vid]),
                "cwe_ids": _cwes(v.get("CweIDs")),
                "detail": (v.get("Description") or "")[:500],
            })
        # Secret rilevate nei layer/filesystem (`--scanners secret`).
        for s in (res.get("Secrets") or []):
            rule = s.get("RuleID") or "secret"
            line = s.get("StartLine")
            findings.append({
                "source": "trivy",
                "asset_ip": asset_ip or artifact or target,
                "title": s.get("Title") or f"Secret: {rule}",
                "package": rule,
                "version": "",
                "ecosystem": "secret",
                "location": f"{target}:{line}" if line else target,
                "severity": _norm_sev(s.get("Severity") or "HIGH"),
                "cve_ids": [],
                "cwe_ids": ["CWE-798"],   # hardcoded credentials
                "detail": (s.get("Match") or "")[:200],
            })
    return findings


def parse_grype(doc: dict, asset_ip: str = "") -> list:
    """Grype JSON: matches[].vulnerability + artifact."""
    findings = []
    src = doc.get("source") or {}
    target = (src.get("target") if isinstance(src.get("target"), str)
              else (src.get("target") or {}).get("userInput", "")) or ""
    for m in (doc.get("matches") or []):
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        vid = (vuln.get("id") or "").upper()
        related = [r.get("id") for r in (m.get("relatedVulnerabilities") or [])]
        pkg = art.get("name") or ""
        findings.append({
            "source": "grype",
            "asset_ip": asset_ip or target,
            "title": f"{vid} in {pkg}".strip(),
            "package": pkg,
            "version": art.get("version") or "",
            "ecosystem": art.get("type") or "",
            "location": target,
            "severity": _norm_sev(vuln.get("severity")),
            "cve_ids": _cves([vid] + related),
            "cwe_ids": [],
            "detail": (vuln.get("description") or "")[:500],
        })
    return findings


def parse_nuclei(doc, asset_ip: str = "") -> list:
    """Nuclei JSON export / JSONL: un record per finding template-based."""
    records = doc if isinstance(doc, list) else [doc]
    findings = []
    for r in records:
        if not isinstance(r, dict):
            continue
        info = r.get("info") or {}
        tid = r.get("template-id") or r.get("templateID") or r.get("template") or ""
        cls = info.get("classification") or {}
        cve_raw = cls.get("cve-id") or []
        if isinstance(cve_raw, str):
            cve_raw = [cve_raw]
        host = r.get("host") or r.get("ip") or ""
        findings.append({
            "source": "nuclei",
            "asset_ip": asset_ip or host,
            "title": info.get("name") or tid,
            "package": tid,
            "version": "",
            "ecosystem": r.get("type") or "",
            "location": r.get("matched-at") or r.get("matched") or host,
            "severity": _norm_sev(info.get("severity")),
            "cve_ids": _cves(cve_raw),
            "cwe_ids": _cwes(cls.get("cwe-id")),
            "detail": (info.get("description") or "")[:500],
        })
    return findings


def parse_semgrep(doc, asset_ip: str = "") -> list:
    """Semgrep --json: results[].check_id + extra.severity/message."""
    results = doc.get("results") if isinstance(doc, dict) else doc
    findings = []
    for r in (results or []):
        extra = r.get("extra") or {}
        path = r.get("path") or ""
        line = ((r.get("start") or {}).get("line"))
        loc = f"{path}:{line}" if line else path
        check = r.get("check_id") or ""
        findings.append({
            "source": "semgrep",
            "asset_ip": asset_ip or "code",
            "title": check.rsplit(".", 1)[-1].replace("-", " ") or check,
            "package": check,
            "version": "",
            "ecosystem": "code",
            "location": loc,
            "severity": _norm_sev(extra.get("severity")),
            "cve_ids": _cves((extra.get("metadata") or {}).get("cve", [])),
            "cwe_ids": _cwes(_semgrep_cwes((extra.get("metadata") or {}).get("cwe"))),
            "detail": (extra.get("message") or "")[:500],
        })
    return findings


def _semgrep_cwes(raw) -> list:
    """Semgrep annota le CWE come 'CWE-78: OS Command Injection' -> ['CWE-78']."""
    if isinstance(raw, str):
        raw = [raw]
    return [str(v).split(":", 1)[0] for v in (raw or [])]


def parse_gitleaks(doc, asset_ip: str = "") -> list:
    """Gitleaks JSON (array di leak): secret hardcoded in repo/directory."""
    records = doc if isinstance(doc, list) else [doc]
    findings = []
    for r in records:
        if not isinstance(r, dict):
            continue
        rule = r.get("RuleID") or "secret"
        path = r.get("File") or ""
        line = r.get("StartLine")
        findings.append({
            "source": "gitleaks",
            "asset_ip": asset_ip or "code",
            "title": r.get("Description") or f"Secret: {rule}",
            "package": rule,
            "version": "",
            "ecosystem": "secret",
            "location": f"{path}:{line}" if line else path,
            "severity": "HIGH",
            "cve_ids": [],
            "cwe_ids": ["CWE-798"],   # hardcoded credentials
            # MAI includere il valore della secret nel finding persistito.
            "detail": f"Commit: {r.get('Commit') or 'n/a'} · "
                      f"Entropy: {r.get('Entropy') or 'n/a'}",
        })
    return findings


def parse_trufflehog(doc, asset_ip: str = "") -> list:
    """Trufflehog JSONL: una riga per secret; CRITICAL se verificata live."""
    records = doc if isinstance(doc, list) else [doc]
    findings = []
    for r in records:
        if not isinstance(r, dict) or "DetectorName" not in r:
            continue
        det = r.get("DetectorName") or "secret"
        meta = ((r.get("SourceMetadata") or {}).get("Data") or {})
        fsdata = meta.get("Filesystem") or meta.get("Git") or {}
        path = fsdata.get("file") or ""
        line = fsdata.get("line")
        verified = bool(r.get("Verified"))
        findings.append({
            "source": "trufflehog",
            "asset_ip": asset_ip or "code",
            "title": f"Secret: {det}" + (" (VERIFIED)" if verified else ""),
            "package": det,
            "version": "",
            "ecosystem": "secret",
            "location": f"{path}:{line}" if path and line else path or det,
            "severity": "CRITICAL" if verified else "HIGH",
            "cve_ids": [],
            "cwe_ids": ["CWE-798"],
            # MAI includere il valore della secret nel finding persistito.
            "detail": "Credential verified against live service" if verified
                      else "Credential detected (not verified)",
        })
    return findings


_PARSERS = {"trivy": parse_trivy, "grype": parse_grype,
            "nuclei": parse_nuclei, "semgrep": parse_semgrep,
            "gitleaks": parse_gitleaks, "trufflehog": parse_trufflehog}


def ingest_report(raw: bytes | str, tool: str = "auto", asset_ip: str = "") -> tuple:
    """
    Punto d'ingresso unico: decodifica il corpo, riconosce (o valida) il tool,
    ritorna (tool, findings_normalizzati). IngestError su input non valido.
    """
    doc = parse_payload(raw)
    tool = (tool or "auto").strip().lower()
    if tool in ("", "auto"):
        tool = detect_tool(doc)
    if tool not in _PARSERS:
        raise IngestError(
            f"Tool non supportato: {tool}. Supportati: " + ", ".join(SUPPORTED_TOOLS))
    return tool, _PARSERS[tool](doc, asset_ip=(asset_ip or "").strip())
