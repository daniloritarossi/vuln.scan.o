"""
cve.py
------
Arricchimento CVE dopo il rilevamento della versione.

Due livelli:

1) LOOKUP STRUTTURATO (OSV.dev): dato prodotto + versione, interroga l'API
   pubblica di OSV (https://osv.dev) e ritorna il numero di vulnerabilita' note
   e i relativi id. Deterministico, nessuna API key, matching esatto sui range
   di versione affetti. E' la fonte autorevole per "quante CVE ci sono".

2) SINTESI IN LINGUAGGIO NATURALE: LLM locale (Ollama) o Claude (Anthropic)
   configurabile via config.json. Best-effort: se l'LLM non e' raggiungibile
   la sintesi e' vuota e il sistema mostra solo il conteggio.

Nota: l'LLM riceve SOLO gli id gia' trovati da OSV e ha istruzione di non
inventarne; il conteggio "ufficiale" viene sempre da OSV, mai dal modello.
"""

import json as _json
import re as _re

import requests

from config import load_config

try:
    import anthropic as _anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

# Cache in-process: evita query OSV ripetute per la stessa coppia (prodotto, versione).
_osv_cache: dict = {}


def _osv_url() -> str:
    return load_config()["osv"]["url"]


def _osv_timeout() -> int:
    return int(load_config()["osv"]["timeout"])


def _osv_raw(product: str, version: str | None, timeout: int | None = None) -> dict:
    """
    Interrogazione OSV grezza (cache-ata): ritorna la lista COMPLETA di id.
    {"count": int, "ids": [str] (tutti), "error": str | None}.
    """
    key = (product.lower(), version or "")
    if key in _osv_cache:
        return _osv_cache[key]

    if timeout is None:
        timeout = _osv_timeout()

    payload = {"package": {"name": product.lower()}}
    if version:
        payload["version"] = version

    try:
        resp = requests.post(
            _osv_url(), json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulns") or []
        ids = [v.get("id") for v in vulns if v.get("id")]
        result = {"count": len(ids), "ids": ids, "error": None}
    except Exception as exc:
        result = {"count": 0, "ids": [], "error": str(exc)}

    _osv_cache[key] = result
    return result


def query_osv(product: str, version: str | None, timeout: int | None = None) -> dict:
    """
    Interroga OSV per (prodotto, versione).

    Ritorna: {"count": int, "ids": [str], "error": str | None}.
    'count' e' il totale reale; 'ids' e' troncato (max 10) per la UI/persistenza.
    """
    if not product:
        return {"count": 0, "ids": [], "error": None}
    r = _osv_raw(product, version, timeout)
    return {"count": r["count"], "ids": r["ids"][:10], "error": r["error"]}


def query_osv_ids(product: str, version: str | None, timeout: int | None = None) -> dict:
    """
    Come query_osv ma con la lista COMPLETA di id (per il 'show more' della UI).
    Ritorna: {"count": int, "ids": [str] (tutti), "error": str | None}.
    """
    if not product:
        return {"count": 0, "ids": [], "error": None}
    return _osv_raw(product, version, timeout)


def query_osv_ecosystem(name: str, ecosystem: str | None, version: str | None,
                        timeout: int | None = None) -> dict:
    """
    Query OSV per (nome, ecosistema, versione) -> lista COMPLETA di id.
    Usata dal 'show more' della tabella posture (ecosystem-aware: Debian, PyPI...).
    Ritorna: {"count": int, "ids": [str], "error": str | None}.
    """
    if not name:
        return {"count": 0, "ids": [], "error": None}
    if timeout is None:
        timeout = _osv_timeout()
    pkg = {"name": name.lower()}
    if ecosystem:
        pkg["ecosystem"] = ecosystem
    payload = {"package": pkg}
    if version:
        payload["version"] = version
    try:
        resp = requests.post(_osv_url(), json=payload,
                             headers={"Content-Type": "application/json"}, timeout=timeout)
        resp.raise_for_status()
        vulns = resp.json().get("vulns") or []
        ids = [v.get("id") for v in vulns if v.get("id")]
        return {"count": len(ids), "ids": ids, "error": None}
    except Exception as exc:
        return {"count": 0, "ids": [], "error": str(exc)}


# Lingue supportate per la sintesi LLM (mappa codice -> nome usato nel prompt).
_LANG_NAMES = {"en": "English", "it": "Italian"}


def _llm_complete(prompt: str, timeout: int) -> str:
    """
    Invia un prompt all'LLM configurato (Ollama o Claude) e ritorna la risposta.
    Best-effort: stringa vuota in caso di errore o provider non disponibile.
    """
    cfg = load_config()["ai"]
    provider = cfg.get("provider", "ollama")

    if provider == "claude":
        if not _ANTHROPIC_AVAILABLE:
            return ""
        api_key = cfg.get("claude_api_key", "")
        if not api_key:
            return ""
        try:
            client = _anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model=cfg.get("claude_model", "claude-haiku-4-5-20251001"),
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            return (msg.content[0].text or "").strip()
        except Exception:
            return ""

    # Default: Ollama
    try:
        resp = requests.post(
            cfg.get("ollama_url", "http://localhost:11434/api/generate"),
            json={
                "model": cfg.get("ollama_model", "qwen2.5:7b"),
                "prompt": prompt,
                "stream": False,
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        return (resp.json().get("response") or "").strip()
    except Exception:
        return ""


def summarize_cves(product: str, version: str | None, ids: list[str],
                   count: int | None = None, timeout: int | None = None,
                   lang: str = "en") -> str:
    """
    Sintesi del rischio via LLM (Ollama o Claude). Best-effort.

    'count' = totale reale di CVE da OSV (puo' superare len(ids), troncato a 10).
    'lang'  = lingua della risposta ('en' default, 'it' supportato).
    Ritorna stringa vuota se l'LLM non risponde.
    """
    if not ids:
        return ""
    if timeout is None:
        timeout = int(load_config()["ai"].get("summary_timeout", 60))

    total = count if count is not None else len(ids)
    language = _LANG_NAMES.get(lang, "English")
    ver = version or "undetermined version"
    prompt = (
        "You are a cybersecurity analyst. "
        f"The product '{product}' ({ver}) is associated with {total} "
        f"known vulnerabilities. Some example identifiers: "
        f"{', '.join(ids[:10])}. "
        "In at most 2 sentences, assess the overall risk level and state whether "
        "an upgrade is advisable. Do not invent identifiers that are not listed. "
        f"Respond EXCLUSIVELY in {language}, with no other languages."
    )
    return _llm_complete(prompt, timeout)


# Operatori ammessi in un vincolo di versione affetta.
_CONSTRAINT_RE = _re.compile(r"(<=|>=|==|<|>)\s*([0-9][0-9A-Za-z.\-]*)")


def _sanitize_constraint(raw: str) -> str:
    """
    Ripulisce la risposta dell'LLM in un vincolo di versione compatto.

    Accetta: '<2.5.0', '>=1.0 <2.0', '==1.2.3', 'all'. Scarta prosa/rumore.
    Ritorna '' se non determinabile.
    """
    if not raw:
        return ""
    low = raw.strip().lower()
    if low in ("all", "any", "*", "tutte", "tutti"):
        return "all"
    if low in ("unknown", "none", "n/a", "sconosciuto", "nessuna"):
        return ""
    if not _CONSTRAINT_RE.search(raw) and _re.search(
            r"\b(all|every|any|tutte|tutti)\b.*\bversion", low):
        return "all"
    parts = [f"{op}{ver}" for op, ver in _CONSTRAINT_RE.findall(raw)]
    if parts:
        return " ".join(parts)
    m = _re.search(r"\b([0-9]+(?:\.[0-9A-Za-z\-]+)+)\b", raw)
    return f"<={m.group(1)}" if m else ""


def extract_affected_version(product: str, description: str,
                             timeout: int | None = None) -> str:
    """
    Estrae via LLM il RANGE di versione affetto del prodotto a partire da una
    descrizione testuale di vulnerabilita' SENZA CVE/versione. Best-effort.
    """
    if not product or not description:
        return ""
    if timeout is None:
        timeout = int(load_config()["ai"].get("advisory_timeout", 60))

    prompt = (
        "You are a security analyst. From the vulnerability description below, "
        f"extract the affected version range of the product '{product}'. "
        "Answer with ONLY a compact version constraint using the operators "
        "< <= > >= == and dotted versions, e.g. '<2.5.0' or '>=1.0 <2.0'. "
        "If every version is affected answer exactly 'all'. "
        "If it cannot be determined answer exactly 'unknown'. "
        "No explanation, no extra text.\n\n"
        f"Description: {description}"
    )
    return _sanitize_constraint(_llm_complete(prompt, timeout))


def extract_product_llm(description: str, timeout: int | None = None) -> dict:
    """
    Estrae prodotto e versione via LLM da testo libero.
    Usato come fallback quando il dizionario locale non trova match.
    Ritorna {"product": str|None, "version": str|None}.
    """
    if not description:
        return {"product": None, "version": None}
    if timeout is None:
        timeout = int(load_config()["ai"].get("extract_timeout", 30))
    prompt = (
        "You are a security analyst. Extract the affected software product name and version "
        "from the text below. Answer with ONLY valid JSON, no markdown, no explanation:\n"
        '{"product": "<canonical lowercase name or null>", "version": "<dotted version string or null>"}\n'
        "Use null if not present or not determinable.\n\n"
        f"Text: {description[:800]}"
    )
    raw = _llm_complete(prompt, timeout)
    try:
        m = _re.search(r'\{[^}]+\}', raw)
        if m:
            data = _json.loads(m.group(0))
            product = (data.get("product") or "").strip().lower() or None
            version = (data.get("version") or "").strip() or None
            if product in ("null", "none", "n/a", "unknown"):
                product = None
            if version in ("null", "none", "n/a", "unknown"):
                version = None
            return {"product": product, "version": version}
    except Exception:
        pass
    return {"product": None, "version": None}


def generate_remediation(product: str, version: str | None, cve_ids: list[str],
                         cve_count: int, lang: str = "en",
                         timeout: int | None = None) -> str:
    """
    Genera una singola azione di remediation per un asset vulnerabile. Best-effort.
    Max ~12 parole, nessuna spiegazione aggiuntiva.
    """
    if not product:
        return ""
    if timeout is None:
        timeout = int(load_config()["ai"].get("remediation_timeout", 30))
    language = _LANG_NAMES.get(lang, "English")
    ver = version or "undetermined version"
    ids_str = ", ".join(cve_ids[:5]) if cve_ids else "none listed"
    prompt = (
        f"Asset running {product} {ver} has {cve_count} known CVEs ({ids_str}). "
        "Give a single concise remediation action. "
        "Examples: 'Upgrade to 2.5.0 or later' / 'Apply vendor security patch'. "
        "Max 12 words, no explanation, no trailing punctuation. "
        f"Respond in {language}."
    )
    return _llm_complete(prompt, timeout)


def generate_triage_report(results: list[dict], product: str, lang: str = "en",
                           timeout: int | None = None) -> str:
    """
    Report di triage AI post-scan: top-3 asset più critici con motivazione e azione.
    Best-effort: stringa vuota se LLM offline o nessun asset critico.
    """
    if not results:
        return ""
    if timeout is None:
        timeout = int(load_config()["ai"].get("triage_timeout", 60))
    language = _LANG_NAMES.get(lang, "English")
    lines = []
    for r in results:
        ip = r.get("ip", "?")
        vuln = r.get("vuln_match", "INCERTO")
        ver = r.get("detected_version") or "unknown"
        cves = r.get("cve_count") or 0
        found = r.get("product_found", False)
        lines.append(f"{ip}: status={vuln}, version={ver}, CVEs={cves}, found={found}")
    summary = "\n".join(lines)
    prompt = (
        f"Security scan of '{product}' across {len(results)} assets:\n"
        f"{summary}\n\n"
        "List the top 3 most critical assets to remediate first. "
        "Format each line EXACTLY as: <IP> | <risk reason> | <recommended action>. "
        "Only include VULNERABILE or INCERTO assets. "
        "If fewer than 3 critical assets exist, list only those. "
        f"Respond EXCLUSIVELY in {language}."
    )
    return _llm_complete(prompt, timeout)


if __name__ == "__main__":
    for prod, ver in [("apache", "2.4.7"), ("openssh", "6.6.1"), ("nginx", "1.21")]:
        info = query_osv(prod, ver)
        print(f"{prod} {ver}: {info['count']} CVE -> {info['ids'][:3]} (err={info['error']})")
    demo = query_osv("apache", "2.4.7")
    print("\nLLM summary:\n",
          summarize_cves("apache", "2.4.7", demo["ids"], count=demo["count"]))
