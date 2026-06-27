"""
osint.py
--------
Estrazione del "Software Target" da una descrizione testuale di vulnerabilita'.

Strategia:
1) Estrazione LOCALE (primaria, sempre attiva): matching su un dizionario di
   prodotti noti + regex per la versione. Veloce e offline.
2) Arricchimento OSINT (opzionale): query al motore di ricerca configurato
   (DuckDuckGo o Serper) per confermare/identificare il prodotto quando
   l'estrazione locale fallisce. Disattivabile via config.

L'OSINT online e' best-effort: se la rete non e' disponibile il sistema
ricade sull'estrazione locale senza errori.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from config import load_config
from cve import extract_product_llm

try:
    import requests
    from bs4 import BeautifulSoup
    _NET_AVAILABLE = True
except Exception:  # pragma: no cover - dipendenze opzionali
    _NET_AVAILABLE = False


# Dizionario prodotti noti -> alias riconosciuti nel testo.
# La chiave e' il nome canonico usato dallo scanner per il fingerprinting.
KNOWN_PRODUCTS = {
    "python": ["python", "cpython", "pypi", "pip"],
    "openssh": ["openssh", "ssh", "sshd"],
    "apache": ["apache", "httpd", "apache2"],
    "nginx": ["nginx"],
    "openssl": ["openssl"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql", "postgres"],
    "php": ["php"],
    "nodejs": ["node.js", "nodejs", "node"],
    "log4j": ["log4j", "log4shell"],
    "wordpress": ["wordpress", "wp"],
    "tomcat": ["tomcat", "catalina"],
    "redis": ["redis"],
    "vsftpd": ["vsftpd"],
    "exim": ["exim"],
    # Software client Windows (rilevati via scansione autenticata PowerShell).
    # Nota: l'alias "notepad++" non e' matchabile con \b...\b (il '+' finale non
    # crea word boundary), quindi si usa "notepad" come alias funzionante.
    "notepad++": ["notepad", "npp", "notepad plus plus"],
    "putty": ["putty"],
}

# Dipendenze note per prodotto canonico. Servono a costruire il grafo
# "DETECTED PRODUCTS NETWORK": nodo centrale = prodotto, nodi figli = librerie
# da cui dipende (rilevanti per la superficie di attacco).
PRODUCT_DEPENDENCIES = {
    "python": ["openssl", "libffi", "zlib", "sqlite"],
    "openssh": ["openssl", "zlib", "pam"],
    "nginx": ["openssl", "pcre", "zlib"],
    "apache": ["openssl", "pcre", "apr"],
    "php": ["openssl", "pcre", "zlib", "libxml2"],
    "nodejs": ["openssl", "v8", "libuv", "zlib"],
    "openssl": ["zlib"],
    "mysql": ["openssl", "zlib"],
    "postgresql": ["openssl", "zlib", "readline"],
    "tomcat": ["java", "apr"],
    "redis": ["jemalloc", "lua"],
    "log4j": ["java"],
    "wordpress": ["php", "mysql"],
    "vsftpd": ["openssl", "pam"],
    "exim": ["openssl", "pcre"],
    "notepad++": ["scintilla", "boost"],
    "putty": ["zlib"],
}

# Versione: numeri tipo 3.10, 8.4, 1.1.1k, 2.4.49 ...
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,3}[a-z]?)\b")


@dataclass
class TargetInfo:
    """Risultato dell'identificazione del software."""
    product: Optional[str]            # nome canonico, es. "python"
    version: Optional[str]            # es. "3.10" se presente
    matched_alias: Optional[str]      # alias effettivamente trovato nel testo
    source: str                       # "local" | "osint" | "none"
    candidates: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "version": self.version,
            "matched_alias": self.matched_alias,
            "source": self.source,
            "candidates": self.candidates,
            "dependencies": PRODUCT_DEPENDENCIES.get(self.product or "", []),
        }


def extract_version(text: str) -> Optional[str]:
    """Restituisce la prima versione numerica trovata nel testo, se presente."""
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def extract_local(text: str) -> TargetInfo:
    """
    Estrazione offline: cerca alias di prodotti noti nel testo (case-insensitive)
    e una eventuale versione. Ritorna il primo prodotto con match piu' lungo.
    """
    lowered = text.lower()
    best_product = None
    best_alias = None
    best_len = 0
    candidates: List[str] = []

    for product, aliases in KNOWN_PRODUCTS.items():
        for alias in aliases:
            if re.search(rf"\b{re.escape(alias)}\b", lowered):
                candidates.append(product)
                if len(alias) > best_len:
                    best_len = len(alias)
                    best_product = product
                    best_alias = alias

    version = extract_version(text)
    return TargetInfo(
        product=best_product,
        version=version,
        matched_alias=best_alias,
        source="local" if best_product else "none",
        candidates=sorted(set(candidates)),
    )


def _ddg_search(query: str, timeout: int = 6) -> str:
    """DuckDuckGo HTML endpoint. Best-effort."""
    if not _NET_AVAILABLE:
        return ""
    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (VulnFeedAggregator OSINT)"},
            timeout=timeout,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        snippets = soup.select(".result__snippet, .result__title")
        return " ".join(s.get_text(" ", strip=True) for s in snippets)
    except Exception:
        return ""


def _serper_search(query: str, api_key: str, timeout: int = 6) -> str:
    """Serper.dev Google SERP API. Best-effort."""
    if not _NET_AVAILABLE or not api_key:
        return ""
    try:
        resp = requests.post(
            "https://google.serper.dev/search",
            json={"q": query},
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        parts = []
        for item in data.get("organic", []):
            if item.get("title"):
                parts.append(item["title"])
            if item.get("snippet"):
                parts.append(item["snippet"])
        return " ".join(parts)
    except Exception:
        return ""


def _web_search(query: str, timeout: int = 6) -> str:
    """Dispatch search al provider configurato (duckduckgo o serper)."""
    cfg = load_config()["search_engine"]
    provider = cfg.get("provider", "duckduckgo")
    if provider == "serper":
        result = _serper_search(query, cfg.get("serper_api_key", ""), timeout)
        if result:
            return result
        # fallback DDG se serper fallisce (chiave vuota / quota esaurita)
        return _ddg_search(query, timeout)
    return _ddg_search(query, timeout)


def _count_product_hits(product: str, text: str) -> int:
    """Numero di occorrenze (parola intera) degli alias del prodotto nel testo."""
    text_l = text.lower()
    total = 0
    for alias in KNOWN_PRODUCTS.get(product, [product]):
        total += len(re.findall(rf"\b{re.escape(alias)}\b", text_l))
    return total


def extract_osint(text: str) -> TargetInfo:
    """
    Arricchimento online: interroga il motore di ricerca configurato,
    poi usa prima l'LLM e poi (fallback) il matching regex locale sul testo.

    Si fida del prodotto dedotto via regex solo se compare almeno min_osint_hits
    volte nei risultati (soglia anti-falsi-positivi configurabile).
    """
    cfg = load_config()["search_engine"]
    min_hits = int(cfg.get("min_osint_hits", 2))

    results_text = _web_search(text)
    if not results_text:
        return TargetInfo(None, extract_version(text), None, "none")

    # Punto 3: LLM processa il testo web per estrarre prodotto + versione.
    combined = f"Original query: {text}\n\nSearch results: {results_text[:1500]}"
    llm = extract_product_llm(combined)
    if llm["product"]:
        return TargetInfo(
            product=llm["product"],
            version=llm["version"] or extract_version(text),
            matched_alias=llm["product"],
            source="osint",
            candidates=[llm["product"]],
        )

    # Fallback: regex locale sul testo web (comportamento precedente).
    info = extract_local(results_text)
    if not info.product:
        return TargetInfo(None, extract_version(text), None, "none")

    if _count_product_hits(info.product, results_text) < min_hits:
        return TargetInfo(None, extract_version(text), None, "none")

    info.source = "osint"
    info.version = extract_version(text)
    return info


def identify_product(text: str, use_osint: bool = True) -> TargetInfo:
    """
    Punto di ingresso unico per il backend.

    1. Estrazione locale (dizionario + regex) — offline, prioritaria.
    2. (Punto 1) Fallback LLM diretto — deduce prodotto senza web search.
    3. (Punto 3) OSINT web search + LLM sui risultati — solo se LLM offline o fallisce.
    """
    cfg = load_config()["search_engine"]
    min_query = int(cfg.get("min_osint_query", 4))

    local = extract_local(text)
    if local.product or not use_osint:
        return local

    if len(re.sub(r"[^a-z0-9]", "", text.lower())) < min_query:
        return local

    # Punto 1: LLM diretto — più veloce del web search, nessuna rete esterna.
    llm = extract_product_llm(text)
    if llm["product"]:
        return TargetInfo(
            product=llm["product"],
            version=llm["version"] or extract_version(text),
            matched_alias=llm["product"],
            source="llm",
            candidates=[llm["product"]],
        )

    # Punto 3: fallback web search + LLM sui risultati.
    return extract_osint(text)


if __name__ == "__main__":
    for sample in [
        "Remote Code Execution in Python 3.10 via HTTP component",
        "Buffer overflow affecting OpenSSH 8.4",
        "Some weird issue in nginx 1.21",
    ]:
        info = identify_product(sample, use_osint=False)
        print(f"{sample!r} -> {info.to_dict()}")
