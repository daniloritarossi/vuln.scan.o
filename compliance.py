"""
compliance.py
-------------
Compliance tagging (capability ASPM: compliance mapping).

Deriva per ogni finding i riferimenti di conformita':

  - CWE       -> dai metadati del report (Trivy CweIDs, Semgrep metadata.cwe,
                 Nuclei classification.cwe-id) quando presenti
  - OWASP     -> Top 10 2021 (A01..A10), dalla mappa CWE oppure da euristica
                 su sorgente/ecosistema quando la CWE manca
  - NIS2      -> misure minime dell'art. 21(2) della direttiva (UE) 2022/2555
                 pertinenti alla categoria del finding

Modulo puro e deterministico: nessuna chiamata di rete, i tag sono calcolati
al volo da /api/findings (nessuna colonna aggiuntiva oltre a cwe_ids).
"""

import re

# --- CWE -> OWASP Top 10 2021 ----------------------------------------------
# Sottoinsieme delle mappe ufficiali OWASP (le CWE piu' frequenti per voce).

_CWE_TO_OWASP = {
    # A01 Broken Access Control
    "22": "A01", "23": "A01", "35": "A01", "59": "A01", "200": "A01",
    "201": "A01", "219": "A01", "264": "A01", "275": "A01", "284": "A01",
    "285": "A01", "352": "A01", "425": "A01", "441": "A01", "548": "A01",
    "639": "A01", "862": "A01", "863": "A01", "918": "A01",
    # A02 Cryptographic Failures
    "261": "A02", "296": "A02", "310": "A02", "319": "A02", "321": "A02",
    "322": "A02", "323": "A02", "324": "A02", "325": "A02", "326": "A02",
    "327": "A02", "328": "A02", "329": "A02", "330": "A02", "331": "A02",
    "335": "A02", "336": "A02", "337": "A02", "338": "A02", "340": "A02",
    "347": "A02", "523": "A02", "720": "A02", "757": "A02", "759": "A02",
    "760": "A02", "780": "A02", "818": "A02", "916": "A02",
    # A03 Injection
    "20": "A03", "74": "A03", "75": "A03", "77": "A03", "78": "A03",
    "79": "A03", "80": "A03", "83": "A03", "87": "A03", "88": "A03",
    "89": "A03", "90": "A03", "91": "A03", "93": "A03", "94": "A03",
    "95": "A03", "96": "A03", "97": "A03", "98": "A03", "99": "A03",
    "113": "A03", "116": "A03", "138": "A03", "184": "A03", "470": "A03",
    "471": "A03", "564": "A03", "610": "A03", "643": "A03", "644": "A03",
    "652": "A03", "917": "A03",
    # A04 Insecure Design
    "73": "A04", "183": "A04", "209": "A04", "213": "A04", "235": "A04",
    "256": "A04", "257": "A04", "266": "A04", "269": "A04", "280": "A04",
    "311": "A04", "312": "A04", "313": "A04", "316": "A04", "419": "A04",
    "430": "A04", "434": "A04", "444": "A04", "451": "A04", "472": "A04",
    "501": "A04", "522": "A04", "525": "A04", "539": "A04", "579": "A04",
    "598": "A04", "602": "A04", "642": "A04", "646": "A04", "650": "A04",
    "653": "A04", "656": "A04", "657": "A04", "799": "A04", "807": "A04",
    "840": "A04", "841": "A04", "927": "A04", "1021": "A04", "1173": "A04",
    # A05 Security Misconfiguration
    "2": "A05", "11": "A05", "13": "A05", "15": "A05", "16": "A05",
    "260": "A05", "315": "A05", "520": "A05", "526": "A05", "537": "A05",
    "541": "A05", "547": "A05", "611": "A05", "614": "A05", "756": "A05",
    "776": "A05", "942": "A05", "1004": "A05", "1032": "A05", "1174": "A05",
    # A06 Vulnerable and Outdated Components
    "937": "A06", "1035": "A06", "1104": "A06",
    # A07 Identification and Authentication Failures
    "255": "A07", "259": "A07", "287": "A07", "288": "A07", "290": "A07",
    "294": "A07", "295": "A07", "297": "A07", "300": "A07", "302": "A07",
    "304": "A07", "306": "A07", "307": "A07", "346": "A07", "384": "A07",
    "521": "A07", "613": "A07", "620": "A07", "640": "A07", "798": "A07",
    "940": "A07", "1216": "A07",
    # A08 Software and Data Integrity Failures
    "345": "A08", "353": "A08", "426": "A08", "494": "A08", "502": "A08",
    "565": "A08", "784": "A08", "829": "A08", "830": "A08", "915": "A08",
    # A09 Security Logging and Monitoring Failures
    "117": "A09", "223": "A09", "532": "A09", "778": "A09",
    # A10 Server-Side Request Forgery (CWE-918 gia' in A01 nella mappa OWASP;
    # qui la teniamo su A10, voce dedicata)
}
_CWE_TO_OWASP["918"] = "A10"

OWASP_TITLES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# --- NIS2, art. 21(2), direttiva (UE) 2022/2555 -----------------------------
# Misure minime pertinenti per categoria di finding.

NIS2_TITLES = {
    "21.2.d": "Supply chain security",
    "21.2.e": "Vulnerability handling and disclosure",
    "21.2.g": "Cyber hygiene and training",
    "21.2.h": "Cryptography and encryption",
    "21.2.i": "Access control and asset management",
    "21.2.j": "Multi-factor authentication and secured communications",
}

# Sorgente -> tag di default (quando la CWE non e' disponibile).
_SOURCE_DEFAULTS = {
    "posture":    {"owasp": ["A06"], "nis2": ["21.2.d", "21.2.e"]},
    "trivy":      {"owasp": ["A06"], "nis2": ["21.2.d", "21.2.e"]},
    "grype":      {"owasp": ["A06"], "nis2": ["21.2.d", "21.2.e"]},
    "nuclei":     {"owasp": ["A05"], "nis2": ["21.2.e"]},
    "semgrep":    {"owasp": [],      "nis2": ["21.2.e"]},
    "gitleaks":   {"owasp": ["A07"], "nis2": ["21.2.h", "21.2.i"]},
    "trufflehog": {"owasp": ["A07"], "nis2": ["21.2.h", "21.2.i"]},
}

_OWASP_TO_NIS2 = {
    "A01": ["21.2.i"], "A02": ["21.2.h"], "A03": ["21.2.e"],
    "A04": ["21.2.e"], "A05": ["21.2.e", "21.2.g"], "A06": ["21.2.d", "21.2.e"],
    "A07": ["21.2.i", "21.2.j"], "A08": ["21.2.d"], "A09": ["21.2.e"],
    "A10": ["21.2.e"],
}

_CWE_RE = re.compile(r"(?:CWE-)?(\d{1,4})$", re.IGNORECASE)


def normalize_cwes(raw) -> list:
    """['CWE-79', '89', 'cwe-798'] -> ['CWE-79', 'CWE-89', 'CWE-798'] dedup."""
    out = []
    for v in (raw or []):
        m = _CWE_RE.match(str(v).strip())
        if m:
            cwe = f"CWE-{int(m.group(1))}"
            if cwe not in out:
                out.append(cwe)
    return out


def derive_compliance(finding: dict) -> dict:
    """
    Tag di conformita' per un finding:
      {"cwe": [...], "owasp": ["A06 Vulnerable and Outdated Components"],
       "nis2": ["21.2.e Vulnerability handling and disclosure"]}
    """
    cwes = normalize_cwes(finding.get("cwe_ids"))
    owasp_codes = []
    for cwe in cwes:
        code = _CWE_TO_OWASP.get(cwe.split("-", 1)[1])
        if code and code not in owasp_codes:
            owasp_codes.append(code)

    # Fallback euristico dalla sorgente quando la CWE non mappa/manca.
    if not owasp_codes:
        for src in (finding.get("source") or "").split("+"):
            for code in _SOURCE_DEFAULTS.get(src, {}).get("owasp", []):
                if code not in owasp_codes:
                    owasp_codes.append(code)
    # Vulnerabilita' con CVE su componente = comunque A06.
    if (finding.get("cve_ids") and finding.get("package")
            and "A06" not in owasp_codes):
        owasp_codes.append("A06")

    nis2_codes = []
    for code in owasp_codes:
        for n in _OWASP_TO_NIS2.get(code, []):
            if n not in nis2_codes:
                nis2_codes.append(n)
    for src in (finding.get("source") or "").split("+"):
        for n in _SOURCE_DEFAULTS.get(src, {}).get("nis2", []):
            if n not in nis2_codes:
                nis2_codes.append(n)

    return {
        "cwe": cwes,
        "owasp": [f"{c} {OWASP_TITLES[c]}" for c in sorted(owasp_codes)],
        "nis2": [f"{c} {NIS2_TITLES[c]}" for c in sorted(nis2_codes)],
    }


def compliance_summary(rows: list) -> dict:
    """
    Aggregato per la UI: conteggio finding APERTI (open/triaged) per voce
    OWASP Top 10 e per misura NIS2 art. 21(2).
    """
    owasp: dict = {}
    nis2: dict = {}
    for r in rows:
        if (r.get("status") or "open") not in ("open", "triaged"):
            continue
        comp = r.get("compliance") or derive_compliance(r)
        for tag in comp["owasp"]:
            owasp[tag] = owasp.get(tag, 0) + 1
        for tag in comp["nis2"]:
            nis2[tag] = nis2.get(tag, 0) + 1
    return {
        "owasp": dict(sorted(owasp.items())),
        "nis2": dict(sorted(nis2.items())),
    }
