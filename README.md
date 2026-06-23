# Vulnerability Feed Aggregator

Web app per **audit autorizzati**: gestisce un inventario di asset, identifica software vulnerabile da una **descrizione testuale** (anche senza CVE esplicito), esegue scansioni di rete, arricchisce i risultati con dati CVE e produce analisi di postura di sicurezza tramite AI.

Backend **FastAPI** · Frontend **HTML + Tailwind** (CDN) · risultati in tempo reale via **Server-Sent Events** · persistenza su **Supabase locale (Docker)**.

> ⚠️ **Uso responsabile.** Eseguire scansioni o login solo su asset di propria titolarità o per cui si dispone di autorizzazione scritta. Scansionare sistemi terzi senza permesso è illecito.

---

## Installazione

Richiede: **Python 3.10+**, `pip`, `venv`, **Docker** (per Supabase).  
Su Debian/Ubuntu: `sudo apt install python3-pip python3-venv`

### Primo avvio (wizard interattivo)

```bash
git clone <repo>
cd vulnerability_feed_aggregator
chmod +x start.sh
./start.sh
```

Al primo avvio (nessun `config.json`) parte il **wizard**:

1. **Modello AI** — scelta tra:
   - `Locale` → Ollama (modello gira sulla macchina locale; verifica raggiungibilità e scarica il modello via `ollama pull`)
   - `Remoto` → Claude API (Anthropic; richiede API key)
2. **Search engine OSINT** — scelta tra:
   - `DuckDuckGo` — gratuito, nessuna API key
   - `Serper` — risultati Google, richiede API key

Dopo le scelte il wizard scrive `config.json`, installa le dipendenze Python nel virtualenv `.venv` e lancia l'app.

### Avvio successivo

```bash
./start.sh                  # avvio normale (porta 8000)
PORT=9000 ./start.sh        # porta personalizzata
./start.sh --no-supabase    # salta Supabase (già attivo o non necessario)
```

### Modifica configurazione

```bash
./start.sh update           # menu interattivo: cambia AI e/o search engine
./start.sh update --no-supabase   # modifica config senza avviare Supabase
```

Il menu `update` mostra la configurazione attuale e permette di:
- Cambiare AI provider (Ollama ↔ Claude)
- Cambiare search engine (DuckDuckGo ↔ Serper)
- Salvare ed uscire, oppure salvare e lanciare l'app

### Stop

```bash
./stop.sh       # ferma Supabase (i dati persistono)
# Ctrl+C        # ferma solo il server FastAPI
```

---

## Architettura

```
start.sh ──► wizard config.json ──► .venv + deps ──► Supabase ──► FastAPI
```

| File | Ruolo |
|------|-------|
| `app.py` | Server FastAPI: routing pagine + API REST + SSE |
| `config.py` | Lettura/scrittura `config.json`; defaults embedded |
| `osint.py` | Identifica prodotto e versione dalla descrizione testuale |
| `scanner.py` | Scansione asset: banner grabbing TCP + audit SSH |
| `cve.py` | Lookup CVE su OSV.dev + sintesi AI + remediation |
| `posture.py` | SCA (Software Composition Analysis) per asset: inventario pacchetti + OSV |
| `assets.py` | Parsing e CRUD inventario asset (`assets.txt` + API) |
| `db.py` | Persistenza Supabase (best-effort) |
| `config.json` | Configurazione runtime (generato dal wizard) |
| `assets.txt` | Inventario asset (IP\|user\|pass) |

---

## Funzionalità

### 1 · Identificazione prodotto (OSINT)

Data una descrizione testuale (`"Buffer overflow affecting OpenSSH 8.4"`):

1. **Estrazione locale** — regex + dizionario `KNOWN_PRODUCTS` (centinaia di prodotti); zero dipendenze di rete.
2. **Fallback web** — se la locale fallisce, esegue una query sul search engine configurato (DuckDuckGo o Serper) e ri-applica il matching sul testo restituito.

Output: `TargetInfo` con `product`, `version`, `aliases`, `source`, `candidates`.

### 2 · Scansione asset (SSE in tempo reale)

Per ogni asset dell'inventario:

| Modalità | Cosa fa |
|----------|---------|
| **No-auth** | Banner grabbing TCP reale sulle porte del prodotto (es. 22 per SSH, 80/443 per web) |
| **Auth simulato** (default) | Risposta deterministica per demo e test offline |
| **Auth reale** | Login SSH via `paramiko`, raccolta banner e path `/proc` (solo se `simulate_auth: false` in `config.json`) |

I risultati arrivano alla UI **un asset alla volta** via Server-Sent Events.

### 3 · Lookup CVE e sintesi AI

Dopo il rilevamento della versione:

- **OSV.dev** — query strutturata (senza API key) per CVE note e range di versione affetti; deterministico.
- **Sintesi AI** — riassunto in linguaggio naturale via Ollama (locale) o Claude API; best-effort (se non raggiungibile mostra solo il conteggio).
- **Remediation** — suggerimenti di rimedio generati dall'AI per i CVE trovati.
- **Triage report** — report consolidato per l'intera scansione (lingua configurabile: `it` / `en`).

### 4 · Postura di sicurezza (SCA)

Per ogni asset esegue una **Software Composition Analysis**:

- Raccoglie l'inventario pacchetti installati (SSH reale → `dpkg`/`rpm`/`pip`; simulato → catalogo realistico con versioni note vulnerabili).
- Interroga OSV.dev in batch per ogni pacchetto.
- Restituisce: pacchetti vulnerabili, CVE totali, distribuzione per severità (critical / high / medium / low), score aggregato.

### 5 · Gestione asset

CRUD completo dell'inventario via UI (`/assets`) e API REST:

- Aggiunta, modifica, eliminazione asset
- Health check (raggiungibilità) per ogni host
- Formato file: `IP|username|password` (righe `#` = commenti)

### 6 · Pagine dell'interfaccia

| Percorso | Contenuto |
|----------|-----------|
| `/` | Scan principale: inserisci descrizione, vedi risultati in tempo reale |
| `/assets` | Gestione inventario asset |
| `/audit` | Storico scansioni salvate su Supabase |
| `/intel` | Ricerca OSINT manuale su un prodotto/versione |
| `/settings` | Configurazione AI e search engine via UI (equivalente a `./start.sh update`) |

---

## Configurazione (`config.json`)

Generato dal wizard; modificabile via `./start.sh update` o dalla pagina `/settings`.

```jsonc
{
  "ai": {
    "provider": "ollama",           // "ollama" | "claude"
    "ollama_url": "http://localhost:11434/api/generate",
    "ollama_model": "qwen2.5:7b",
    "claude_api_key": "",
    "claude_model": "claude-haiku-4-5-20251001",
    "ai_remediation": false         // true = genera remediation AI
  },
  "search_engine": {
    "provider": "duckduckgo",       // "duckduckgo" | "serper"
    "serper_api_key": "",
    "min_osint_hits": 2,
    "min_osint_query": 4
  },
  "scanner": {
    "simulate_auth": true,          // false = SSH reale via paramiko
    "socket_timeout": 4
  },
  "osv": {
    "url": "https://api.osv.dev/v1/query",
    "timeout": 15
  }
}
```

---

## Formato `assets.txt`

```
# commento
45.33.32.156||              # no-auth (scanme.nmap.org — host pubblico autorizzato Nmap)
93.184.216.34|admin|secret  # auth SSH
10.0.0.5                    # solo IP, equivale a no-auth
```

---

## Persistenza Supabase (locale, Docker)

Stack lean (`supabase/docker-compose.yml`): Postgres + PostgREST + Studio + nginx. Dati persistenti su bind-mount (`supabase/volumes/db/data`).

| Servizio | URL | Note |
|----------|-----|------|
| Studio GUI | http://localhost:3001 | Table editor / SQL editor |
| REST API | http://localhost:8001/rest/v1/ | header `apikey` + `Authorization` |
| Postgres | localhost:5432 | accesso diretto |

**Schema** (`supabase/volumes/db/init/01-schema.sql`):

- `scans` — una riga per scansione: prodotto/versione/aliases/source/candidates + sintesi CVE
- `scan_results` — una riga per asset: ip, method, product\_found, detected\_version, raw\_evidence, vuln\_match, cve\_count, cve\_ids

L'app si collega in modalità **best-effort**: se Supabase è spento la scansione non si interrompe.

Override via env: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `SUPABASE_PERSIST=0` (disattiva persistenza).

> ⚠️ Le chiavi in `supabase/.env` sono **demo, solo per l'ambiente locale**. Non usare in produzione.

---

## Test moduli (senza server)

```bash
python3 osint.py      # identifica prodotto da esempi embedded
python3 assets.py     # dump inventario interpretato
python3 scanner.py    # scansione (esegue banner grab reale!)
```

---

## Sicurezza auth SSH

`scanner.py` usa `RejectPolicy` sulle host key (nessun auto-accept).  
Con `simulate_auth: true` (default) nessun login SSH viene eseguito.  
Con `simulate_auth: false` abilita login reali: **usare solo su host di propria titolarità**.

---

## Esempi di input

| Input | Prodotto identificato |
|-------|-----------------------|
| `Remote Code Execution in Python 3.10 via HTTP` | python 3.10 |
| `Buffer overflow affecting OpenSSH 8.4` | openssh 8.4 |
| `Critical vuln in nginx 1.21 HTTP/2 module` | nginx 1.21 |
| `Log4Shell — Apache Log4j 2.14.1` | log4j 2.14.1 |

I prodotti riconosciuti sono in `KNOWN_PRODUCTS` (`osint.py`) — estendibile aggiungendo nuove voci al dizionario.
