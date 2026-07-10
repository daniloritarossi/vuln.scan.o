# Vulnerability Feed Aggregator

Web app per **audit autorizzati**: gestisce un inventario di asset, identifica software vulnerabile da una **descrizione testuale** (anche senza CVE esplicito), esegue scansioni di rete, arricchisce i risultati con dati CVE e produce analisi di postura di sicurezza tramite AI.

Backend **FastAPI** · Frontend **HTML + Tailwind** (CDN) · risultati in tempo reale via **Server-Sent Events** · persistenza su **Supabase locale (Docker)**.

> ⚠️ **Uso responsabile.** Eseguire scansioni o login solo su asset di propria titolarità o per cui si dispone di autorizzazione scritta. Scansionare sistemi terzi senza permesso è illecito.

![Home](static/screens/home1.png)
![Home](static/screens/home2.png)
---

## Installazione

Richiede: **Python 3.10+**, `pip`, `venv`, **Docker**, **Go ≥ 1.21** (per la compilazione di `encdec`).  
Su Debian/Ubuntu: `sudo apt install python3-pip python3-venv golang`

### Primo avvio (wizard interattivo)

```bash
git clone <repo>
cd vulnerability_feed_aggregator
chmod +x start.sh stop.sh
./start.sh
```

In alternativa al `clone`, è sempre possibile scaricare l'artefatto di un **tag/release** come pacchetto `.zip` (pagina *Tags* del repo → *Download ZIP*, o `<repo>/archive/refs/tags/<tag>.zip`): estrarre e procedere da `cd vulnerability_feed_aggregator` in poi.

---

## `start.sh` — avvio e configurazione

Lo script è il punto di ingresso unico. Gestisce in sequenza: cifratura password, configurazione AI/search, macchina di test Docker, virtualenv, Supabase e server FastAPI.

### Fasi di esecuzione

```
start.sh
 │
 ├─ 1) encdec setup      ──► prima volta: chiede prefisso segreto → patcha sorgente → compila binario
 │                            avvii successivi: binario già presente, nessuna interazione
 │
 ├─ 2) Wizard / Update
 │     ├─ AI provider    ──► Ollama locale  |  Claude API
 │     ├─ Search engine  ──► DuckDuckGo    |  Serper
 │     └─ Docker test    ──► crea macchina Linux vulnerabile (opzionale)
 │
 ├─ 3) Virtualenv        ──► crea .venv, installa requirements.txt
 ├─ 4) Supabase          ──► avvia stack Docker (skippabile con --no-supabase)
 └─ 5) FastAPI           ──► exec uvicorn app:app --host 127.0.0.1 --port $PORT
```

### Modalità di avvio

```bash
./start.sh                        # avvio normale (porta 8000)
PORT=9000 ./start.sh              # porta personalizzata
./start.sh --no-supabase          # salta Supabase
./start.sh update                 # menu modifica configurazione
./start.sh update --no-supabase   # modifica config senza Supabase
```

### Wizard primo avvio

Al primo avvio (nessun `config.json`) il wizard chiede:

1. **Prefisso segreto encdec** — inserito una sola volta; compilato nel binario (vedi sezione Cifratura password)
2. **Modello AI**:
   - `Locale` → Ollama (verifica raggiungibilità, esegue `ollama pull`)
   - `Remoto` → Claude API (richiede API key)
3. **Search engine OSINT**:
   - `DuckDuckGo` — gratuito, nessuna API key
   - `Serper` — risultati Google, richiede API key
4. **Macchina Linux Docker di test** — opzionale (vedi sezione dedicata)

### Menu `update`

```bash
./start.sh update
```

Mostra la configurazione corrente e permette di:

| Opzione | Azione |
|---|---|
| 1 | Cambia AI provider (Ollama ↔ Claude) |
| 2 | Cambia search engine (DuckDuckGo ↔ Serper) |
| 3 | Crea/avvia macchina Linux Docker di test |
| 4 | Salva ed esci (solo configurazione, non lancia l'app) |
| 5 | Salva e lancia l'app |

---

## `stop.sh` — arresto completo

```bash
./stop.sh
```

Esegue in sequenza:

1. **Spegne lo stack Supabase** (`docker compose down`) — i dati persistono in `supabase/volumes/db/data`
2. **Rimuove il container di test** `vuln-test-linux-1` se presente (`docker rm -f`)

Il server FastAPI si ferma separatamente con `Ctrl+C` nel terminale dove gira `start.sh`.

---

## Cifratura password asset (`encdec`)

Le password degli asset sono cifrate a riposo tramite il binario [encdec](https://github.com/daniloritarossi/encdec).

### Funzionamento

| Fase | Dettaglio |
|---|---|
| **Prima compilazione** | `start.sh` chiede un prefisso segreto (con conferma), patcha `defaultSecretKeyPrefix` in `lib/lib.go` e compila il binario in `.encdec/encdec` |
| **Avvii successivi** | Binario già presente → nessuna interazione, nessuna password chiesta |
| **Segreto** | Compilato dentro il binario; non esiste su disco né in variabili d'ambiente |
| **Algoritmo** | AES-GCM machine-bound con prefisso applicativo (`ENC`/`DEC`) |
| **Formato in tabella `assets`** | `ENC:<hex-ciphertext>` |

### Flusso encrypt/decrypt

```
UI inserisce password  →  POST /api/assets
                          └─ crypto.encrypt_password()
                             └─ encdec ENC <plain>  →  ENC:<hex>  →  tabella Supabase 'assets'

Login SSH asset        →  scanner._scan_auth_real()
                          └─ crypto.decrypt_password(ENC:<hex>)
                             └─ encdec DEC <hex>  →  password in chiaro  →  paramiko
```

### Modulo `crypto.py`

| Funzione | Comportamento |
|---|---|
| `encrypt_password(plain)` | Chiama `encdec ENC`, prefissa con `ENC:`, ritorna stringa cifrata |
| `decrypt_password(stored)` | Stringa senza `ENC:` → ritornata invariata (retrocompat.); stringa `ENC:` → chiama `encdec DEC` |
| `is_encrypted(val)` | `True` se la stringa inizia con `ENC:` |

> Se la password non è cifrata (testo in chiaro), l'app la segnala con badge arancione **NOT ENCRYPTED** nella pagina Asset Inventory e rifiuta il login SSH in fase di health check.

---

## Macchine di test (Docker)

Il wizard (primo avvio o `./start.sh update` → opzione 3) chiede **quale** macchina di test creare:

```
Quale macchina di test vuoi creare?
  1) Linux   — Ubuntu 20.04 + SSH + Python 3.6 (obsoleto)
  2) Windows — Win 11 (KVM) + Notepad++ 7.8.1 + PuTTY 0.70 (vulnerabili)
  3) Nessuna — salta
```

Entrambe usano credenziali `admin` / `admin` e, a fine setup, offrono lo stesso sottomenu «Aggiungere all'inventario asset?» (cifrate / chiaro / No). L'asset viene inserito nella tabella Supabase `assets` via PostgREST.

### Linux — specifiche

| Parametro | Valore |
|---|---|
| Base image | `ubuntu:20.04` |
| Python | 3.6 (via PPA `deadsnakes` — versione obsoleta intenzionale) |
| SSH | `openssh-server`, `PasswordAuthentication yes`, `PermitRootLogin no` |
| Utente | `admin` / password `admin` (gruppo `sudo`) |
| Container name | `vuln-test-linux-1` |
| Network | Docker bridge (`172.17.0.x`) |

Build idempotente: a ogni esecuzione il wizard riscrive il `Dockerfile`, ricostruisce l'immagine `vuln-test-linux` e rimuove/ricrea il container `vuln-test-linux-1`.

### Ciclo di vita

```bash
# Creazione (via wizard)
./start.sh update   # → opzione 3

# Verifica
ssh admin@172.17.0.2       # password: admin
python3.6 --version         # Python 3.6.x (obsoleto, via deadsnakes)

# Stop e rimozione
./stop.sh                   # rimuove il container automaticamente
```

### Sottomenu «Aggiungere all'inventario asset?»

Dopo l'avvio del container il wizard chiede se aggiungerlo all'inventario, con tre scelte:

| Opzione | Comportamento |
|---|---|
| 1 — credenziali cifrate | Cifra `admin` con `encdec` e salva `ENC:<hex>`. Se il binario `encdec` manca o la cifratura fallisce, avvisa esplicitamente e ripiega su password in chiaro |
| 2 — password in chiaro | Salva `admin` in chiaro (nessun tentativo di cifratura) |
| 3 — No | Non modifica l'inventario |

L'asset e' inserito con `username=admin`, `os_type=linux`.

### Windows — specifiche

Windows non gira come container nativo su un host Docker **Linux**: le immagini Windows native (`mcr.microsoft.com/windows/nanoserver`, `servercore`) hanno solo manifest Windows — `docker pull` fallisce con `no matching manifest for linux/amd64` e girano solo su un host Docker **Windows**. In più `nanoserver` è headless (niente `winget`, niente GUI) → non può ospitare Notepad++/PuTTY.

Per questo il wizard usa **[`dockurr/windows`](https://github.com/dockur/windows)**, che avvia una VM Windows 11 reale tramite **QEMU/KVM** dentro un container Linux. **Richiede `/dev/kvm`**. Se `/dev/kvm` è assente il wizard **non procede** e stampa una guida coerente (vedi sotto). La guida BIOS appare **solo** in questo caso: quando KVM è già attivo non viene mostrata.

#### Prerequisito: virtualizzazione hardware (KVM)

Qualsiasi VM Windows locale — **dockurr/KVM, VirtualBox, VMware, Hyper-V** — richiede la virtualizzazione hardware **VT-x (Intel) / AMD-V «SVM» (AMD)**. Senza, il guest Windows a 64-bit non parte. È lo stesso prerequisito per tutte le soluzioni locali; l'unica eccezione è l'emulazione software QEMU-TCG (vedi alternative).

Verifica e abilitazione:

```bash
ls -l /dev/kvm            # se esiste, KVM è già attivo: nessuna azione
lscpu | grep -i virtual   # mostra "AMD-V" o "VT-x" se la CPU lo espone
sudo modprobe kvm_amd     # carica il modulo (Intel: kvm_intel)
```

| Sintomo | Causa | Azione |
|---|---|---|
| `/dev/kvm` presente | KVM attivo | Nessuna — il wizard procede |
| Nessun flag `svm`/`vmx` in `/proc/cpuinfo` | Virtualizzazione **disabilitata** nel BIOS | Abilitala nel BIOS (sotto) |
| Flag presente ma `modprobe` → `Operation not supported` | SVM/VT-x **bloccato** nel BIOS (flag visibile, funzione lockata) | Abilitala nel BIOS (sotto) |
| `modprobe` ok ma `/dev/kvm` sparisce al riavvio | Modulo non persistente | `echo kvm_amd \| sudo tee /etc/modules-load.d/kvm.conf` |

**Abilitare la virtualizzazione nel BIOS/UEFI** (es. Lenovo Yoga Slim 7, AMD):

1. Riavvio **completo** (non sospensione).
2. All'accensione premi **F2** (o **Fn+F2**); in alternativa pulsante/foro **Novo** → *BIOS Setup*.
3. **Configuration** (o *Advanced*).
4. **SVM Mode** (alias *AMD-V* / *Virtualization* / *VT-x*) → **Enabled**.
5. **F10** → *Save and Exit* → conferma.

Al riavvio, completa e persisti:

```bash
sudo modprobe kvm_amd                                  # (Intel: kvm_intel)
echo "kvm_amd" | sudo tee /etc/modules-load.d/kvm.conf # persiste al riavvio
sudo usermod -aG kvm "$USER"                           # poi logout/login
ls -l /dev/kvm                                          # crw-rw---- root kvm
```

**Alternative senza BIOS** (se non puoi/vuoi toccare il firmware):

- **Emulazione software (QEMU-TCG):** in `docker-test-machine-windows/compose.yml` aggiungi `KVM: "N"` fra le `environment`. Funziona senza `/dev/kvm` ma è **molto lento** (installazione di Windows = ore).
- **Host Windows esterno:** una VM cloud (es. **AWS Free Tier**, Windows Server `t3.micro`, 750 h/mese per 12 mesi) o un PC Windows in LAN. Abiliti OpenSSH + installi Notepad++/PuTTY e aggiungi l'IP all'inventario asset con `os_type = windows`. Nessuna virtualizzazione locale.

| Parametro | Valore |
|---|---|
| Immagine | `dockurr/windows` (VM Windows 11 via KVM) |
| Software vulnerabile | **Notepad++ 7.8.1**, **PuTTY 0.70** (installati al primo boot da `oem/install.bat`) |
| Accesso scansione | **OpenSSH** con shell PowerShell di default (porta guest 22) |
| Utente | `admin` / password `admin` |
| Porte host | `3389` RDP · `2222`→22 SSH · `8006` viewer installazione dockurr |
| Container name | `vuln-test-windows-1` |
| File generati | `docker-test-machine-windows/compose.yml`, `docker-test-machine-windows/oem/install.bat` |

```bash
# Creazione (via wizard) — la prima installazione di Windows richiede minuti
./start.sh update   # → opzione 3 → 2 (Windows)

# Avanzamento installazione
http://localhost:8006        # viewer dockurr

# Stop e rimozione (incluso il container Windows)
./stop.sh
```

> ⚠️ La scansione autenticata Windows funziona **solo a installazione completata** (OpenSSH attivo + Notepad++/PuTTY installati). Gli URL degli installer in `oem/install.bat` puntano a versioni datate volutamente vulnerabili.

#### Attendere il download dell'immagine

Al primo avvio dockurr **scarica la ISO di Windows 11 dai server Microsoft** (diversi GB): a seconda della connessione possono volerci **decine di minuti**. Finché il download e la successiva installazione non sono completi, **la VM non è raggiungibile** e `ssh ...` restituisce `Connection refused`. Bisogna **aspettare** che l'immagine sia scaricata e installata prima di scansionare.

Verifica lo stato di download/installazione:

```bash
docker logs -f vuln-test-windows-1
```

Le fasi nel log si susseguono così:

```
Downloading Windows 11...        ← download ISO (mostra % e ETA, es. "13%  44m16s")
Extracting / Installing...       ← installazione
Booting Windows...               ← primo avvio
oem/install.bat                  ← OpenSSH + Notepad++ 7.8.1 + PuTTY 0.70
```

In alternativa, il **viewer web** mostra l'avanzamento grafico:

```
http://localhost:8006
```

Quando il log raggiunge l'esecuzione di `oem/install.bat` (OpenSSH attivo), l'asset diventa scansionabile:

```bash
ssh admin@localhost -p 2222 "winget list"   # password: admin — deve elencare Notepad++/PuTTY
```

### Logica di scansione Windows

Quando un asset ha `os_type = windows`, il path autenticato (`scanner._scan_auth_real`) esegue via SSH un inventario software con PowerShell invece del comando Linux (`dpkg`):

```powershell
# 1. Programmi standard (Winget)
winget list

# 2. Registro profondo: software a 32 e 64 bit che sfuggono a winget
Get-ItemProperty `
  HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* , `
  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* `
  | Select-Object DisplayName, DisplayVersion
```

L'output (`DisplayName` / `DisplayVersion`) viene confrontato con gli alias del prodotto target (`notepad++` → `notepad++`/`npp`/`notepad plus plus`; `putty` → `putty`); la prima versione `X.Y[.Z]` sulla riga corrispondente diventa la `detected_version`. Metodo riportato nei risultati: `auth-ssh-win`.

> I comandi girano solo se `scanner.simulate_auth: false` in `config.json` (login SSH reale). Con `simulate_auth: true` (default) l'esito è simulato e deterministico, indipendente dall'OS.

---

## Architettura

```
start.sh ──► encdec setup ──► wizard config.json ──► .venv + deps ──► Supabase ──► FastAPI
```

| File | Ruolo |
|------|-------|
| `app.py` | Server FastAPI: routing pagine + API REST + SSE + health check SSH |
| `crypto.py` | Wrapper encdec: cifratura/decifratura password asset |
| `config.py` | Lettura/scrittura `config.json`; defaults embedded |
| `osint.py` | Identifica prodotto e versione dalla descrizione testuale |
| `scanner.py` | Scansione asset: banner grabbing TCP + audit SSH (con decrypt password) |
| `cve.py` | Lookup CVE su OSV.dev + sintesi AI + remediation |
| `posture.py` | SCA per asset: inventario pacchetti + OSV |
| `ingest.py` | Ingestione report scanner esterni (Trivy, Grype, Nuclei, Semgrep, Gitleaks, Trufflehog) |
| `findings.py` | Ciclo di vita finding: dedup per fingerprint, stati workflow, SLA |
| `localscan.py` | Wrapper scanner locali opzionali: gitleaks (secrets), trivy image (vuln+secret) |
| `compliance.py` | Tagging conformità: CWE → OWASP Top 10 2021 / NIS2 art. 21(2) |
| `ticketing.py` | Ticket di remediation da finding: GitHub Issues / Jira Cloud |
| `assets.py` | CRUD inventario asset su Supabase (tabella `assets`) |
| `db.py` | Persistenza Supabase (best-effort) |
| `config.json` | Configurazione runtime (generato dal wizard) |
| `docker-test-machine/Dockerfile` | Immagine Linux vulnerabile per test |

---

## Funzionalità

### 1 · Identificazione prodotto (OSINT)

Data una descrizione testuale (`"Buffer overflow affecting OpenSSH 8.4"`):

1. **Estrazione locale** — regex + dizionario `KNOWN_PRODUCTS`; zero dipendenze di rete.
2. **Fallback web** — query sul search engine configurato (DuckDuckGo o Serper) + matching sul testo.

Output: `TargetInfo` con `product`, `version`, `aliases`, `source`, `candidates`.

### 2 · Scansione asset (SSE in tempo reale)

Per ogni asset dell'inventario:

| Modalità | Cosa fa |
|----------|---------|
| **No-auth** | Banner grabbing TCP reale sulle porte del prodotto |
| **Auth simulato** (default) | Risposta deterministica per demo e test offline |
| **Auth reale** | Login SSH via `paramiko` con password decifrata da `encdec`; solo se `simulate_auth: false`. Inventario **Linux** (`dpkg`) o **Windows** (`winget` + registro Uninstall via PowerShell) in base a `os_type` |

I risultati arrivano alla UI **un asset alla volta** via Server-Sent Events.

**Deep Probe** (checkbox in dashboard → `&deep=true`): solo sul path non autenticato e solo per il prodotto `python`, quando la versione non emerge dal banner. Esegue GET HTTP completi (header + corpo) per dedurre la versione; il risultato è marcato con `method: "deep-probe"`.

### 3 · Lookup CVE e sintesi AI

- **OSV.dev** — query strutturata (senza API key)
- **Sintesi AI** — Ollama o Claude API
- **Remediation** — suggerimenti generati dall'AI
- **Triage report** — report consolidato (lingua: `it` / `en`)

**Pattern RAG** (UI: pannello `RAG · CVE INTELLIGENCE`): gli ID CVE recuperati live da OSV.dev vengono iniettati nel prompt LLM (retrieve → augment → generate), con vincolo anti-allucinazione *«non inventare identificatori non elencati»*. È un RAG architetturale via API, non a embeddings/vector store.

### 4 · Postura di sicurezza (SCA)

SCA per asset: inventario pacchetti → OSV.dev batch → score aggregato (critical / high / medium / low).

### 4-bis · SBOM (`/sbom`)

La pagina SBOM espone i pacchetti raccolti dall'ultima run di postura (SCA). Endpoint `GET /api/sbom` → righe `{asset_ip, package, version, ecosystem, cve_count}`. Se non esiste alcuna run di postura, ritorna `{"rows": []}`.

**Export standard** — `GET /api/sbom/export?format=cyclonedx|spdx` scarica la SBOM in **CycloneDX 1.5** o **SPDX 2.3** (JSON), con purl, CPE, licenze, hash, relazioni di dipendenza e CVE associate. Interoperabile con Dependency-Track e qualunque consumer SBOM standard.

### 4-ter · Findings unificati (`/findings`)

Ciclo di vita ASPM completo dei finding, da qualunque sorgente:

**Ingestione scanner esterni** — `POST /api/findings/import` accetta i report JSON nativi di:

| Tool | Formato | Contenuto |
|------|---------|-----------|
| **Trivy** | `trivy ... -f json` | vulnerabilità pacchetti/immagini + secret nei layer |
| **Grype** | `grype ... -o json` | vulnerabilità pacchetti/immagini |
| **Nuclei** | JSON export o JSONL | finding template-based su host |
| **Semgrep** | `semgrep --json` | finding SAST su codice |
| **Gitleaks** | `gitleaks detect -f json` | secret hardcoded in repo/directory |
| **Trufflehog** | `trufflehog ... --json` | secret (CRITICAL se verificata live) |

Il formato è riconosciuto automaticamente (`tool=auto`) o forzabile; `asset_ip` opzionale attribuisce i finding a un asset dell'inventario. Upload anche da UI (pannello IMPORT). I valori delle secret rilevate **non** vengono mai persistiti nel finding.

**Scan locale** (`POST /api/findings/scan-local`, pannello LOCAL SCAN) — se i binari sono installati sul server esegue lo scanner e ne ingerisce il report:

| Tipo | Tool | Target |
|------|------|--------|
| `secrets` | gitleaks | directory/repo locale |
| `image` | trivy (`--scanners vuln,secret`) | immagine container |

Se il binario manca, l'endpoint torna 400 con le istruzioni di installazione (nessuna dipendenza dura).

**Compliance tagging** — ogni finding riceve i riferimenti di conformità, calcolati a runtime: **CWE** (dai metadati del report), **OWASP Top 10 2021** (A01–A10, dalla mappa CWE o euristica su sorgente) e **NIS2** (misure minime dell'art. 21(2) della direttiva UE 2022/2555). La pagina `/findings` aggrega i finding aperti per voce OWASP e per misura NIS2 (barre).

**Ticketing** — `POST /api/findings/{id}/ticket` crea un ticket di remediation su **GitHub Issues** o **Jira Cloud** (provider e credenziali in Settings → sezione TICKETING) e ne salva il riferimento sul finding (colonna TICKET → link). Titolo, severità, asset, CVE, SLA e fingerprint nel corpo del ticket.

**Dedup per fingerprint** — identità stabile calcolata su (asset, pacchetto, CVE primaria) — o location per i finding senza CVE. La sorgente NON fa parte della chiave: lo stesso difetto riportato da Trivy **e** Grype è un solo finding (source `trivy+grype`, `times_seen` incrementato). Anche i finding della postura interna (SCA) confluiscono automaticamente nello stesso ciclo di vita a ogni run.

**Stati di workflow** — `open → triaged → accepted | fixed` (transizioni libere via `PATCH /api/findings/{id}/status`, cambio inline in UI). Un finding `fixed` che riappare in un report successivo viene **riaperto automaticamente** (`reopened` incrementato). I finding di postura non più osservati nell'ultima run dell'asset vengono **auto-chiusi** (`fixed`).

**SLA di remediation** — scadenza calcolata alla prima osservazione in base alla severità (default: critical 7g, high 30g, medium 90g, low 180g; configurabile in `config.json`, sezione `sla`). Badge `BREACHED` in UI se oltre scadenza e non fixed/accepted.

La pagina `/findings` mostra KPI (aperti, SLA violate, triage, accettati, risolti), filtri per stato/severità/sorgente/testo e tabella con cambio stato inline.

### 5 · Gestione asset (`/assets`)

CRUD completo con:

- **Cifratura automatica** — password cifrata con `encdec` alla creazione/modifica; mai esposta in chiaro nelle API
- **Badge NOT ENCRYPTED** — avviso arancione se password in chiaro (formato legacy)
- **Health check avanzato** — colonna ACTIVE con 4 stati:

| Badge | Condizione |
|---|---|
| 🔴 NOT AVAILABLE | Host non raggiungibile TCP |
| 🟢 AVAILABLE | Raggiungibile, nessuna credenziale |
| 🟢 SSH OK | Raggiungibile + login SSH riuscito (password decifrata) |
| 🟠 SSH FAIL | Raggiungibile + login SSH fallito o password non cifrata |

- Il login SSH in health check usa la password decifrata via `encdec`; se la password non è cifrata (`ENC:` mancante) l'esito è automaticamente SSH FAIL

### 6 · Dashboard (`/`)

Layout (dall'alto verso il basso):

1. **KPI cards** — Verified Assets, Active Vulnerabilities, Security Posture Score
2. **THREAT INTELLIGENCE QUERY** + **SCAN_ENGINE_TTY1** (console output real-time)
3. **DETECTED PRODUCTS NETWORK** (grafo) + **ASSET AUTHENTICATION** (barre stato)
4. Progress bar scansione + risultati

#### DETECTED PRODUCTS NETWORK

Grafo SVG che mappa il prodotto identificato (nodo centrale cyan) e le sue dipendenze note (`PRODUCT_DEPENDENCIES` in `osint.py`), con archi radiali prodotto→dipendenza e archi tratteggiati fra librerie correlate (`DEP_RELATIONS`).

| Stato | Visuale |
|---|---|
| Idle (nessuna scansione) | Demo a rotazione: il grafo cambia prodotto ogni 3 s con badge `LIVE DEMO` |
| Scansione in corso | **Loader** in stile grafo: nodo centrale con spinner, anelli rotanti, nodi placeholder pulsanti; legenda con skeleton shimmer |
| Scansione completata | Grafo reale del prodotto rilevato + legenda con dipendenze e conteggio link inter-dipendenza |

#### ASSET AUTHENTICATION

Pannello con 4 barre orizzontali aggiornate in tempo reale tramite health check:

| Barra | Colore | Conta |
|---|---|---|
| NOT AVAILABLE | Rosso | Host non raggiungibili |
| AVAILABLE | Verde | Raggiungibili senza credenziali |
| SSH OK | Cyan | Login SSH verificato |
| SSH FAIL | Arancione | Raggiungibili ma login fallito |

Spinner `CHECKING…` attivo durante i check; contatori si aggiornano asset per asset.

#### IDENTIFICATION PIPELINE

3 step collegati agli eventi SSE reali della scansione:

| Step | Attiva su | Completa su |
|---|---|---|
| Parsing Input | Avvio scan | Evento `target` |
| OSINT Correlation | Evento `target` | Primo evento `result` |
| Active Detection | Primo `result` | Evento `done` |

Stati visivi: `idle` (grigio) → `running` (cyan pulsante) → `done` (verde ✓) → `error` (rosso).

### 7 · Pagine dell'interfaccia

| Percorso | Contenuto |
|----------|-----------|
| `/` | Dashboard: scan, console, grafo prodotti, postura |
| `/assets` | Gestione inventario asset con cifratura password e health check SSH |
| `/audit` | Storico scansioni salvate su Supabase |
| `/findings` | Finding unificati: import report scanner esterni, dedup, stati workflow, SLA |
| `/sbom` | SBOM: pacchetti rilevati dall'ultima scansione di postura (SCA), con conteggio CVE per pacchetto; export CycloneDX 1.5 / SPDX 2.3 |
| `/intel` | Ricerca OSINT manuale su un prodotto/versione |
| `/settings` | Configurazione AI e search engine via UI |

---

## Configurazione (`config.json`)

```jsonc
{
  "ai": {
    "provider": "ollama",           // "ollama" | "claude"
    "ollama_url": "http://localhost:11434/api/generate",
    "ollama_model": "qwen2.5:7b",
    "claude_api_key": "",
    "claude_model": "claude-haiku-4-5-20251001",
    "ai_remediation": false
  },
  "search_engine": {
    "provider": "duckduckgo",       // "duckduckgo" | "serper"
    "serper_api_key": "",
    "min_osint_hits": 2,
    "min_osint_query": 4
  },
  "scanner": {
    "simulate_auth": true,          // false = SSH reale
    "socket_timeout": 4
  },
  "osv": {
    "url": "https://api.osv.dev/v1/query",
    "timeout": 15
  },
  "sla": {                          // giorni di SLA remediation per severità
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "unknown": 90
  },
  "ticketing": {                    // ticket di remediation dai finding
    "provider": "",                 // "github" | "jira" | "" (disabilitato)
    "github_token": "",
    "github_repo": "",              // "owner/repo"
    "jira_url": "",                 // "https://org.atlassian.net"
    "jira_email": "",
    "jira_api_token": "",
    "jira_project_key": ""
  }
}
```

---

## Inventario asset (tabella Supabase `assets`)

L'inventario vive nella tabella `public.assets` (Supabase locale). Colonne:
`ip`, `username`, `password` (cifrata `ENC:<hex>`), `os_type` (`linux`/`windows`),
`os_major_version`, `enabled`.

- Password in chiaro → badge ⚠️ NOT ENCRYPTED; health check SSH FAIL
- Password `ENC:<hex>` → cifrata con encdec; health check esegue login reale

**Migrazione dal legacy `assets.txt`**: alla prima lettura, se la tabella e'
vuota e `assets.txt` esiste, il file viene importato automaticamente e
rinominato in `assets.txt.migrated` (backup).

---

## Persistenza Supabase (locale, Docker)

Stack: Postgres + PostgREST + Studio + nginx. Dati in `supabase/volumes/db/data`.

| Servizio | URL |
|----------|-----|
| Studio GUI | http://localhost:3001 |
| REST API | http://localhost:8001/rest/v1/ |
| Postgres | localhost:5432 |

Schema:
- `scans` — una riga per scansione (prodotto, versione, CVE summary)
- `scan_results` — una riga per asset (ip, method, vuln\_match, cve\_count, cve\_ids)
- `posture_runs` / `posture_assets` / `posture_findings` / `posture_components` — Full Posture (SCA) + SBOM
- `findings` — finding unificati: fingerprint (dedup), source, severity, cve\_ids, cwe\_ids, status, SLA, contatori riaperture/osservazioni, ticket\_ref/ticket\_url

Override env: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `SUPABASE_PERSIST=0`.

> ⚠️ Le chiavi in `supabase/.env` sono demo, solo per ambiente locale.

---

## Sicurezza

- **Password a riposo** — cifrate AES-GCM con prefisso segreto compilato nel binario `encdec`; mai in chiaro su disco
- **SSH host key** — `RejectPolicy` (nessun auto-accept)
- **simulate_auth: true** (default) — nessun login SSH eseguito in fase di scan
- **Health check SSH** — login reale solo se password cifrata (`ENC:`); plain text → SSH FAIL automatico
- **API password** — endpoint `/api/assets/all` non espone mai la password; ritorna solo `has_password` (bool) e `password_encrypted` (bool)
- **Token ticketing** — `github_token` e `jira_api_token` mascherati (`••••`) da `GET /api/settings`; il placeholder inviato dal frontend preserva il valore salvato
- **Secrets scanning** — i valori delle secret rilevate (gitleaks/trufflehog/trivy) non vengono mai persistiti nel finding: solo regola, percorso e metadati non sensibili

---

## Esempi di input

| Input | Prodotto identificato |
|-------|-----------------------|
| `Remote Code Execution in Python 3.10 via HTTP` | python 3.10 |
| `Buffer overflow affecting OpenSSH 8.4` | openssh 8.4 |
| `Critical vuln in nginx 1.21 HTTP/2 module` | nginx 1.21 |
| `Log4Shell — Apache Log4j 2.14.1` | log4j 2.14.1 |
| `Stack overflow in Notepad++ 7.8.1` | notepad++ 7.8.1 |
| `PuTTY 0.70 SSH host key vulnerability` | putty 0.70 |
