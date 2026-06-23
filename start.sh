#!/usr/bin/env bash
# Vulnerability Feed Aggregator — avvio + configurazione
#
# Uso:
#   ./start.sh                 primo avvio: wizard, poi lancia
#   ./start.sh                 avvio normale se config.json esiste
#   ./start.sh update          modifica configurazione esistente via CLI
#   ./start.sh --no-supabase   salta Supabase (qualunque altro arg combinabile)
#   PORT=9000 ./start.sh       porta diversa per FastAPI
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8000}"
WITH_SUPABASE=1
MODE="normal"
LAUNCH_APP=1
CONFIG_FILE="config.json"

for _arg in "$@"; do
  case "$_arg" in
    update)        MODE="update"   ;;
    --no-supabase) WITH_SUPABASE=0 ;;
  esac
done

# ── UI helpers ────────────────────────────────────────────────────────────────

_ask() {
  # _ask "Prompt" "default" → stampa la risposta su stdout
  printf "  %s [%s]: " "$1" "$2" >&2
  read -r _ans
  printf '%s' "${_ans:-$2}"
}

_ask_secret() {
  printf "  %s: " "$1" >&2
  read -rs _secret
  printf '\n' >&2
  printf '%s' "$_secret"
}

_choose() {
  # _choose "Titolo" opt1 opt2 ... → stampa numero scelto (1-based) su stdout
  local _title="$1"; shift
  local _opts=("$@")
  printf '\n' >&2
  printf '  %s\n' "$_title" >&2
  local _i=1
  for _o in "${_opts[@]}"; do
    printf '    %d) %s\n' "$_i" "$_o" >&2
    ((_i++))
  done
  while true; do
    printf '  Scelta [1]: ' >&2
    read -r _sel
    _sel="${_sel:-1}"
    if [[ "$_sel" =~ ^[0-9]+$ ]] && [ "$_sel" -ge 1 ] && [ "$_sel" -le "${#_opts[@]}" ]; then
      printf '%s' "$_sel"
      return
    fi
    printf '  Scelta non valida.\n' >&2
  done
}

_sep() { printf '\n  %-44s\n' "── $1 " | tr ' ' '─' | head -c 48; printf '\n' >&2; }

# ── JSON helpers (python3 di sistema, non serve il venv) ──────────────────────

_json_read() {
  # _json_read section key
  python3 -c "
import json, pathlib
d = {}
p = pathlib.Path('$CONFIG_FILE')
if p.exists():
    try: d = json.loads(p.read_text())
    except Exception: pass
print(d.get('$1', {}).get('$2', ''))
"
}

_json_write() {
  # _json_write section.key=value ...
  python3 - "$@" <<'PYEOF'
import json, sys, pathlib

CONFIG = pathlib.Path("config.json")
DEFAULTS = {
    "search_engine": {
        "provider": "duckduckgo", "serper_api_key": "",
        "min_osint_hits": 2, "min_osint_query": 4,
    },
    "ai": {
        "provider": "ollama",
        "ollama_url": "http://localhost:11434/api/generate",
        "ollama_model": "qwen2.5:7b",
        "claude_api_key": "", "claude_model": "claude-haiku-4-5-20251001",
        "summary_timeout": 60, "advisory_timeout": 60,
        "extract_timeout": 30, "remediation_timeout": 30,
        "triage_timeout": 60, "ai_remediation": False,
    },
    "scanner": {"simulate_auth": True, "socket_timeout": 4},
    "osv": {"url": "https://api.osv.dev/v1/query", "timeout": 15},
}
data = {k: dict(v) for k, v in DEFAULTS.items()}
if CONFIG.exists():
    try:
        raw = json.loads(CONFIG.read_text())
        for sec in DEFAULTS:
            data[sec].update(raw.get(sec, {}))
    except Exception:
        pass

for arg in sys.argv[1:]:
    sec, rest = arg.split(".", 1)
    key, val  = rest.split("=", 1)
    if val.lower() in ("true", "false"):
        val = val.lower() == "true"
    else:
        try:    val = int(val)
        except ValueError:
            try: val = float(val)
            except ValueError: pass
    data[sec][key] = val

CONFIG.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF
}

# ── Wizard: AI ────────────────────────────────────────────────────────────────

_wizard_ai() {
  _sep "Configurazione AI" >&2
  local _c
  _c=$(_choose "Tipo modello AI:" \
    "Locale — Ollama (modello gira sulla tua macchina)" \
    "Remoto — Claude API (Anthropic, richiede API key)")

  if [ "$_c" = "1" ]; then
    local _url _model
    _url=$(_ask   "Ollama URL"     "http://localhost:11434/api/generate")
    _model=$(_ask "Modello Ollama" "qwen2.5:7b")
    _json_write "ai.provider=ollama" "ai.ollama_url=$_url" "ai.ollama_model=$_model"
    printf '  ✓  Provider: Ollama (%s)\n' "$_model" >&2
    # verifica raggiungibilità
    local _base="${_url%/api/generate}"
    if curl -sf --max-time 3 "$_base" >/dev/null 2>&1; then
      printf '  ✓  Ollama raggiungibile.\n' >&2
      if command -v ollama >/dev/null 2>&1; then
        printf '  ==> ollama pull %s\n' "$_model" >&2
        ollama pull "$_model" >&2 2>/dev/null \
          || printf '  ⚠  pull fallito — esegui manualmente: ollama pull %s\n' "$_model" >&2
      fi
    else
      printf '  ⚠  Ollama non raggiungibile a %s\n     Assicurati che sia avviato prima di usare le funzioni AI.\n' "$_base" >&2
    fi
  else
    local _key _model
    _key=$(_ask_secret "Claude API Key")
    _model=$(_ask "Modello Claude" "claude-haiku-4-5-20251001")
    _json_write "ai.provider=claude" "ai.claude_api_key=$_key" "ai.claude_model=$_model"
    printf '  ✓  Provider: Claude API (%s)\n' "$_model" >&2
  fi
}

# ── Wizard: Search Engine ─────────────────────────────────────────────────────

_wizard_search() {
  _sep "Configurazione Search Engine" >&2
  local _c
  _c=$(_choose "Search engine OSINT:" \
    "DuckDuckGo — gratuito, nessuna API key" \
    "Serper     — risultati Google, richiede API key")

  if [ "$_c" = "1" ]; then
    _json_write "search_engine.provider=duckduckgo"
    printf '  ✓  Search engine: DuckDuckGo\n' >&2
  else
    local _key
    _key=$(_ask_secret "Serper API Key")
    _json_write "search_engine.provider=serper" "search_engine.serper_api_key=$_key"
    printf '  ✓  Search engine: Serper\n' >&2
  fi
}

# ── Wizard: macchina Linux Docker di test ────────────────────────────────────

_wizard_test_machine() {
  _sep "Macchina Linux di test (Docker)" >&2

  if ! docker info >/dev/null 2>&1; then
    printf '  ⚠  Docker non in esecuzione — wizard saltato.\n' >&2
    return
  fi

  local _c
  _c=$(_choose "Creare macchina Linux Docker con SSH + Python 3.6 (obsoleto)?" \
    "Si — build e avvia container di test" \
    "No — salta")
  [ "$_c" = "2" ] && return

  local _dir="$PWD/docker-test-machine"
  mkdir -p "$_dir"

  cat > "$_dir/Dockerfile" << 'DOCKEREOF'
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server sudo software-properties-common gnupg && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y python3.6 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash admin && \
    echo 'admin:admin' | chpasswd && \
    adduser admin sudo

RUN mkdir /var/run/sshd && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
DOCKEREOF

  printf '\n  ==> build immagine vuln-test-linux (ubuntu:20.04 + python3.6 + sshd)...\n' >&2
  docker build -t vuln-test-linux "$_dir" >&2 || {
    printf '  ERRORE: build immagine fallita.\n' >&2; return
  }

  docker rm -f vuln-test-linux-1 >/dev/null 2>&1 || true

  printf '  ==> avvio container vuln-test-linux-1...\n' >&2
  docker run -d --name vuln-test-linux-1 vuln-test-linux >/dev/null || {
    printf '  ERRORE: avvio container fallito.\n' >&2; return
  }

  sleep 1
  local _ip
  _ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vuln-test-linux-1 2>/dev/null)

  printf '\n  ✓  Container avviato\n' >&2
  printf '     IP  : %s\n' "$_ip" >&2
  printf '     SSH : ssh admin@%s  (password: admin)\n' "$_ip" >&2
  printf '     Test: ssh admin@%s python3.6 --version\n\n' "$_ip" >&2

  if [ -n "$_ip" ]; then
    local _add
    _add=$(_choose "Aggiungere a assets.txt?" \
      "Si — aggiungi con credenziali cifrate" \
      "No")
    if [ "$_add" = "1" ]; then
      local _stored_pw="admin"
      if [ -x "${ENCDEC_BIN:-}" ] && [ -n "${ENCDEC_PASS:-}" ]; then
        local _enc
        _enc=$("$ENCDEC_BIN" ENC "admin" 2>/dev/null | sed 's/^encrypted : //')
        [ -n "$_enc" ] && _stored_pw="ENC:$_enc"
      fi
      printf '%s|admin|%s|linux|\n' "$_ip" "$_stored_pw" >> assets.txt
      printf '  ✓  Aggiunto a assets.txt: %s\n' "$_ip" >&2
    fi
  fi
}

# ── Update menu ───────────────────────────────────────────────────────────────

_update_menu() {
  while true; do
    _sep "Modifica Configurazione" >&2
    local _ai _se
    _ai=$(_json_read ai provider)
    _se=$(_json_read search_engine provider)
    printf '  AI attuale    : %s\n' "$_ai" >&2
    printf '  Search attuale: %s\n\n' "$_se" >&2

    local _c
    _c=$(_choose "Cosa vuoi modificare?" \
      "AI provider (locale/remoto)" \
      "Search engine (DuckDuckGo/Serper)" \
      "Macchina Linux Docker di test" \
      "Salva ed esci (solo configurazione, non lancia)" \
      "Salva e lancia l'app")
    case "$_c" in
      1) _wizard_ai           ;;
      2) _wizard_search        ;;
      3) _wizard_test_machine  ;;
      4) LAUNCH_APP=0; break  ;;
      5) break                ;;
    esac
  done
}

# ── encdec: setup cifratura password ─────────────────────────────────────────
# Il segreto viene chiesto UNA SOLA VOLTA, compilato dentro il binario tramite
# patch di defaultSecretKeyPrefix in lib/lib.go, poi nessun file o env var lo
# contiene — il segreto esiste solo nel binario .encdec/encdec.

ENCDEC_BIN="$PWD/.encdec/encdec"
ENCDEC_DIR="$PWD/.encdec"

if [ ! -x "$ENCDEC_BIN" ]; then
  printf '\n'
  printf '  ╔══════════════════════════════════════════════╗\n'
  printf '  ║   encdec — setup cifratura password          ║\n'
  printf '  ╚══════════════════════════════════════════════╝\n'
  printf '\n  Binario encdec non presente. Operazione unica: compilazione.\n'
  printf '  Il prefisso segreto verra'"'"' compilato nel binario e non\n'
  printf '  sara'"'"' mai piu'"'"' richiesto ne'"'"' salvato su disco.\n\n'

  if ! command -v go >/dev/null 2>&1; then
    printf '  ERRORE: Go non trovato. Installa Go >= 1.21 e riprova.\n' >&2
    exit 1
  fi

  _PFX1=$(_ask_secret "Prefisso segreto per cifratura (inserito una sola volta)")
  _PFX2=$(_ask_secret "Conferma prefisso segreto")
  if [ "$_PFX1" != "$_PFX2" ]; then
    printf '\n  ERRORE: I prefissi non corrispondono.\n' >&2
    unset _PFX1 _PFX2
    exit 1
  fi

  mkdir -p "$ENCDEC_DIR"
  _TMP_ENCDEC=$(mktemp -d)

  printf '\n  ==> clone encdec...\n' >&2
  git clone --depth 1 https://github.com/daniloritarossi/encdec "$_TMP_ENCDEC/encdec" >&2

  # Patch: sostituisce defaultSecretKeyPrefix con il segreto scelto
  python3 - "$_TMP_ENCDEC/encdec/lib/lib.go" "$_PFX1" << 'PYEOF'
import sys, re
path, secret = sys.argv[1], sys.argv[2]
src = open(path).read()
src = re.sub(
    r'(defaultSecretKeyPrefix\s*=\s*)"[^"]*"',
    lambda m: m.group(1) + '"' + secret.replace('\\', '\\\\').replace('"', '\\"') + '"',
    src
)
open(path, 'w').write(src)
PYEOF
  unset _PFX1 _PFX2

  printf '  ==> build encdec (prefisso segreto compilato)...\n' >&2
  ( cd "$_TMP_ENCDEC/encdec" && go build -o "$ENCDEC_BIN" . ) >&2
  rm -rf "$_TMP_ENCDEC"
  printf '  ✓  encdec compilato con segreto integrato: %s\n\n' "$ENCDEC_BIN" >&2
fi

# ── MAIN: config phase ────────────────────────────────────────────────────────

if [ "$MODE" = "update" ]; then
  if [ ! -f "$CONFIG_FILE" ]; then
    printf '\n  Nessun config.json. Avvio wizard primo configurazione...\n\n' >&2
    _wizard_ai
    _wizard_search
    _wizard_test_machine
  else
    _update_menu
  fi
elif [ ! -f "$CONFIG_FILE" ]; then
  printf '\n'
  printf '  ╔══════════════════════════════════════════╗\n'
  printf '  ║  Vulnerability Feed Aggregator — Setup   ║\n'
  printf '  ╚══════════════════════════════════════════╝\n'
  printf '\n  Prima configurazione. Invio = valore di default.\n'
  _wizard_ai
  _wizard_search
  _wizard_test_machine
  printf '\n  ✓ config.json creato.\n\n'
fi

[ "$LAUNCH_APP" = "0" ] && exit 0

# ── 1) Virtualenv + dipendenze ────────────────────────────────────────────────

PYBIN=".venv/bin/python"
if [ ! -x "$PYBIN" ]; then
  echo "==> creo virtualenv .venv"
  python3 -m venv .venv
fi
export PATH="$PWD/.venv/bin:$PATH"
echo "==> installo/aggiorno dipendenze (requirements.txt)"
"$PYBIN" -m pip install -q --upgrade pip
"$PYBIN" -m pip install -q -r requirements.txt

# ── 2) Stack Supabase (Docker) ────────────────────────────────────────────────

if [ "$WITH_SUPABASE" = "1" ]; then
  if ! docker info >/dev/null 2>&1; then
    echo "ERRORE: Docker non in esecuzione. Avvia Docker e riprova." >&2
    exit 1
  fi
  echo "==> avvio Supabase locale (Docker)"
  ( cd supabase && ./setup.sh )
else
  echo "==> salto Supabase (--no-supabase)"
fi

# ── 3) Server FastAPI (foreground) ────────────────────────────────────────────

AI_PROV=$(_json_read ai provider)
SE_PROV=$(_json_read search_engine provider)

cat <<EOF

============================================================
  App        : http://127.0.0.1:${PORT}
  Studio GUI : http://localhost:3001
  REST API   : http://localhost:8001/rest/v1/
  AI         : ${AI_PROV}
  Search     : ${SE_PROV}
============================================================
  Ctrl+C ferma l'app. Supabase resta attivo → ./stop.sh

EOF

# Niente --reload: uvicorn entrerebbe in supabase/volumes/db/data (uid 100,
# perms 700) e crasherebbe con PermissionError.
exec "$PYBIN" -m uvicorn app:app --host 127.0.0.1 --port "${PORT}"
