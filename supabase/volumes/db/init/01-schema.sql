-- Schema del Vulnerability Feed Aggregator.
-- Applicato in modo idempotente da setup.sh dopo l'avvio del DB.
--
-- Due tabelle:
--   scans         -> una riga per esecuzione di scansione (target + sintesi CVE)
--   scan_results  -> una riga per asset scansionato, con esito + CVE rilevate

-- 1) Ruoli (anon/authenticated/service_role/authenticator) sono gia' forniti
--    dall'immagine supabase/postgres e sono riservati: non li tocchiamo qui.
--    authenticator accede con POSTGRES_PASSWORD (vedi PGRST_DB_URI nel compose).

-- 2) Tabelle.
CREATE TABLE IF NOT EXISTS public.scans (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at    timestamptz NOT NULL DEFAULT now(),
  description   text,                 -- testo vulnerabilita' in input
  product       text,                 -- prodotto canonico identificato
  version       text,                 -- versione target
  matched_alias text,                 -- alias trovato nel testo
  source        text,                 -- local | osint | none
  candidates    jsonb DEFAULT '[]'::jsonb,
  dependencies  jsonb DEFAULT '[]'::jsonb,
  cve_count     integer,              -- conteggio CVE ufficiale (OSV)
  cve_ids       jsonb DEFAULT '[]'::jsonb,
  cve_summary   text,                 -- sintesi LLM locale
  cve_error     text
);

CREATE TABLE IF NOT EXISTS public.scan_results (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id          bigint REFERENCES public.scans(id) ON DELETE CASCADE,
  created_at       timestamptz NOT NULL DEFAULT now(),
  ip               text NOT NULL,
  auth_required    boolean,
  method           text,              -- banner-grab | auth-sim | auth-ssh
  product_found    boolean,
  detected_version text,
  raw_evidence     text,
  vuln_match       text,              -- VULNERABILE | NON VULNERABILE | INCERTO
  cve_count        integer,
  cve_ids          jsonb DEFAULT '[]'::jsonb,
  cve_error        text
);

-- Advisory AI (vulnerabilita' SENZA CVE): versione affetta dedotta dall'LLM e
-- base del verdetto. Tenute DISTINTE dai campi CVE (cve_count/cve_ids).
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS affected_version text,   -- vincolo AI (es. '<2.5.0')
  ADD COLUMN IF NOT EXISTS affected_source  text;   -- 'input' | 'ai' | null
ALTER TABLE public.scan_results
  ADD COLUMN IF NOT EXISTS affected_version  text,   -- vincolo valutato per l'asset
  ADD COLUMN IF NOT EXISTS match_basis       text,   -- 'input-version'|'ai-advisory'|'none'
  ADD COLUMN IF NOT EXISTS os_type           text,   -- 'linux' | 'windows' (da inventario)
  ADD COLUMN IF NOT EXISTS os_major_version  text;   -- es. '22.04', '10', '2019'

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON public.scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip      ON public.scan_results(ip);

-- 3) Permessi (locale: nessuna RLS; service_role bypassa comunque).
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;

-- 4b) INVENTARIO ASSET: sostituisce assets.txt. Una riga per asset.
--     La password e' memorizzata cifrata (prefisso 'ENC:', vedi crypto.py).
CREATE TABLE IF NOT EXISTS public.assets (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  ip               text NOT NULL,        -- IP o hostname
  username         text NOT NULL DEFAULT '',
  password         text NOT NULL DEFAULT '',  -- 'ENC:<hex>' oppure vuota
  os_type          text NOT NULL DEFAULT '',  -- 'linux' | 'windows' | ''
  os_major_version text NOT NULL DEFAULT '',  -- es. '22.04', '10', '2019'
  enabled          boolean NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON public.assets(ip);

-- Contesto business dell'asset (capability ASPM: prioritizzazione contestuale).
-- Pesano il risk score: un critical su asset prod internet-facing conta di piu'.
ALTER TABLE public.assets
  ADD COLUMN IF NOT EXISTS environment     text    NOT NULL DEFAULT 'unknown', -- prod|staging|dev|unknown
  ADD COLUMN IF NOT EXISTS internet_facing boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS criticality     integer NOT NULL DEFAULT 3;          -- 1 (basso) .. 5 (alto)

-- 5) FULL POSTURE (SCA): run manuale -> asset -> finding per pacchetto.
CREATE TABLE IF NOT EXISTS public.posture_runs (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at      timestamptz NOT NULL DEFAULT now(),
  assets_scanned  integer,
  total_packages  integer,
  total_vulnerable integer,
  total_vulns     integer,
  avg_score       integer
);

CREATE TABLE IF NOT EXISTS public.posture_assets (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id              bigint REFERENCES public.posture_runs(id) ON DELETE CASCADE,
  created_at          timestamptz NOT NULL DEFAULT now(),
  ip                  text NOT NULL,
  os_guess            text,
  method              text,            -- 'ssh' | 'sim'
  total_packages      integer,
  vulnerable_packages integer,
  total_vulns         integer,
  score               integer,
  sev_critical        integer,
  sev_high            integer,
  sev_medium          integer,
  sev_low             integer,
  sev_unknown         integer,
  os_type             text,    -- 'linux' | 'windows' (da inventario asset)
  os_major_version    text     -- es. '22.04', '10', '2019'
);

CREATE TABLE IF NOT EXISTS public.posture_findings (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id     bigint REFERENCES public.posture_assets(id) ON DELETE CASCADE,
  package      text NOT NULL,
  version      text,
  ecosystem    text,
  category     text,
  vuln_count   integer,
  max_severity text,
  cve_ids      jsonb DEFAULT '[]'::jsonb
);

ALTER TABLE public.posture_assets
  ADD COLUMN IF NOT EXISTS os_type          text,
  ADD COLUMN IF NOT EXISTS os_major_version text;

-- Inventario software COMPLETO per asset (SBOM): tutti i pacchetti installati,
-- non solo i vulnerabili. Arricchito con identificatori e metadati SBOM.
CREATE TABLE IF NOT EXISTS public.posture_components (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id     bigint REFERENCES public.posture_assets(id) ON DELETE CASCADE,
  package      text NOT NULL,
  version      text,
  ecosystem    text,
  category     text,
  purl         text,      -- Package URL (spec purl)
  cpe          text,      -- CPE 2.3 (best-effort)
  license      text,      -- SPDX id o NOASSERTION
  supplier     text,      -- fornitore o NOASSERTION
  sha256       text,      -- digest coordinate (identita' deterministica)
  vuln_count   integer DEFAULT 0,
  max_severity text,
  cve_ids      jsonb DEFAULT '[]'::jsonb,
  depends_on   jsonb DEFAULT '[]'::jsonb   -- nomi pacchetti dipendenti (relazioni)
);

CREATE INDEX IF NOT EXISTS idx_posture_assets_run    ON public.posture_assets(run_id);
CREATE INDEX IF NOT EXISTS idx_posture_findings_asset ON public.posture_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_posture_components_asset ON public.posture_components(asset_id);

-- Permessi anche sulle nuove tabelle.
GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- 6) FINDINGS UNIFICATI (ciclo di vita ASPM): dedup per fingerprint, stati di
--    workflow (open|triaged|accepted|fixed) e SLA di remediation.
--    Alimentata dalla postura interna (SCA) e dai report di scanner esterni
--    ingeriti via /api/findings/import (Trivy, Grype, Nuclei, Semgrep).
CREATE TABLE IF NOT EXISTS public.findings (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  fingerprint       text NOT NULL UNIQUE,   -- identita' stabile (dedup cross-tool)
  source            text NOT NULL,          -- posture|trivy|grype|nuclei|semgrep (o 'a+b')
  asset_ip          text,
  title             text,
  package           text,
  version           text,
  ecosystem         text,
  location          text,                   -- target/percorso/URL del finding
  severity          text,                   -- CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
  cve_ids           jsonb DEFAULT '[]'::jsonb,
  detail            text,
  status            text NOT NULL DEFAULT 'open',  -- open|triaged|accepted|fixed
  status_note       text DEFAULT '',
  status_changed_at timestamptz DEFAULT now(),
  first_seen        timestamptz NOT NULL DEFAULT now(),
  last_seen         timestamptz NOT NULL DEFAULT now(),
  times_seen        integer NOT NULL DEFAULT 1,    -- osservazioni (report che lo confermano)
  reopened          integer NOT NULL DEFAULT 0,    -- riaperture automatiche post-fixed
  sla_due           timestamptz                    -- scadenza remediation per severita'
);

-- Compliance tagging (CWE dai report; OWASP/NIS2 derivati a runtime) e
-- riferimento al ticket di remediation (GitHub Issue / Jira).
ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS cwe_ids    jsonb DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS ticket_ref text,   -- '#42' | 'SEC-101'
  ADD COLUMN IF NOT EXISTS ticket_url text;

CREATE INDEX IF NOT EXISTS idx_findings_status   ON public.findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_asset_ip ON public.findings(asset_ip);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON public.findings(severity);

GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- 7) Ricarica la cache schema di PostgREST.
NOTIFY pgrst, 'reload schema';
