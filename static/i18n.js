/*
 * i18n.js — lightweight client-side internationalization.
 *
 * Base language: English ('en'). Italian ('it') available via the topbar switch.
 *
 * Usage in HTML (static text):
 *   <span data-i18n="key">English fallback</span>          -> sets innerHTML
 *   <input data-i18n-ph="key">                              -> sets placeholder
 *   <el data-i18n-title="key">                              -> sets title
 *
 * Usage in JS (dynamic text):
 *   t('key')                 -> translated string
 *   t('key', {n: 5})         -> with {n} interpolation
 *
 * Re-render on language change: listen for window 'langchange'.
 * The chosen language is persisted in localStorage ('lang').
 */
(function () {
  const DICT = {
    en: {
      // common
      'common.reload': 'RELOAD',
      'common.disabled': 'DISABLED',
      'common.authenticated': 'AUTHENTICATED',
      'common.not_required': 'NOT REQUIRED',
      'common.auth': 'AUTH',
      'common.noauth': 'NO-AUTH',
      'common.yes': 'yes',
      'common.no': 'no',
      'common.na': 'N/A',
      'common.none': 'none',
      'common.save': 'SAVE',
      'common.cancel': 'CANCEL',
      'common.edit': 'EDIT',
      'common.delete': 'DELETE',
      // topbar
      'top.status_active': 'SYSTEM_ACTIVE',
      'top.asset_registry': 'ASSET_REGISTRY',
      'top.audit_ledger': 'AUDIT_LEDGER',
      'top.intel_center': 'POSTURE_CENTER',
      'intel.header': 'Application Security Posture',
      'intel.subtitle': 'Full software-composition posture per asset — installed packages vs OSV.',
      'intel.run_btn': 'RUN FULL POSTURE SCAN',
      'intel.pick_assets': 'ASSETS',
      'intel.pick_title': 'TARGET ASSETS',
      'intel.select_all': 'ALL',
      'intel.select_none': 'NONE',
      'intel.scanning': 'Scanning assets…',
      'intel.scan_done': 'Scan complete',
      'intel.kpi_assets': 'ASSETS',
      'intel.kpi_packages': 'PACKAGES',
      'intel.kpi_vuln_pkgs': 'VULNERABLE PKGS',
      'intel.kpi_cves': 'TOTAL CVES',
      'intel.kpi_score': 'AVG POSTURE',
      'intel.chart_gauge': 'POSTURE SCORE',
      'intel.chart_sev': 'SEVERITY DISTRIBUTION',
      'intel.chart_cat': 'FINDINGS BY CATEGORY',
      'intel.chart_top': 'TOP VULNERABLE COMPONENTS',
      'intel.chart_asset': 'SEVERITY BY ASSET',
      'intel.findings': 'PACKAGE FINDINGS',
      'intel.search_ph': 'Filter package, CVE, asset…',
      'intel.th_sev': 'SEVERITY',
      'intel.th_pkg': 'PACKAGE',
      'intel.th_ver': 'VERSION',
      'intel.th_eco': 'ECOSYSTEM',
      'intel.th_cat': 'CATEGORY',
      'intel.th_asset': 'ASSET',
      'intel.empty': 'No posture data yet. Run a scan.',
      // vuln match enum
      'vuln.VULNERABILE': 'VULNERABLE',
      'vuln.NON VULNERABILE': 'NOT VULNERABLE',
      'vuln.INCERTO': 'UNCERTAIN',
      // dashboard
      'dash.posture_title': 'SECURITY POSTURE SCORE',
      'dash.posture_note': 'product not detected on {n} asset(s)',
      'dash.verified_title': 'VERIFIED ASSETS',
      'dash.verified_waiting': 'awaiting scan',
      'dash.verified_scanning': 'scanning…',
      'dash.verified_count': '{n} assets verified',
      'dash.vulns_title': 'ACTIVE VULNERABILITIES',
      'dash.vulns_triage': 'Requires immediate triage',
      'dash.network_title': 'DETECTED PRODUCTS NETWORK',
      'dash.network_hint': 'Run a scan to map the product dependency graph.',
      'dash.graph_mapping': 'Mapping dependency graph…',
      'dash.graph_empty': 'No product identified — empty graph.',
      'dash.legend_dependency': 'dependency',
      'dash.legend_links': 'inter-dependency links',
      'dash.legend_no_deps': 'No known dependencies mapped for this product.',
      'dash.legend_sample': 'sample',
      'dash.legend_product': 'product',
      'dash.authn_title': 'ASSET AUTHENTICATION',
      'dash.authn_auth_nodes': 'Authenticated Nodes',
      'dash.authn_unauth_nodes': 'Unauthenticated Nodes',
      'dash.authn_total': 'total assets in inventory',
      'dash.query_title': 'THREAT INTELLIGENCE QUERY',
      'dash.query_placeholder': 'Describe Vulnerability or input CVE...',
      'dash.query_hint': 'Press ENTER to initiate scan sequence',
      'dash.query_btn': 'AI ANALYSIS',
      'dash.pipeline_title': 'IDENTIFICATION PIPELINE',
      'dash.pipe_parse': 'Parsing Input',
      'dash.pipe_osint': 'OSINT Correlation',
      'dash.pipe_detect': 'Active Detection',
      'dash.console_init': 'Initializing core diagnostic protocol...',
      'dash.console_await': 'Awaiting threat intelligence query.',
      'dash.inventory_title': 'ASSET INVENTORY (LOCAL)',
      'dash.inventory_viewall': 'VIEW ALL',
      'dash.inventory_loading': 'Loading inventory…',
      'dash.inventory_none': 'No assets.',
      'dash.inventory_failed': 'Inventory load failed.',
      'dash.alerts_title': 'CRITICAL INTELLIGENCE ALERTS',
      'dash.deep_label': 'DEEP VERSION PROBE',
      'dash.deep_tooltip': 'Active, more intrusive scan to infer the installed Python version. On top of the passive banner, it sends full GET requests (including a non-existent path) to read the "Python/X.Y" token in the Server header (Werkzeug, mod_wsgi) and any framework tracebacks or error pages. It is slower and generates extra HTTP traffic on the target — enable it only on systems you are authorized to test. Off by default. Note: authenticated assets always run "python3 --version" regardless of this switch.',
      // console / log dynamic
      'log.query': 'Query:',
      'log.product_identified': 'Product identified:',
      'log.source': 'source',
      'log.no_product': 'No product identified from query.',
      'log.on_host': 'on host',
      'log.detected': 'detected',
      'log.product_not_found': 'product not found',
      'log.cve_n': '{n} CVE (OSV)',
      'log.cve_0': '0 CVE',
      'cve.osv_unreachable': 'OSV unreachable: {err}',
      'cve.known': '{n} known vulnerabilities (OSV).',
      'cve.more': '+{n} more',
      'cve.no_summary': '(local LLM summary unavailable — Ollama offline)',
      'cve.none': 'no known CVE on OSV.',
      'scan.complete': 'Scan complete · {n} asset(s)',
      'note.no_product': 'No product identified.',
      // alerts (disabled demo)
      'alert.cve_title': 'CVE-2023-4567 Detected',
      'alert.cve_body': 'Unauthorized access vector identified on SRV-PROD-01 via Python library vulnerability.',
      'alert.cve_btn': 'INITIATE ISOLATION',
      'alert.drift_title': 'Configuration Drift',
      'alert.drift_body': 'GATEWAY-MAIN configuration checksum mismatch detected against baseline.',
      'alert.drift_btn': 'REVIEW DIFF',
      // assets page
      'assets.header': 'Asset Inventory',
      'assets.subtitle': 'CRUD management of the config file',
      'assets.new_title': 'NEW ASSET',
      'assets.ph_ip': 'IP / hostname',
      'assets.ph_user': 'username (optional)',
      'assets.ph_pass': 'password (optional)',
      'assets.add_btn': 'ADD ASSET',
      'assets.help': 'Without username and password the asset is <span class="text-slate-600">NOT REQUIRED</span> (unauthenticated banner-grab).',
      'assets.th_host': 'IP / HOST',
      'assets.th_user': 'USERNAME',
      'assets.th_pass': 'PASSWORD',
      'assets.th_auth': 'AUTH',
      'assets.th_active': 'ACTIVE',
      'assets.th_actions': 'ACTIONS',
      'assets.checking': 'Checking…',
      'assets.available': 'Available',
      'assets.not_available': 'Not available',
      'assets.active_tooltip': 'When this page loads, every asset is checked live: the app tries a TCP connection to common ports (80, 443, 22, 8080) of the host. If it responds it is marked Available (green), otherwise Not available (red). Until the check finishes the state is "Checking…". URLs are normalised (scheme/path stripped). This is a reachability test, not a full port scan, and runs again on reload.',
      'assets.empty': 'Inventory empty. Add the first asset.',
      'assets.auto': 'auto',
      'assets.count': '{n} ASSET(S)',
      'assets.added': 'Asset added',
      'assets.updated': 'Asset updated',
      'assets.deleted': 'Asset deleted',
      'assets.load_failed': 'Inventory load failed',
      'assets.err_create': 'Create error',
      'assets.err_update': 'Update error',
      'assets.err_delete': 'Delete error',
      'assets.confirm_delete': 'Delete asset "{ip}" from inventory?',
      // audit page
      'audit.header': 'Audit Ledger',
      'audit.subtitle': 'Scan results history stored on <span class="text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">Supabase</span> · most recent first',
      'audit.kpi_scans': 'TOTAL SCANS',
      'audit.kpi_results': 'ASSET RESULTS',
      'audit.kpi_vuln': 'VULNERABLE OUTCOMES',
      'audit.loading': 'Loading history…',
      'audit.th_method': 'METHOD',
      'audit.th_outcome': 'OUTCOME',
      'audit.th_found': 'FOUND',
      'audit.th_version': 'VERSION',
      'audit.th_evidence': 'EVIDENCE',
      'audit.deps': 'DEPS',
      'audit.no_results': 'No per-asset results.',
      'audit.no_product': 'product not identified',
      'audit.err_unreachable': 'Supabase unreachable.',
      'audit.err_network': 'Network error reaching the server.',
      'audit.start_supabase': 'Start Supabase:',
      'audit.empty': 'No scan saved yet. Run one from the <a href="/" class="text-cyan-600 underline">Dashboard</a>.',
      'audit.assets_n': '{n} asset(s)',
      'audit.cve_n': '{n} CVE',
      'audit.show_more': '+{n} more',
      'audit.show_less': 'show less',
      'audit.cve_loading': 'loading…',
      'audit.cve_failed': 'failed to load',
      'audit.search_ph': 'Search CVE, IP, version…',
      'audit.no_match': 'No results matching the search.',
      'audit.advisory': 'AI advisory',
      'audit.advisory_t': 'Verdict from the AI-extracted affected version (no CVE).',
      'audit.affected': 'affected',
      'log.ai_affected': 'AI-inferred affected version',
      'log.ai_basis': 'AI advisory',
    },
    it: {
      // common
      'common.reload': 'AGGIORNA',
      'common.disabled': 'DISABILITATO',
      'common.authenticated': 'AUTENTICATO',
      'common.not_required': 'NON RICHIESTO',
      'common.auth': 'AUTH',
      'common.noauth': 'NO-AUTH',
      'common.yes': 'sì',
      'common.no': 'no',
      'common.na': 'N/D',
      'common.none': 'nessuna',
      'common.save': 'SALVA',
      'common.cancel': 'ANNULLA',
      'common.edit': 'MODIFICA',
      'common.delete': 'ELIMINA',
      // topbar
      'top.status_active': 'SISTEMA_ATTIVO',
      'top.asset_registry': 'REGISTRO_ASSET',
      'top.audit_ledger': 'REGISTRO_AUDIT',
      'top.intel_center': 'CENTRO_POSTURE',
      'intel.header': 'Postura di Sicurezza Applicativa',
      'intel.subtitle': 'Postura completa (software composition) per asset — pacchetti installati vs OSV.',
      'intel.run_btn': 'AVVIA SCAN POSTURE COMPLETA',
      'intel.pick_assets': 'ASSET',
      'intel.pick_title': 'ASSET TARGET',
      'intel.select_all': 'TUTTI',
      'intel.select_none': 'NESSUNO',
      'intel.scanning': 'Scansione asset in corso…',
      'intel.scan_done': 'Scansione completata',
      'intel.kpi_assets': 'ASSET',
      'intel.kpi_packages': 'PACCHETTI',
      'intel.kpi_vuln_pkgs': 'PACCHETTI VULNERABILI',
      'intel.kpi_cves': 'CVE TOTALI',
      'intel.kpi_score': 'POSTURA MEDIA',
      'intel.chart_gauge': 'PUNTEGGIO POSTURA',
      'intel.chart_sev': 'DISTRIBUZIONE SEVERITÀ',
      'intel.chart_cat': 'FINDING PER CATEGORIA',
      'intel.chart_top': 'COMPONENTI PIÙ VULNERABILI',
      'intel.chart_asset': 'SEVERITÀ PER ASSET',
      'intel.findings': 'FINDING PER PACCHETTO',
      'intel.search_ph': 'Filtra pacchetto, CVE, asset…',
      'intel.th_sev': 'SEVERITÀ',
      'intel.th_pkg': 'PACCHETTO',
      'intel.th_ver': 'VERSIONE',
      'intel.th_eco': 'ECOSISTEMA',
      'intel.th_cat': 'CATEGORIA',
      'intel.th_asset': 'ASSET',
      'intel.empty': 'Nessun dato di postura. Avvia una scansione.',
      // vuln match enum
      'vuln.VULNERABILE': 'VULNERABILE',
      'vuln.NON VULNERABILE': 'NON VULNERABILE',
      'vuln.INCERTO': 'INCERTO',
      // dashboard
      'dash.posture_title': 'PUNTEGGIO SICUREZZA',
      'dash.posture_note': 'prodotto non rilevato su {n} asset',
      'dash.verified_title': 'ASSET VERIFICATI',
      'dash.verified_waiting': 'in attesa di scansione',
      'dash.verified_scanning': 'scansione in corso…',
      'dash.verified_count': '{n} asset verificati',
      'dash.vulns_title': 'VULNERABILITÀ ATTIVE',
      'dash.vulns_triage': 'Richiede triage immediato',
      'dash.network_title': 'RETE PRODOTTI RILEVATI',
      'dash.network_hint': 'Avvia una scansione per mappare il grafo delle dipendenze.',
      'dash.graph_mapping': 'Mappatura grafo dipendenze…',
      'dash.graph_empty': 'Nessun prodotto identificato — grafo vuoto.',
      'dash.legend_dependency': 'dipendenza',
      'dash.legend_links': 'collegamenti inter-dipendenza',
      'dash.legend_no_deps': 'Nessuna dipendenza nota per questo prodotto.',
      'dash.legend_sample': 'esempio',
      'dash.legend_product': 'prodotto',
      'dash.authn_title': 'AUTENTICAZIONE ASSET',
      'dash.authn_auth_nodes': 'Nodi autenticati',
      'dash.authn_unauth_nodes': 'Nodi non autenticati',
      'dash.authn_total': 'asset totali in inventario',
      'dash.query_title': 'QUERY THREAT INTELLIGENCE',
      'dash.query_placeholder': 'Descrivi la vulnerabilità o inserisci un CVE...',
      'dash.query_hint': 'Premi INVIO per avviare la scansione',
      'dash.query_btn': 'ANALISI AI',
      'dash.pipeline_title': 'PIPELINE DI IDENTIFICAZIONE',
      'dash.pipe_parse': 'Analisi input',
      'dash.pipe_osint': 'Correlazione OSINT',
      'dash.pipe_detect': 'Rilevamento attivo',
      'dash.console_init': 'Inizializzazione protocollo diagnostico...',
      'dash.console_await': 'In attesa di query threat intelligence.',
      'dash.inventory_title': 'INVENTARIO ASSET (LOCALE)',
      'dash.inventory_viewall': 'VEDI TUTTI',
      'dash.inventory_loading': 'Caricamento inventario…',
      'dash.inventory_none': 'Nessun asset.',
      'dash.inventory_failed': 'Caricamento inventario fallito.',
      'dash.alerts_title': 'ALERT CRITICI',
      'dash.deep_label': 'RILEVAMENTO VERSIONE APPROFONDITO',
      'dash.deep_tooltip': 'Scansione attiva e piu\' invasiva per dedurre la versione di Python installata. Oltre al banner passivo, invia richieste GET complete (incluso un path inesistente) per leggere il token "Python/X.Y" nell\'header Server (Werkzeug, mod_wsgi) ed eventuali traceback o pagine d\'errore del framework. E\' piu\' lenta e genera traffico HTTP aggiuntivo sul target — attivala solo su sistemi che sei autorizzato a testare. Disattivata di default. Nota: gli asset autenticati eseguono sempre "python3 --version", indipendentemente da questo switch.',
      // console / log dynamic
      'log.query': 'Query:',
      'log.product_identified': 'Prodotto identificato:',
      'log.source': 'fonte',
      'log.no_product': 'Nessun prodotto identificato dalla query.',
      'log.on_host': 'su host',
      'log.detected': 'rilevato',
      'log.product_not_found': 'prodotto non trovato',
      'log.cve_n': '{n} CVE (OSV)',
      'log.cve_0': '0 CVE',
      'cve.osv_unreachable': 'OSV non raggiungibile: {err}',
      'cve.known': '{n} vulnerabilità note (OSV).',
      'cve.more': '+{n} altre',
      'cve.no_summary': '(sintesi LLM locale non disponibile — Ollama offline)',
      'cve.none': 'nessuna CVE nota su OSV.',
      'scan.complete': 'Scansione completata · {n} asset',
      'note.no_product': 'Nessun prodotto identificato.',
      // alerts (disabled demo)
      'alert.cve_title': 'CVE-2023-4567 Rilevato',
      'alert.cve_body': 'Vettore di accesso non autorizzato individuato su SRV-PROD-01 tramite vulnerabilità di una libreria Python.',
      'alert.cve_btn': 'AVVIA ISOLAMENTO',
      'alert.drift_title': 'Deriva di configurazione',
      'alert.drift_body': 'Mismatch del checksum di configurazione di GATEWAY-MAIN rispetto alla baseline.',
      'alert.drift_btn': 'CONFRONTA DIFF',
      // assets page
      'assets.header': 'Inventario Asset',
      'assets.subtitle': 'Gestione CRUD del file di configurazione',
      'assets.new_title': 'NUOVO ASSET',
      'assets.ph_ip': 'IP / hostname',
      'assets.ph_user': 'username (opzionale)',
      'assets.ph_pass': 'password (opzionale)',
      'assets.add_btn': 'AGGIUNGI ASSET',
      'assets.help': "Senza username e password l'asset risulta <span class=\"text-slate-600\">NON RICHIESTO</span> (banner-grab non autenticato).",
      'assets.th_host': 'IP / HOST',
      'assets.th_user': 'UTENTE',
      'assets.th_pass': 'PASSWORD',
      'assets.th_auth': 'AUTH',
      'assets.th_active': 'ATTIVO',
      'assets.th_actions': 'AZIONI',
      'assets.checking': 'Checking…',
      'assets.available': 'Disponibile',
      'assets.not_available': 'Non disponibile',
      'assets.active_tooltip': 'All\'apertura della pagina ogni asset viene verificato a runtime: l\'app tenta una connessione TCP sulle porte note (80, 443, 22, 8080) dell\'host. Se risponde e\' segnato Disponibile (verde), altrimenti Non disponibile (rosso). Finche\' il controllo non termina lo stato e\' "Checking…". Gli URL sono normalizzati (schema/path rimossi). E\' un test di raggiungibilita\', non uno scan completo delle porte, e viene rieseguito al reload.',
      'assets.empty': 'Inventario vuoto. Aggiungi il primo asset.',
      'assets.auto': 'auto',
      'assets.count': '{n} ASSET',
      'assets.added': 'Asset aggiunto',
      'assets.updated': 'Asset aggiornato',
      'assets.deleted': 'Asset eliminato',
      'assets.load_failed': 'Caricamento inventario fallito',
      'assets.err_create': 'Errore creazione',
      'assets.err_update': 'Errore aggiornamento',
      'assets.err_delete': 'Errore eliminazione',
      'assets.confirm_delete': 'Eliminare l\'asset "{ip}" dall\'inventario?',
      // audit page
      'audit.header': 'Registro Audit',
      'audit.subtitle': 'Storico dei risultati di scansione salvati su <span class="text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">Supabase</span> · più recenti prima',
      'audit.kpi_scans': 'SCANSIONI TOTALI',
      'audit.kpi_results': 'RISULTATI ASSET',
      'audit.kpi_vuln': 'ESITI VULNERABILE',
      'audit.loading': 'Caricamento storico…',
      'audit.th_method': 'METODO',
      'audit.th_outcome': 'ESITO',
      'audit.th_found': 'TROVATO',
      'audit.th_version': 'VERSIONE',
      'audit.th_evidence': 'EVIDENZA',
      'audit.deps': 'DIPENDENZE',
      'audit.no_results': 'Nessun risultato per asset.',
      'audit.no_product': 'prodotto non identificato',
      'audit.err_unreachable': 'Supabase non raggiungibile.',
      'audit.err_network': 'Errore di rete verso il server.',
      'audit.start_supabase': 'Avvia Supabase:',
      'audit.empty': 'Nessuna scansione salvata. Lanciane una dalla <a href="/" class="text-cyan-600 underline">Dashboard</a>.',
      'audit.assets_n': '{n} asset',
      'audit.cve_n': '{n} CVE',
      'audit.show_more': '+{n} altre',
      'audit.show_less': 'mostra meno',
      'audit.cve_loading': 'caricamento…',
      'audit.cve_failed': 'caricamento fallito',
      'audit.search_ph': 'Cerca CVE, IP, versione…',
      'audit.no_match': 'Nessun risultato per la ricerca.',
      'audit.advisory': 'advisory AI',
      'audit.advisory_t': 'Verdetto dalla versione affetta dedotta dall\'AI (senza CVE).',
      'audit.affected': 'affette',
      'log.ai_affected': 'versione affetta dedotta dall\'AI',
      'log.ai_basis': 'advisory AI',
    },
  };

  let lang = localStorage.getItem('lang') || 'en';
  if (!DICT[lang]) lang = 'en';

  function t(key, vars) {
    let s = (DICT[lang] && DICT[lang][key] != null) ? DICT[lang][key]
          : (DICT.en[key] != null ? DICT.en[key] : key);
    if (vars) for (const k in vars) s = s.replace(new RegExp('\\{' + k + '\\}', 'g'), vars[k]);
    return s;
  }

  function applyStatic(root) {
    const scope = root || document;
    scope.querySelectorAll('[data-i18n]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n')); });
    scope.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
    scope.querySelectorAll('[data-i18n-title]').forEach((el) => { el.setAttribute('title', t(el.getAttribute('data-i18n-title'))); });
    document.documentElement.lang = lang;
  }

  function updateSwitch() {
    document.querySelectorAll('[data-lang-btn]').forEach((b) => {
      const on = b.getAttribute('data-lang-btn') === lang;
      b.classList.toggle('bg-slate-900', on);
      b.classList.toggle('text-white', on);
      b.classList.toggle('text-slate-400', !on);
    });
  }

  function setLang(l) {
    if (!DICT[l] || l === lang) return;
    lang = l;
    localStorage.setItem('lang', l);
    applyStatic();
    updateSwitch();
    window.dispatchEvent(new CustomEvent('langchange', { detail: { lang: l } }));
  }

  window.t = t;
  window.i18n = { t, setLang, applyStatic, get lang() { return lang; } };

  document.addEventListener('DOMContentLoaded', () => {
    applyStatic();
    updateSwitch();
    document.querySelectorAll('[data-lang-btn]').forEach((b) => {
      b.addEventListener('click', () => setLang(b.getAttribute('data-lang-btn')));
    });
  });
})();
