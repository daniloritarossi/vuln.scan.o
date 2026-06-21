/* tableutils.js — sort / paginate / export helpers shared by all pages */

const PAGE_SIZES = [50, 100, 500, 1000, 0]; // 0 = All

function _dlBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; document.body.appendChild(a);
  a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// CSV export — rows is array of plain objects (keys become headers)
function exportCSV(rows, filename) {
  if (!rows.length) return;
  const cols = Object.keys(rows[0]);
  const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const lines = [cols.map(q).join(',')].concat(rows.map(r => cols.map(c => q(r[c])).join(',')));
  _dlBlob(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }), filename);
}

// XLSX export — uses SheetJS (XLSX global) if loaded, else falls back to .xls HTML trick
function exportXLS(rows, filename) {
  if (!rows.length) return;
  if (typeof XLSX !== 'undefined') {
    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Data');
    XLSX.writeFile(wb, filename.match(/\.xlsx?$/i) ? filename : filename + '.xlsx');
  } else {
    const cols = Object.keys(rows[0]);
    const xe = v => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    let html = '<html xmlns:o="urn:schemas-microsoft-com:office:office" '
      + 'xmlns:x="urn:schemas-microsoft-com:office:excel">'
      + '<head><meta charset="utf-8"/></head><body><table>';
    html += '<tr>' + cols.map(c => `<th>${xe(c)}</th>`).join('') + '</tr>';
    rows.forEach(r => { html += '<tr>' + cols.map(c => `<td>${xe(r[c])}</td>`).join('') + '</tr>'; });
    html += '</table></body></html>';
    _dlBlob(new Blob([html], { type: 'application/vnd.ms-excel' }),
      filename.replace(/\.(xlsx?)$/i, '') + '.xls');
  }
}

// Sort icon HTML — inline style so it works without Tailwind JIT
function sortIcon(field, state) {
  if (!state || state.field !== field)
    return '<span style="opacity:0.3;font-size:10px;margin-left:3px;vertical-align:middle">⇅</span>';
  return state.dir === 'asc'
    ? '<span style="color:#0891b2;font-size:11px;margin-left:3px;vertical-align:middle">↑</span>'
    : '<span style="color:#0891b2;font-size:11px;margin-left:3px;vertical-align:middle">↓</span>';
}

// Sort array of objects by field; severity-aware for max_severity/vuln_match
function sortArray(arr, field, dir) {
  if (!field) return arr;
  const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  return arr.slice().sort((a, b) => {
    let av = a[field], bv = b[field];
    if (av == null) av = ''; if (bv == null) bv = '';
    if (field === 'max_severity') {
      const ai = SEV_ORDER.indexOf(String(av).toUpperCase()), bi = SEV_ORDER.indexOf(String(bv).toUpperCase());
      const cmp = (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
      return dir === 'asc' ? cmp : -cmp;
    }
    const na = parseFloat(av), nb = parseFloat(bv);
    if (!isNaN(na) && !isNaN(nb)) return dir === 'asc' ? na - nb : nb - na;
    const cmp = String(av).toLowerCase().localeCompare(String(bv).toLowerCase());
    return dir === 'asc' ? cmp : -cmp;
  });
}

// Render paginator HTML into container element and wire prev/next/size events
// onPageChange(newPage, newPageSize) called on interaction
function renderPaginator(containerId, total, page, pageSize, onPageChange) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const totalPages = pageSize === 0 ? 1 : Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (pageSize === 0 ? 1 : page * pageSize + 1);
  const to   = pageSize === 0 ? total : Math.min((page + 1) * pageSize, total);
  const sizeOpts = PAGE_SIZES.map(s =>
    `<option value="${s}"${pageSize === s ? ' selected' : ''}>${s === 0 ? 'All' : s}</option>`
  ).join('');
  const base = 'font-code-sm text-[11px] px-2.5 py-1 rounded-lg border bg-white transition-colors';
  const ena  = ' border-slate-200 hover:bg-slate-100 cursor-pointer text-slate-600';
  const dis  = ' border-slate-100 opacity-40 cursor-not-allowed text-slate-400';
  container.innerHTML =
    `<div class="flex items-center gap-4 flex-wrap justify-between px-5 py-3 border-t border-slate-100/70">
      <span class="font-code-sm text-[11px] text-slate-400">${from}–${to} of ${total.toLocaleString()}</span>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-1.5">
          <label class="font-label-caps text-[10px] text-slate-400">ROWS</label>
          <select data-pg-size class="border border-slate-200 rounded-lg px-2 py-1 font-code-sm text-[11px] bg-white focus:outline-none focus:border-cyan-300 cursor-pointer">${sizeOpts}</select>
        </div>
        <div class="flex items-center gap-1">
          <button data-pg-prev ${page <= 0 ? 'disabled' : ''} class="${base}${page <= 0 ? dis : ena}">‹ Prev</button>
          <span class="font-code-sm text-[11px] text-slate-500 px-2">${page + 1} / ${totalPages}</span>
          <button data-pg-next ${page >= totalPages - 1 ? 'disabled' : ''} class="${base}${page >= totalPages - 1 ? dis : ena}">Next ›</button>
        </div>
      </div>
    </div>`;
  container.querySelector('[data-pg-size]').addEventListener('change', e =>
    onPageChange(0, parseInt(e.target.value, 10)));
  const p = container.querySelector('[data-pg-prev]');
  const n = container.querySelector('[data-pg-next]');
  if (p && !p.disabled) p.addEventListener('click', () => onPageChange(page - 1, pageSize));
  if (n && !n.disabled) n.addEventListener('click', () => onPageChange(page + 1, pageSize));
}
