/**
 * Safe DOM helpers for evidence UI — never interpolate guest-controlled
 * strings into HTML; use textContent / createElement instead.
 */

export function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function escapeAttr(s) {
  return escapeHtml(s);
}

/** True when a string still contains raw HTML special chars (pre-escape check). */
export function looksLikeHtmlInjection(s) {
  return /[<>&"']/.test(String(s ?? ''));
}

/**
 * Build a table where every cell uses textContent.
 * rows: array of { cells: (string|number|null)[], attrs?: Record<string,string>, className?: string }
 */
export function buildSafeTable(headers, rows) {
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  for (const h of headers) {
    const th = document.createElement('th');
    th.textContent = h == null ? '' : String(h);
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  for (const row of rows) {
    const tr = document.createElement('tr');
    if (row.className) tr.className = row.className;
    if (row.attrs) {
      for (const [k, v] of Object.entries(row.attrs)) {
        tr.setAttribute(k, String(v));
      }
    }
    for (const cell of row.cells || []) {
      const td = document.createElement('td');
      if (cell != null && typeof cell === 'object' && !Array.isArray(cell)) {
        td.textContent = cell.text == null ? '' : String(cell.text);
        if (cell.title) td.title = String(cell.title);
        if (cell.className) td.className = cell.className;
      } else {
        td.textContent = cell == null ? '' : String(cell);
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  return table;
}

export function setMutedMessage(panel, text) {
  panel.replaceChildren();
  const p = document.createElement('p');
  p.className = 'muted';
  p.textContent = text;
  panel.appendChild(p);
  return p;
}

export function appendMuted(panel, text) {
  const p = document.createElement('p');
  p.className = 'muted';
  p.textContent = text;
  panel.appendChild(p);
  return p;
}
