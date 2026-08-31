(function () {
  'use strict';

  const NOISE_PATTERNS = [
    /\\Microsoft\\EdgeUpdate\\/i,
    /\\Windows Security Health\\/i,
    /\\PowerGrid\\/i,
    /manifest-capture\.json$/i,
    /Get-QuarantineGuestManifest\.ps1$/i,
    /Get-QuarantineGuestSysmonEvents\.ps1$/i,
    /\.etl$/i,
    /\\Windows\\Temp\\/i,
    /\\Temp\\/i,
    /\\SearchIndexer\.exe/i,
    /\\svchost\.exe/i,
    /\\MsMpEng\.exe/i,
    /\\SecurityHealthService\.exe/i
  ];

  const SYSMON_TYPE_LABELS = {
    ProcessCreate: 'Process',
    FileCreate: 'File create',
    FileCreateStream: 'File stream',
    RegistryEvent: 'Registry',
    DnsQuery: 'DNS',
    FileDelete: 'File delete',
    FileDeleteDetected: 'File delete'
  };

  let diff = null;
  let activeTab = 'overview';
  let statFilter = null;
  let selectedRowId = null;

  const $ = (sel) => document.querySelector(sel);
  const app = $('#app');
  const dropzone = $('#dropzone');
  const detailPanel = $('#detail-panel');

  function isNoise(text) {
    if (!text) return false;
    return NOISE_PATTERNS.some((re) => re.test(text));
  }

  function normalizeFile(item) {
    if (!item) return { path: '' };
    if (typeof item === 'string') return { path: item };
    return item;
  }

  function filePath(item) {
    return normalizeFile(item).path || '';
  }

  function matchesSearch(text, q) {
    if (!q) return true;
    return String(text || '').toLowerCase().includes(q.toLowerCase());
  }

  function fmtBytes(n) {
    const v = Number(n);
    if (!Number.isFinite(v)) return '—';
    if (v < 1024) return `${v} B`;
    if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
    return `${(v / (1024 * 1024)).toFixed(2)} MB`;
  }

  function fmtDelta(from, to) {
    const a = Number(from);
    const b = Number(to);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return `${from} → ${to}`;
    const d = b - a;
    const sign = d > 0 ? '+' : '';
    return `${fmtBytes(a)} → ${fmtBytes(b)} (${sign}${fmtBytes(d)})`;
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).catch(() => {});
  }

  function copyBtn(text) {
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'copy';
    btn.title = 'Copy to clipboard';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyText(text);
    });
    return btn;
  }

  function badge(kind, label) {
    const span = document.createElement('span');
    span.className = `badge ${kind}`;
    span.textContent = label || kind;
    return span;
  }

  function decodeContent(encoding, data) {
    if (!encoding || encoding === 'none') {
      return { type: 'missing', text: '' };
    }
    if (encoding === 'too_large') {
      return { type: 'note', text: 'File exceeds content capture limit. Re-capture manifest with a higher contentMaxKb.' };
    }
    if (encoding === 'access_denied') {
      return { type: 'note', text: 'Content not available (access denied during capture).' };
    }
    if (encoding === 'text') {
      return { type: 'text', text: data || '' };
    }
    if (encoding === 'base64') {
      try {
        const binary = atob(data || '');
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const previewLen = Math.min(bytes.length, 512);
        let hex = '';
        for (let i = 0; i < previewLen; i++) {
          hex += bytes[i].toString(16).padStart(2, '0') + ' ';
          if ((i + 1) % 16 === 0) hex += '\n';
        }
        const suffix = bytes.length > previewLen ? `\n… ${bytes.length - previewLen} more bytes` : '';
        return { type: 'binary', text: hex.trim() + suffix, size: bytes.length };
      } catch (err) {
        return { type: 'note', text: 'Could not decode binary content: ' + err.message };
      }
    }
    return { type: 'note', text: `Unknown encoding: ${encoding}` };
  }

  function simpleLineDiff(before, after) {
    const a = (before || '').split('\n');
    const b = (after || '').split('\n');
    const max = Math.max(a.length, b.length);
    const lines = [];
    for (let i = 0; i < max; i++) {
      const left = a[i];
      const right = b[i];
      if (left === right) {
        if (left !== undefined) lines.push({ kind: 'same', text: left });
      } else {
        if (left !== undefined) lines.push({ kind: 'del', text: left });
        if (right !== undefined) lines.push({ kind: 'add', text: right });
      }
    }
    return lines;
  }

  function renderContentPre(content) {
    const pre = document.createElement('pre');
    pre.className = 'content-block';
    if (content.type === 'text' || content.type === 'binary') {
      pre.textContent = content.text;
    } else {
      pre.className = 'content-note';
      pre.textContent = content.text;
    }
    return pre;
  }

  function renderLineDiff(before, after) {
    const wrap = document.createElement('pre');
    wrap.className = 'content-block';
    const lines = simpleLineDiff(before, after);
    lines.forEach((line) => {
      const span = document.createElement('span');
      span.className = line.kind === 'add' ? 'diff-line-add' : line.kind === 'del' ? 'diff-line-del' : 'diff-line-same';
      span.textContent = (line.kind === 'add' ? '+ ' : line.kind === 'del' ? '- ' : '  ') + line.text + '\n';
      wrap.appendChild(span);
    });
    return wrap;
  }

  function getFilters() {
    return {
      q: $('#search').value.trim(),
      category: $('#categoryFilter').value,
      change: statFilter || $('#changeFilter').value,
      hideNoise: $('#hideNoise').checked
    };
  }

  function rowPasses(item, filters) {
    if (filters.hideNoise && item.noise) return false;
    if (filters.change !== 'all' && item.kind !== filters.change) return false;
    if (filters.category !== 'all' && item.category !== filters.category) return false;
    if (!matchesSearch(item.searchText, filters.q)) return false;
    return true;
  }

  function buildRows() {
    const rows = [];

    (diff.files.added || []).forEach((item) => {
      const f = normalizeFile(item);
      const src = f.source ? ` · ${f.source}` : '';
      rows.push({
        id: `file:added:${f.path}`,
        category: 'files', kind: 'added', noise: isNoise(f.path),
        searchText: f.path, label: f.path, fileDetail: f, selectable: true,
        cells: [badge('added', 'added'), f.path, fmtBytes(f.size), (f.hash || '—').slice(0, 16) + src]
      });
    });
    (diff.files.removed || []).forEach((item) => {
      const f = normalizeFile(item);
      const src = f.source ? ` · ${f.source}` : '';
      rows.push({
        id: `file:removed:${f.path}`,
        category: 'files', kind: 'removed', noise: isNoise(f.path),
        searchText: f.path, label: f.path, fileDetail: f, selectable: true,
        cells: [badge('removed', 'removed'), f.path, fmtBytes(f.size), (f.hash || '—').slice(0, 16) + src]
      });
    });
    (diff.files.modified || []).forEach((f) => {
      const src = f.source ? ` · ${f.source}` : '';
      rows.push({
        id: `file:modified:${f.path}`,
        category: 'files', kind: 'modified', noise: isNoise(f.path),
        searchText: `${f.path} ${f.fromHash} ${f.toHash}`,
        label: f.path, fileDetail: f, selectable: true,
        cells: [
          badge('modified', 'modified'),
          f.path,
          fmtDelta(f.fromSize, f.toSize),
          `${(f.fromHash || '—').slice(0, 12)} → ${(f.toHash || '—').slice(0, 12)}${src}`,
          `${f.fromMtime || ''} → ${f.toMtime || ''}`
        ]
      });
    });

    (diff.registry.added || []).forEach((r) => {
      const text = `${r.key}[${r.name}]`;
      rows.push({
        id: `reg:added:${text}`,
        category: 'registry', kind: 'added', noise: false,
        searchText: `${text} ${r.value}`, label: text, registryDetail: r, selectable: true,
        cells: [badge('added', 'added'), text, r.value]
      });
    });
    (diff.registry.removed || []).forEach((r) => {
      const text = `${r.key}[${r.name}]`;
      rows.push({
        id: `reg:removed:${text}`,
        category: 'registry', kind: 'removed', noise: false,
        searchText: `${text} ${r.value}`, label: text, registryDetail: r, selectable: true,
        cells: [badge('removed', 'removed'), text, r.value]
      });
    });
    (diff.registry.modified || []).forEach((r) => {
      const text = `${r.key}[${r.name}]`;
      rows.push({
        id: `reg:modified:${text}`,
        category: 'registry', kind: 'modified', noise: false,
        searchText: `${text} ${r.fromValue} ${r.toValue}`, label: text, registryDetail: r, selectable: true,
        cells: [badge('modified', 'modified'), text, `${r.fromValue} → ${r.toValue}`]
      });
    });

    (diff.tasks.added || []).forEach((t) => {
      rows.push({
        id: `task:added:${t.TaskName}`,
        category: 'tasks', kind: 'added', noise: false,
        searchText: `${t.TaskName} ${t.TaskToRun}`, label: t.TaskName, taskDetail: t, selectable: true,
        cells: [badge('added', 'added'), t.TaskName, t.TaskToRun || '—', t.RunAsUser || '—']
      });
    });
    (diff.tasks.removed || []).forEach((t) => {
      rows.push({
        id: `task:removed:${t.TaskName}`,
        category: 'tasks', kind: 'removed', noise: false,
        searchText: `${t.TaskName} ${t.TaskToRun}`, label: t.TaskName, taskDetail: t, selectable: true,
        cells: [badge('removed', 'removed'), t.TaskName, t.TaskToRun || '—', t.RunAsUser || '—']
      });
    });
    (diff.tasks.modified || []).forEach((t) => {
      rows.push({
        id: `task:modified:${t.taskName}`,
        category: 'tasks', kind: 'modified', noise: false,
        searchText: `${t.taskName} ${t.fromTaskToRun} ${t.toTaskToRun}`, label: t.taskName, taskDetail: t, selectable: true,
        cells: [
          badge('modified', 'modified'),
          t.taskName,
          `${t.fromTaskToRun || '—'} → ${t.toTaskToRun || '—'}`,
          `${t.fromRunAsUser || '—'} → ${t.toRunAsUser || '—'}`
        ]
      });
    });
    (diff.tasks.volatileOnly || []).forEach((t) => {
      rows.push({
        id: `task:volatile:${t.taskName}`,
        category: 'tasks', kind: 'volatile', noise: true,
        searchText: `${t.taskName} ${t.fromLastRun} ${t.toLastRun}`, label: t.taskName, taskDetail: t, selectable: true,
        cells: [
          badge('volatile', 'volatile'),
          t.taskName,
          `${t.fromLastRun || '—'} → ${t.toLastRun || '—'}`,
          `${t.fromNextRun || '—'} → ${t.toNextRun || '—'}`
        ]
      });
    });

    (diff.sysmon?.added || []).forEach((ev, idx) => {
      const label = ev.summary || ev.target || ev.targetObject || ev.image || ev.queryName || ev.type || 'Sysmon event';
      const typeLabel = SYSMON_TYPE_LABELS[ev.type] || ev.type || `EID ${ev.eid}`;
      rows.push({
        id: `sysmon:added:${ev.id || idx}:${ev.t}`,
        category: 'sysmon',
        kind: 'added',
        noise: isNoise(label) || isNoise(ev.image || '') || isNoise(ev.commandLine || ''),
        searchText: `${typeLabel} ${label} ${ev.image || ''} ${ev.commandLine || ''} ${ev.targetObject || ''} ${ev.queryName || ''}`,
        label,
        sysmonDetail: ev,
        selectable: true,
        cells: [
          badge('added', typeLabel),
          label,
          ev.t || '—',
          ev.user || ev.image || ev.details || '—'
        ]
      });
    });

    return rows;
  }

  function closeDetail() {
    selectedRowId = null;
    detailPanel.classList.add('hidden');
    app.classList.remove('panel-layout', 'detail-open');
    document.querySelectorAll('tbody tr.selected').forEach((tr) => tr.classList.remove('selected'));
  }

  function showDetail(row) {
    selectedRowId = row.id;
    detailPanel.classList.remove('hidden');
    app.classList.add('panel-layout', 'detail-open');

    $('#detail-kicker').textContent = `${row.category} · ${row.kind}`;
    $('#detail-title').textContent = row.label || '';
    $('#detail-meta').innerHTML = '';
    $('#detail-body').innerHTML = '';

    const body = $('#detail-body');
    const meta = $('#detail-meta');

    if (row.fileDetail) {
      const f = row.fileDetail;
      if (row.kind === 'modified') {
        meta.textContent = `${fmtDelta(f.fromSize, f.toSize)} · hash changed · click row again to copy path`;
        const from = decodeContent(f.fromContentEncoding, f.fromContent);
        const to = decodeContent(f.toContentEncoding, f.toContent);

        if (from.type === 'text' && to.type === 'text') {
          body.appendChild(renderLineDiff(from.text, to.text));
        } else {
          const grid = document.createElement('div');
          grid.className = 'content-grid';
          [['Before', from], ['After', to]].forEach(([title, content]) => {
            const block = document.createElement('div');
            const h = document.createElement('h4');
            h.textContent = title;
            block.appendChild(h);
            block.appendChild(renderContentPre(content));
            grid.appendChild(block);
          });
          body.appendChild(grid);
        }
      } else {
        const src = f.source ? ` · ${f.source}` : '';
        meta.textContent = `${fmtBytes(f.size)} · ${f.hash || 'no hash (run manifest enrich)'} · ${f.mtime || ''}${src}`;
        const content = decodeContent(f.contentEncoding, f.content);
        if (content.type === 'missing') {
          const note = document.createElement('div');
          note.className = 'content-note';
          note.textContent = f.source
            ? 'Path from USN/Sysmon only. Run: .\\quarantine-vm.ps1 manifest enrich -SnapshotName <to-snapshot> to hash and embed content for changed files.'
            : 'Content was not captured. Run manifest enrich or full capture (scanMode full in config) for file bodies.';
          body.appendChild(note);
        } else {
          body.appendChild(renderContentPre(content));
        }
      }
      return;
    }

    if (row.registryDetail) {
      const r = row.registryDetail;
      meta.textContent = row.kind === 'modified' ? 'Registry value change' : `${r.type || 'REG'} value`;
      if (row.kind === 'modified') {
        body.appendChild(renderLineDiff(r.fromValue, r.toValue));
      } else {
        body.appendChild(renderContentPre({ type: 'text', text: r.value || '' }));
      }
      return;
    }

    if (row.taskDetail) {
      const t = row.taskDetail;
      meta.textContent = 'Scheduled task details';
      const pre = document.createElement('pre');
      pre.className = 'content-block';
      pre.textContent = JSON.stringify(t, null, 2);
      body.appendChild(pre);
      return;
    }

    if (row.sysmonDetail) {
      const ev = row.sysmonDetail;
      meta.textContent = `${SYSMON_TYPE_LABELS[ev.type] || ev.type || 'Sysmon'} · Event ID ${ev.eid || '?'}`;
      const pre = document.createElement('pre');
      pre.className = 'content-block';
      pre.textContent = JSON.stringify(ev, null, 2);
      body.appendChild(pre);
    }
  }

  function renderStats(rows, filters) {
    const statsEl = $('#stats');
    statsEl.innerHTML = '';
    const counts = {};
    rows.forEach((r) => {
      if (filters.hideNoise && r.noise) return;
      const key = `${r.category}:${r.kind}`;
      counts[key] = (counts[key] || 0) + 1;
    });

    const cards = [
      ['files', 'added', 'Files added', 'added'],
      ['files', 'removed', 'Files removed', 'removed'],
      ['files', 'modified', 'Files modified', 'modified'],
      ['registry', 'added', 'Registry added', 'added'],
      ['registry', 'removed', 'Registry removed', 'removed'],
      ['registry', 'modified', 'Registry modified', 'modified'],
      ['tasks', 'added', 'Tasks added', 'added'],
      ['tasks', 'removed', 'Tasks removed', 'removed'],
      ['tasks', 'modified', 'Tasks modified', 'modified'],
      ['tasks', 'volatile', 'Task schedule noise', 'volatile'],
      ['sysmon', 'added', 'Sysmon events', 'added']
    ];

    cards.forEach(([cat, kind, label]) => {
      const val = counts[`${cat}:${kind}`] || 0;
      const card = document.createElement('div');
      card.className = 'stat-card';
      if (statFilter === kind && filters.category === cat) card.classList.add('active');
      card.innerHTML = `<div class="label">${label}</div><div class="value">${val}</div>`;
      card.addEventListener('click', () => {
        statFilter = kind;
        $('#changeFilter').value = kind;
        $('#categoryFilter').value = cat;
        activeTab = cat === 'tasks' ? 'tasks' : cat === 'registry' ? 'registry' : cat === 'sysmon' ? 'sysmon' : 'files';
        setActiveTab(activeTab);
        render();
      });
      statsEl.appendChild(card);
    });
  }

  function renderTable(container, headers, rows) {
    container.innerHTML = '';
    if (!rows.length) {
      container.innerHTML = '<div class="empty">No matching changes. Click a row to inspect file contents.</div>';
      return;
    }

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    headers.forEach((h, idx) => {
      const th = document.createElement('th');
      th.textContent = h;
      if (idx === 1 && rows.some((r) => r.selectable)) {
        const hint = document.createElement('span');
        hint.className = 'view-hint';
        hint.textContent = ' · click row to view';
        th.appendChild(hint);
      }
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    rows.forEach((row) => {
      const tr = document.createElement('tr');
      if (row.selectable) tr.classList.add('selectable');
      if (row.id === selectedRowId) tr.classList.add('selected');

      tr.addEventListener('click', () => {
        document.querySelectorAll('tbody tr.selected').forEach((el) => el.classList.remove('selected'));
        tr.classList.add('selected');
        showDetail(row);
      });

      row.cells.forEach((cell, idx) => {
        const td = document.createElement('td');
        if (typeof cell === 'string') {
          td.className = idx === 1 ? 'path' : '';
          td.textContent = cell;
          if (idx === 1 && row.label) td.appendChild(copyBtn(row.label));
        } else {
          td.appendChild(cell);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function renderOverview(filtered) {
    const panel = $('#panel-overview');
    const byDir = {};
    filtered.filter((r) => r.category === 'files' && r.kind !== 'volatile').forEach((r) => {
      const p = r.label || '';
      const m = p.match(/^([A-Z]:\\[^\\]+\\[^\\]+)/i);
      const bucket = m ? m[1] : '(other)';
      byDir[bucket] = (byDir[bucket] || 0) + 1;
    });

    const entries = Object.entries(byDir).sort((a, b) => b[1] - a[1]);
    let html = '<h3>File changes by top-level folder</h3>';
    if (!entries.length) {
      html += '<div class="empty">No file changes match current filters.</div>';
    } else {
      html += '<table><thead><tr><th>Folder prefix</th><th>Changes</th></tr></thead><tbody>';
      entries.forEach(([dir, count]) => {
        html += `<tr><td class="path">${dir}</td><td>${count}</td></tr>`;
      });
      html += '</tbody></table>';
    }

    const interesting = filtered.filter((r) => !r.noise && r.kind !== 'volatile');
    html += `<h3 style="margin-top:1.5rem">Notable changes <span class="count-pill">(${interesting.length})</span></h3>`;
    html += '<p class="content-note" style="padding-top:0">Open Files, Registry, or Sysmon tabs and click a row for details.</p>';
    if (!interesting.length) {
      html += '<div class="empty">Nothing notable after noise filter — toggle "Hide routine noise".</div>';
    } else {
      html += '<table><thead><tr><th>Type</th><th>Item</th><th>Detail</th></tr></thead><tbody>';
      interesting.slice(0, 80).forEach((r) => {
        const detail = r.cells.slice(2).map((c) => (typeof c === 'string' ? c : '')).join(' · ');
        const kindHtml = r.cells[0] instanceof HTMLElement ? r.cells[0].outerHTML : r.kind;
        html += `<tr class="selectable overview-row" data-row-id="${r.id}"><td>${kindHtml}</td><td class="path">${r.label || ''}</td><td>${detail}</td></tr>`;
      });
      if (interesting.length > 80) {
        html += `<tr><td colspan="3" class="muted">… and ${interesting.length - 80} more (use tabs/filters)</td></tr>`;
      }
      html += '</tbody></table>';
    }
    panel.innerHTML = html;

    panel.querySelectorAll('.overview-row').forEach((tr) => {
      tr.addEventListener('click', () => {
        const rowId = tr.dataset.rowId;
        const row = filtered.find((r) => r.id === rowId) || buildRows().find((r) => r.id === rowId);
        if (row) {
          const tab = row.category === 'tasks' ? 'tasks'
            : row.category === 'registry' ? 'registry'
            : row.category === 'sysmon' ? 'sysmon'
            : 'files';
          setActiveTab(tab);
          showDetail(row);
          render();
        }
      });
    });
  }

  function renderSysmonPanel() {
    const panel = $('#panel-sysmon');
    if (!panel) return;

    const sysmon = diff.sysmon;
    if (!sysmon || sysmon.available === false) {
      panel.innerHTML = `<div class="empty">${sysmon?.message || 'Sysmon not captured. Install Sysmon in the guest and re-capture with -Refresh.'}</div>`;
      return;
    }

    const filters = getFilters();
    const rows = buildRows().filter((r) => r.category === 'sysmon' && rowPasses(r, filters));

    const header = document.createElement('p');
    header.className = 'content-note';
    let headerText = `Events in the To snapshot not present in From · ${(diff.sysmon.added || []).length} new`;
    if (sysmon.baselineAt) {
      headerText += ` · from baseline ${sysmon.baselineAt}`;
    }
    header.textContent = headerText;

    panel.innerHTML = '';
    panel.appendChild(header);
    if (!rows.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No Sysmon events match current filters.';
      panel.appendChild(empty);
      return;
    }

    const tableHost = document.createElement('div');
    panel.appendChild(tableHost);
    renderTable(tableHost, ['Type', 'Summary', 'Time (UTC)', 'User / image'], rows);
  }

  function renderUsnPanel() {
    const panel = $('#panel-usn');
    if (!panel) return;
    panel.innerHTML = '';
    const usn = diff.usn;
    if (!usn || usn.available === false) {
      panel.innerHTML = `<div class="empty">${usn?.message || 'No USN journal data. Run manifest mark after restore, then capture after the test.'}</div>`;
      return;
    }

    const events = usn.events || [];
    let html = `<p class="content-note">Volume ${usn.volume || 'C:'} · ${events.length} events since baseline (${usn.baselineAt || '?'})</p>`;
    if (!events.length) {
      html += '<div class="empty">No file activity recorded since USN baseline.</div>';
      panel.innerHTML = html;
      return;
    }

    html += '<table><thead><tr><th>Time (UTC)</th><th>Reason</th><th>File name</th></tr></thead><tbody>';
    events.forEach((e) => {
      html += `<tr><td class="mono">${e.timestamp || ''}</td><td>${(e.reasons || []).join(', ')}</td><td class="path">${e.fileName || ''}</td></tr>`;
    });
    html += '</tbody></table>';
    if (usn.truncated) {
      html += '<p class="content-note">Event list truncated at capture limit.</p>';
    }
    panel.innerHTML = html;
  }

  function render() {
    if (!diff) return;
    const filters = getFilters();
    const allRows = buildRows();
    const filtered = allRows.filter((r) => rowPasses(r, filters));

    renderStats(allRows, filters);
    renderOverview(filtered);

    renderTable(
      $('#panel-files'),
      ['Change', 'Path', 'Size / delta', 'Hash / mtime'],
      filtered.filter((r) => r.category === 'files')
    );
    renderTable(
      $('#panel-registry'),
      ['Change', 'Key', 'Value / delta'],
      filtered.filter((r) => r.category === 'registry')
    );
    renderTable(
      $('#panel-tasks'),
      ['Change', 'Task', 'Command / delta', 'Run as'],
      filtered.filter((r) => r.category === 'tasks')
    );
    renderSysmonPanel();
    renderUsnPanel();

    if (selectedRowId) {
      const selected = allRows.find((r) => r.id === selectedRowId);
      if (selected && rowPasses(selected, filters)) {
        showDetail(selected);
      } else {
        closeDetail();
      }
    }
  }

  function setActiveTab(name) {
    activeTab = name;
    document.querySelectorAll('.tab').forEach((t) => {
      t.classList.toggle('active', t.dataset.tab === name);
    });
    document.querySelectorAll('.panel').forEach((p) => {
      p.classList.toggle('active', p.id === `panel-${name}`);
    });
  }

  function renderWarnings() {
    const warnings = (diff.meta && diff.meta.warnings) || [];
    let banner = document.getElementById('warn-banner');
    if (!warnings.length) {
      if (banner) banner.remove();
      return;
    }
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'warn-banner';
      banner.className = 'warn-banner';
      const header = app.querySelector('header');
      if (header && header.nextSibling) {
        header.parentNode.insertBefore(banner, header.nextSibling);
      } else {
        app.prepend(banner);
      }
    }
    banner.replaceChildren();
    warnings.forEach((w) => {
      const p = document.createElement('p');
      p.textContent = w;
      banner.appendChild(p);
    });
  }

  function showDiff(data) {
    diff = data;
    selectedRowId = null;
    dropzone.classList.add('hidden');
    app.classList.remove('panel-layout', 'detail-open');
    detailPanel.classList.add('hidden');
    app.classList.remove('hidden');

    const m = diff.meta || {};
    const s = diff.summary || {};
    const fromFiles = m.fromFileCount != null ? ` · ${m.fromFileCount} scanned` : '';
    const toFiles = m.toFileCount != null ? ` · ${m.toFileCount} scanned` : '';
    const fromHku = m.fromUserRegistryCount != null ? ` · ${m.fromUserRegistryCount} HKU reg` : '';
    const toHku = m.toUserRegistryCount != null ? ` · ${m.toUserRegistryCount} HKU reg` : '';
    const fileSrc = m.fileDiffSource ? ` · file diff: ${m.fileDiffSource}` : '';
    const scanNote = (m.toScanMode === 'events' || m.fromScanMode === 'events')
      ? `<div class="content-note" style="margin-top:0.35rem">Event-first capture (USN/Sysmon). Run <span class="mono">manifest enrich -SnapshotName …</span> to hash changed paths.</div>`
      : '';
    $('#meta').innerHTML = `
      <div><strong>From:</strong> ${m.fromSnapshot || '?'} <span class="mono">${m.fromCaptured || ''}${fromFiles}${fromHku}${m.fromScanMode ? ` · ${m.fromScanMode}` : ''}</span></div>
      <div><strong>To:</strong> ${m.toSnapshot || '?'} <span class="mono">${m.toCaptured || ''}${toFiles}${toHku}${m.toScanMode ? ` · ${m.toScanMode}` : ''}</span></div>
      <div class="mono" style="margin-top:0.25rem;font-size:0.8rem">${m.fromManifest || ''}<br>${m.toManifest || ''}${fileSrc}</div>
      ${scanNote}
    `;

    renderWarnings();
    statFilter = null;
    render();
  }

  function loadFile(file) {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        showDiff(JSON.parse(reader.result));
      } catch (err) {
        alert('Invalid JSON: ' + err.message);
      }
    };
    reader.readAsText(file);
  }

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      setActiveTab(tab.dataset.tab);
    });
  });

  ['search', 'categoryFilter', 'changeFilter', 'hideNoise'].forEach((id) => {
    $(`#${id}`).addEventListener('input', () => {
      statFilter = null;
      render();
    });
    $(`#${id}`).addEventListener('change', () => {
      statFilter = null;
      render();
    });
  });

  $('#detail-close').addEventListener('click', closeDetail);

  $('#fileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) loadFile(file);
  });

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
  });

  const dataEl = document.getElementById('manifest-diff-data');
  if (dataEl && dataEl.textContent) {
    try {
      showDiff(JSON.parse(dataEl.textContent));
    } catch (err) {
      console.error('Failed to parse embedded diff JSON:', err);
    }
  } else if (window.__MANIFEST_DIFF__) {
    showDiff(window.__MANIFEST_DIFF__);
  }
})();
