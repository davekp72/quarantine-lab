import { EventsOn } from './wailsjs/runtime/runtime.js';
import { filterDiff, isUsnLeafPath } from './noise.js';

let diffData = null;
let toSnapshot = '';
let snapshotNames = [];
let logDrawerOpen = false;
let fileChangeTab = 'added';

const $ = (sel) => document.querySelector(sel);

async function backend() {
  return window.go?.app?.App;
}

function setBusy(btn, busy, label) {
  if (!btn) return;
  btn.disabled = !!busy;
  if (label) btn.textContent = label;
}

function formatActivityLines(entries) {
  return (entries || []).map((e) => `[${e.time}] ${e.level}: ${e.message}`).join('\n');
}

function scrollLogView() {
  const view = $('#log-view');
  if ($('#log-autoscroll')?.checked) {
    view.scrollTop = view.scrollHeight;
  }
}

function renderLogView(text) {
  $('#log-view').textContent = text || '';
  scrollLogView();
}

async function refreshLogSources() {
  const api = await backend();
  const sel = $('#log-source');
  const prev = sel.value;
  sel.innerHTML = '<option value="activity">Activity</option>';
  if (api?.ListLogFilesWails) {
    const files = await api.ListLogFilesWails() || [];
    files.forEach((f) => {
      const opt = document.createElement('option');
      opt.value = f.path;
      opt.textContent = `[${f.source}] ${f.name}`;
      sel.appendChild(opt);
    });
  }
  if ([...sel.options].some((o) => o.value === prev)) {
    sel.value = prev;
  }
}

async function refreshLogView() {
  const api = await backend();
  const source = $('#log-source').value;
  if (source === 'activity') {
    const lines = api?.GetAppLogWails ? await api.GetAppLogWails() : [];
    renderLogView(formatActivityLines(lines));
    return;
  }
  if (api?.TailLogFileWails) {
    try {
      const text = await api.TailLogFileWails(source, 400);
      renderLogView(text || '(empty)');
    } catch (e) {
      renderLogView(String(e));
    }
  }
}

function toggleLogDrawer(forceOpen) {
  const drawer = $('#log-drawer');
  const btn = $('#btn-toggle-log');
  logDrawerOpen = typeof forceOpen === 'boolean' ? forceOpen : !logDrawerOpen;
  drawer.classList.toggle('hidden', !logDrawerOpen);
  btn.classList.toggle('active', logDrawerOpen);
  if (logDrawerOpen) {
    refreshLogSources().then(refreshLogView).catch((e) => renderLogView(String(e)));
  }
}

function appendActivityLine(entry) {
  const view = $('#log-view');
  view.textContent += `[${entry.time}] ${entry.level}: ${entry.message}\n`;
  scrollLogView();
}

async function refreshStatus() {
  const api = await backend();
  if (!api?.GetVMStatusWails) {
    $('#vm-status').textContent = 'Wails backend unavailable';
    return;
  }
  const st = await api.GetVMStatusWails();
  let line = `${st.vmName || ''} — ${st.state || 'unknown'}`;
  if (st.agentEnabled === 'true') {
    if (st.agentStatus === 'ok') {
      line += ` | agent v${st.agentVersion || '?'} (payload=${st.agentPayloadSession})`;
    } else {
      line += ' | agent unreachable';
    }
  }
  $('#vm-status').textContent = line;
  const agentEl = $('#agent-status');
  if (agentEl) {
    if (st.agentEnabled !== 'true') {
      agentEl.textContent = 'Agent disabled in config';
    } else if (st.agentStatus === 'ok') {
      const usn = st.agentVersion >= '1.0.2'
        ? `, USN ${st.agentUSN === 'true' ? 'on' : 'off'}`
        : '';
      const payload = st.agentPayloadSession === 'true' ? '' : ' (jkcooper not logged in — HKCU diff empty)';
      agentEl.textContent = `Agent OK — Sysmon ${st.agentSysmon === 'true' ? 'on' : 'off'}${usn}${payload}`;
    } else {
      agentEl.textContent = st.agentError || 'Agent not installed';
    }
  }
}

function fillSelect(sel, names, preferred) {
  const prev = preferred || sel.value;
  sel.innerHTML = '';
  if (!names.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '(no snapshots)';
    sel.appendChild(opt);
    return;
  }
  names.forEach((name) => {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  });
  if (prev && names.includes(prev)) {
    sel.value = prev;
  }
}

function selectedSnapshot() {
  return $('#snap-list li.selected')?.dataset.name || '';
}

function renderSnapList(names) {
  const list = $('#snap-list');
  list.innerHTML = '';
  names.forEach((name) => {
    const li = document.createElement('li');
    li.textContent = name;
    li.dataset.name = name;
    li.onclick = () => {
      list.querySelectorAll('li').forEach((el) => el.classList.remove('selected'));
      li.classList.add('selected');
      $('#to-snap').value = name;
    };
    li.ondblclick = () => {
      li.click();
      launchSnapshot().catch((e) => { $('#snap-action-msg').textContent = String(e); });
    };
    list.appendChild(li);
  });
}

async function loadSnapshots(preferFrom, preferTo) {
  const api = await backend();
  const msg = $('#snap-action-msg');
  if (!api?.ListSnapshotsWails) {
    msg.textContent = 'Snapshot API unavailable';
    return;
  }
  try {
    const snaps = await api.ListSnapshotsWails() || [];
    snapshotNames = snaps.map((s) => s.name || s.Name).filter(Boolean);
    fillSelect($('#from-snap'), snapshotNames, preferFrom);
    fillSelect($('#to-snap'), snapshotNames, preferTo);
    renderSnapList(snapshotNames);

    // Sensible defaults when empty selection
    const fromSel = $('#from-snap');
    const toSel = $('#to-snap');
    if (!fromSel.value) {
      const baseline = snapshotNames.find((n) => /cleansession/i.test(n))
        || snapshotNames.find((n) => /^clean$/i.test(n))
        || snapshotNames[0];
      if (baseline) fromSel.value = baseline;
    }
    if (!toSel.value && snapshotNames.length) {
      const evidence = [...snapshotNames].reverse().find((n) => /^evidence-/i.test(n));
      toSel.value = evidence || snapshotNames[snapshotNames.length - 1];
    }
    msg.textContent = `${snapshotNames.length} snapshot(s)`;
  } catch (e) {
    msg.textContent = String(e);
  }
}

async function takeSnapshot() {
  const api = await backend();
  const selected = selectedSnapshot();
  const defaultName = selected || 'Session';
  const name = prompt('Snapshot name:', defaultName)?.trim();
  if (!name) {
    return;
  }
  const msg = $('#snap-action-msg');
  const btn = $('#btn-take-snap');
  setBusy(btn, true, 'Taking…');
  msg.textContent = `Taking snapshot ${name}… (live capture may take several minutes)`;
  try {
    try {
      await api.TakeSnapshotWails(name, 'Taken from Quarantine Lab UI', false);
    } catch (e) {
      const err = String(e);
      if (/already exists/i.test(err) && confirm(`Snapshot "${name}" already exists. Replace it?`)) {
        await api.TakeSnapshotWails(name, 'Taken from Quarantine Lab UI', true);
      } else {
        throw e;
      }
    }
    msg.textContent = `Saved: ${name}`;
    await loadSnapshots($('#from-snap').value, name);
    await refreshStatus();
  } catch (e) {
    msg.textContent = String(e);
  } finally {
    setBusy(btn, false, 'Take snapshot');
  }
}

async function launchSnapshot() {
  const api = await backend();
  const name = selectedSnapshot();
  const msg = $('#snap-action-msg');
  if (!name) {
    msg.textContent = 'Select a snapshot in the list';
    return;
  }
  const btn = $('#btn-launch-snap');
  setBusy(btn, true, 'Launching…');
  msg.textContent = `Restoring and starting ${name}…`;
  try {
    const result = await api.LaunchSnapshotWails(name, false);
    msg.textContent = result || `Launched: ${name}`;
    await refreshStatus();
  } catch (e) {
    msg.textContent = String(e);
  } finally {
    setBusy(btn, false, 'Launch selected');
  }
}

async function deleteSnapshot() {
  const api = await backend();
  const name = selectedSnapshot();
  const msg = $('#snap-action-msg');
  if (!name) {
    msg.textContent = 'Select a snapshot in the list';
    return;
  }
  if (!confirm(`Delete snapshot "${name}"?`)) {
    return;
  }
  const btn = $('#btn-delete-snap');
  setBusy(btn, true, 'Deleting…');
  msg.textContent = `Deleting ${name}…`;
  try {
    let result;
    try {
      result = await api.DeleteSnapshotWails(name, false);
    } catch (e) {
      const err = String(e);
      let force = false;
      if (/child snapshots/i.test(err)) {
        force = confirm(`${err}\n\nDelete the whole branch anyway?`);
      } else if (/protected baseline/i.test(err)) {
        force = confirm(`${err}\n\nDelete this protected baseline anyway?`);
      } else {
        throw e;
      }
      if (!force) {
        msg.textContent = 'Delete cancelled';
        return;
      }
      result = await api.DeleteSnapshotWails(name, true);
    }
    msg.textContent = result || `Deleted: ${name}`;
    await loadSnapshots($('#from-snap').value, $('#to-snap').value);
    await refreshStatus();
  } catch (e) {
    msg.textContent = String(e);
  } finally {
    setBusy(btn, false, 'Delete selected');
  }
}

async function preserveEvidence() {
  const api = await backend();
  const msg = $('#snap-action-msg');
  const btn = $('#btn-preserve');
  setBusy(btn, true, 'Preserving…');
  msg.textContent = 'Preserving evidence… (live capture may take several minutes)';
  try {
    const name = await api.PreserveEvidenceWails('');
    msg.textContent = `Evidence: ${name}`;
    await loadSnapshots($('#from-snap').value, name);
    await refreshStatus();
  } catch (e) {
    msg.textContent = String(e);
  } finally {
    setBusy(btn, false, 'Preserve evidence');
  }
}

function showTab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${name}`));
}

function hideNoiseEnabled() {
  return $('#hideNoise')?.checked !== false;
}

function activeDiff() {
  return filterDiff(diffData, hideNoiseEnabled());
}

function renderOverview() {
  const panel = $('#panel-overview');
  if (!diffData) {
    panel.innerHTML = '<p class="muted">Pick From/To snapshots and click Compare.</p>';
    return;
  }
  const d = activeDiff();
  const s = d.summary || {};
  const m = d.meta || {};
  const noiseNote = hideNoiseEnabled()
    ? '<p class="muted">Routine noise hidden — uncheck to show all changes.</p>'
    : '';
  panel.innerHTML = `
    <p><strong>${m.fromSnapshot || ''}</strong> → <strong>${m.toSnapshot || ''}</strong></p>
    ${noiseNote}
    <div class="stat-grid">
      <div class="stat"><div class="n">${s.filesAdded || 0}</div>Files added</div>
      <div class="stat"><div class="n">${s.filesRemoved || 0}</div>Files removed</div>
      <div class="stat"><div class="n">${s.filesModified || 0}</div>Files modified</div>
      <div class="stat"><div class="n">${s.registryAdded || 0}</div>Registry added</div>
      <div class="stat"><div class="n">${s.registryModified || 0}</div>Registry modified</div>
      <div class="stat"><div class="n">${s.sysmonAdded || 0}</div>Sysmon events</div>
      <div class="stat"><div class="n">${s.dnsQueries || 0}</div>DNS lookups</div>
      <div class="stat"><div class="n">${s.networkRequests || 0}</div>HTTP/proxy</div>
    </div>`;
}

function showFileTab(name) {
  fileChangeTab = name;
  document.querySelectorAll('.file-tabs button').forEach((b) => {
    b.classList.toggle('active', b.dataset.fileTab === name);
  });
  renderFileTree().catch((e) => alert(e));
}

function filterDiffForFileTab(diff, tab) {
  const files = diff.files || {};
  return {
    ...diff,
    files: {
      added: tab === 'added' ? (files.added || []) : [],
      removed: tab === 'removed' ? (files.removed || []) : [],
      modified: tab === 'modified' ? (files.modified || []) : [],
    },
  };
}

function updateFileTabCounts(diff) {
  const files = diff?.files || {};
  const setCount = (id, n) => {
    const el = $(id);
    if (el) el.textContent = n ? `(${n})` : '';
  };
  setCount('#file-count-added', (files.added || []).length);
  setCount('#file-count-removed', (files.removed || []).length);
  setCount('#file-count-modified', (files.modified || []).length);
}

function fileTabEmptyMessage(tab) {
  if (tab === 'added') return 'No new files in this diff.';
  if (tab === 'removed') return 'No deleted files in this diff.';
  return 'No changed files in this diff.';
}

function renderTreeNode(node, container, onSelect, depth = 0) {
  if (!node) return;
  const row = document.createElement('div');
  row.className = 'tree-row' + (node.change ? ` change-${node.change}` : '');
  row.style.paddingLeft = `${depth * 12}px`;
  row.textContent = node.name || node.path || '(root)';
  row.onclick = () => onSelect(node);
  container.appendChild(row);
  const children = node.children;
  if (children && typeof children === 'object') {
    Object.values(children).forEach((child) => renderTreeNode(child, container, onSelect, depth + 1));
  }
}

async function renderFileTree() {
  const host = $('#file-tree');
  host.innerHTML = '';
  const d = activeDiff();
  if (!d) return;
  updateFileTabCounts(d);
  const filtered = filterDiffForFileTab(d, fileChangeTab);
  const count = (filtered.files?.[fileChangeTab] || []).length;
  if (!count) {
    host.innerHTML = `<p class="muted">${fileTabEmptyMessage(fileChangeTab)}</p>`;
    return;
  }
  const api = await backend();
  const json = JSON.stringify(filtered);
  const tree = api?.BuildFileTreeWails ? await api.BuildFileTreeWails(json) : buildFileTreeLocal(filtered);
  renderTreeNode(tree, host, async (node) => {
    if (!node.path || (node.children && Object.keys(node.children).length)) return;
    $('#file-preview').textContent = 'Loading...';
    toSnapshot = diffData.meta?.toSnapshot || $('#to-snap').value;
    try {
      if (api?.ReadSnapshotFileWails) {
        const res = await api.ReadSnapshotFileWails(toSnapshot, node.path);
        $('#file-preview').textContent = res.content || '(empty)';
      } else {
        $('#file-preview').textContent = node.path;
      }
    } catch (e) {
      $('#file-preview').textContent = String(e);
    }
  });
}

function buildFileTreeLocal(diff) {
  const root = { name: 'C:\\', path: 'C:\\', children: {} };
  const add = (path, change, file) => {
    if (isUsnLeafPath(path, file)) return;
    const parts = path.replace(/\//g, '\\').split('\\').filter(Boolean);
    let node = root;
    let acc = parts[0]?.endsWith(':') ? parts[0] : '';
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (i === 0 && part.endsWith(':')) {
        acc = part;
        if (!node.children[part]) node.children[part] = { name: part, path: acc, children: {} };
        node = node.children[part];
        continue;
      }
      acc = acc ? `${acc}\\${part}` : part;
      if (!node.children[part]) node.children[part] = { name: part, path: acc, children: {} };
      node = node.children[part];
      if (i === parts.length - 1) node.change = change;
    }
  };
  (diff.files?.added || []).forEach((f) => add(f.path, 'added', f));
  (diff.files?.removed || []).forEach((f) => add(f.path, 'removed', f));
  (diff.files?.modified || []).forEach((f) => add(f.path, 'modified', f?.after || f));
  return root;
}

async function renderRegistryTree() {
  const host = $('#registry-tree');
  const values = $('#registry-values');
  host.innerHTML = '';
  values.innerHTML = '';
  const d = activeDiff();
  if (!d) return;
  const api = await backend();
  const json = JSON.stringify(d);
  const tree = api?.BuildRegistryTreeWails ? await api.BuildRegistryTreeWails(json) : null;
  if (!tree) {
    const hku = d.meta?.toUserRegistryCount ?? d.meta?.fromUserRegistryCount;
    if (hku === 0) {
      host.innerHTML = '<p class="muted">No HKCU registry in manifests — log in as payload user (jkcooper) before capture for user registry diffs.</p>';
    } else {
      host.textContent = 'No registry tree';
    }
    return;
  }
  const walk = (node, depth) => {
    if (node.path) {
      const row = document.createElement('div');
      row.className = 'tree-row';
      row.style.paddingLeft = `${depth * 12}px`;
      row.textContent = node.path;
      row.onclick = () => {
        values.innerHTML = (node.values || []).map((v) =>
          `<div><code>${v.n}</code> = ${JSON.stringify(v.v)}</div>`).join('') || '<span class="muted">(no values)</span>';
      };
      host.appendChild(row);
    }
    Object.values(node.children || {}).forEach((c) => walk(c, depth + 1));
  };
  walk(tree, 0);
}

function renderSysmon() {
  const panel = $('#panel-sysmon');
  const d = activeDiff();
  const rows = d?.sysmon?.added || [];
  if (!rows.length) {
    panel.innerHTML = '<p class="muted">No Sysmon events in diff.</p>';
    return;
  }
  panel.innerHTML = `<table><thead><tr><th>Time</th><th>EID</th><th>Target</th></tr></thead><tbody>${
    rows.slice(0, 500).map((e) => `<tr><td>${e.time || e.t || ''}</td><td>${e.eid || ''}</td><td>${e.target || e.targetFilename || e.image || e.queryName || ''}</td></tr>`).join('')
  }</tbody></table>`;
}

function usnReasonText(ev) {
  const raw = ev.reason || ev.reasons || [];
  return (Array.isArray(raw) ? raw : [raw]).filter(Boolean).join(', ');
}

function renderUsn() {
  const panel = $('#panel-usn');
  const d = activeDiff();
  const rows = d?.usn?.events || [];
  if (!rows.length) {
    panel.innerHTML = '<p class="muted">No USN events in diff.</p>';
    return;
  }
  panel.innerHTML = `<table><thead><tr><th>File</th><th>Reasons</th><th>USN</th></tr></thead><tbody>${
    rows.slice(0, 500).map((e) => `<tr><td>${e.fileName || ''}</td><td>${usnReasonText(e)}</td><td>${e.usn || ''}</td></tr>`).join('')
  }</tbody></table>`;
}

function renderNetwork() {
  const panel = $('#panel-network');
  const d = activeDiff();
  const net = d?.network;
  if (!net) {
    panel.innerHTML = '<p class="muted">No network section in this diff.</p>';
    return;
  }
  const dns = net.dns || [];
  const reqs = net.requests || [];
  const windowText = net.windowFrom && net.windowTo
    ? `${net.windowFrom} → ${net.windowTo}`
    : 'snapshot capture window';
  let html = `<p class="muted">${windowText} · ${dns.length} DNS · ${reqs.length} HTTP/proxy</p>`;
  if (net.message) {
    html += `<p class="muted">${net.message}</p>`;
  }
  if (!dns.length && !reqs.length) {
    html += '<p class="muted">No network events in this window.</p>';
    panel.innerHTML = html;
    return;
  }
  if (dns.length) {
    html += `<h3>DNS lookups</h3><table><thead><tr><th>Source</th><th>Query</th><th>Type</th><th>Time</th></tr></thead><tbody>${
      dns.slice(0, 500).map((r) => `<tr><td>${r.source || ''}</td><td>${r.qname || r.query || ''}</td><td>${r.qtype || r.type || ''}</td><td>${r.t || ''}</td></tr>`).join('')
    }</tbody></table>`;
  }
  if (reqs.length) {
    html += `<h3>HTTP / proxy</h3><table><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Time</th></tr></thead><tbody>${
      reqs.slice(0, 500).map((r) => `<tr><td>${r.method || ''}</td><td>${r.host || ''}</td><td>${r.path || r.url || ''}</td><td>${r.t || ''}</td></tr>`).join('')
    }</tbody></table>`;
  }
  panel.innerHTML = html;
}

async function rerenderDiff() {
  if (!diffData) return;
  renderOverview();
  await renderFileTree();
  await renderRegistryTree();
  renderSysmon();
  renderUsn();
  renderNetwork();
}

async function loadDiff(jsonStr) {
  diffData = JSON.parse(jsonStr);
  toSnapshot = diffData.meta?.toSnapshot || $('#to-snap').value;
  await rerenderDiff();
}

async function compare() {
  const api = await backend();
  const from = $('#from-snap').value.trim();
  const to = $('#to-snap').value.trim();
  const refresh = $('#refresh').checked;
  if (!from || !to) {
    alert('Select From and To snapshots');
    return;
  }
  if (!api?.CompareSnapshotsJSON) {
    alert('Backend not available');
    return;
  }
  const btn = $('#btn-compare');
  setBusy(btn, true, 'Comparing…');
  try {
    const json = await api.CompareSnapshotsJSON(from, to, refresh);
    await loadDiff(json);
  } finally {
    setBusy(btn, false, 'Compare');
  }
}

document.querySelectorAll('.tabs button').forEach((b) => {
  b.addEventListener('click', () => showTab(b.dataset.tab));
});
document.querySelectorAll('.file-tabs button').forEach((b) => {
  b.addEventListener('click', () => showFileTab(b.dataset.fileTab));
});
$('#btn-compare').addEventListener('click', () => compare().catch((e) => alert(e)));
$('#hideNoise').addEventListener('change', () => rerenderDiff().catch((e) => alert(e)));
$('#btn-refresh-snaps').addEventListener('click', () => loadSnapshots($('#from-snap').value, $('#to-snap').value).catch(alert));
$('#btn-launch-snap').addEventListener('click', () => launchSnapshot());
$('#btn-take-snap').addEventListener('click', () => takeSnapshot());
$('#btn-preserve').addEventListener('click', () => preserveEvidence());
$('#btn-delete-snap').addEventListener('click', () => deleteSnapshot());
$('#btn-install-agent').addEventListener('click', async () => {
  const api = await backend();
  if (!api?.InstallAgentWails) {
    alert('Backend not available');
    return;
  }
  const btn = $('#btn-install-agent');
  setBusy(btn, true, 'Installing…');
  try {
    const msg = await api.InstallAgentWails();
    $('#snap-action-msg').textContent = msg || 'Agent installed';
    toggleLogDrawer(true);
    await refreshStatus();
  } catch (e) {
    alert(String(e));
  } finally {
    setBusy(btn, false, 'Install VM agent');
  }
});
$('#btn-load-file').addEventListener('click', async () => {
  const path = prompt('Diff JSON path');
  if (!path) return;
  const api = await backend();
  const json = api?.LoadDiffFile ? await api.LoadDiffFile(path) : null;
  if (json) await loadDiff(json);
});
$('#btn-toggle-log').addEventListener('click', () => toggleLogDrawer());
$('#btn-log-close').addEventListener('click', () => toggleLogDrawer(false));
$('#btn-log-refresh').addEventListener('click', () => refreshLogView().catch((e) => renderLogView(String(e))));
$('#btn-log-clear').addEventListener('click', async () => {
  const api = await backend();
  if ($('#log-source').value === 'activity' && api?.ClearAppLogWails) {
    await api.ClearAppLogWails();
  }
  await refreshLogView();
});
$('#log-source').addEventListener('change', () => refreshLogView().catch((e) => renderLogView(String(e))));

EventsOn('applog', (entry) => {
  if (!logDrawerOpen || $('#log-source').value !== 'activity') return;
  appendActivityLine(entry);
});

(async () => {
  await refreshStatus();
  await loadSnapshots();
  renderOverview();
})().catch((e) => {
  $('#snap-action-msg').textContent = String(e);
});
