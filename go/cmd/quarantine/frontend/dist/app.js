import { EventsOn } from './wailsjs/runtime/runtime.js';
import { filterDiff, isEphemeralTempPath, isUsnLeafPath } from './noise.js';

let diffData = null;
let toSnapshot = '';
let snapshotNames = [];
let logDrawerOpen = false;
let fileChangeTab = 'added';
let regChangeTab = 'added';

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

async function refreshCaptureStatus() {
  const api = await backend();
  const statusEl = $('#capture-status');
  const detailEl = $('#capture-detail');
  const startBtn = $('#btn-capture-start');
  const stopBtn = $('#btn-capture-stop');
  if (!statusEl) return;
  if (!api?.CaptureStatusWails) {
    statusEl.textContent = 'Unavailable';
    statusEl.className = 'capture-status disabled';
    if (detailEl) detailEl.textContent = '';
    return;
  }
  try {
    const st = await api.CaptureStatusWails();
    const running = !!st.running;
    const enabled = st.enabled !== false;
    statusEl.className = 'capture-status ' + (!enabled ? 'disabled' : running ? 'running' : 'stopped');
    statusEl.textContent = !enabled ? 'Disabled' : running ? 'Recording' : 'Stopped';
    const parts = [];
    if (st.mode) parts.push(st.mode);
    if (st.message && st.message !== 'running' && st.message !== 'stopped') parts.push(st.message);
    else if (st.pcapPath) parts.push(st.pcapPath);
    if (detailEl) detailEl.textContent = parts.join(' · ');
    if (startBtn) startBtn.disabled = !enabled || running;
    if (stopBtn) stopBtn.disabled = !enabled || (!running && !st.pcapPath && !st.stale);
  } catch (e) {
    statusEl.textContent = 'Error';
    statusEl.className = 'capture-status disabled';
    if (detailEl) detailEl.textContent = String(e);
  }
}

async function refreshGatewayStatus() {
  const api = await backend();
  const statusEl = $('#gateway-status');
  const detailEl = $('#gateway-detail');
  if (!statusEl) return;
  if (!api?.GatewayStatusWails) {
    statusEl.textContent = 'Unavailable';
    statusEl.className = 'capture-status disabled';
    return;
  }
  try {
    const st = await api.GatewayStatusWails();
    const vmState = (st.vmState || '').toLowerCase();
    const mode = (st.mode || '').toLowerCase();
    const active = mode === 'gateway' && vmState === 'running';
    statusEl.className = 'capture-status ' + (active ? 'running' : vmState === 'running' ? 'stopped' : 'disabled');
    statusEl.textContent = active ? 'Active' : (vmState === 'running' ? 'Running (idle)' : (vmState || 'Off'));
    const parts = [];
    if (st.vmName) parts.push(st.vmName);
    if (st.lanGateway) parts.push('LAN ' + st.lanGateway);
    if (st.guestIp) parts.push('guest ' + st.guestIp);
    if (st.status && typeof st.status === 'string') {
      const first = st.status.split('\n')[0];
      if (first && !first.includes(st.vmName || '')) parts.push(first);
    }
    if (detailEl) detailEl.textContent = parts.join(' · ');
  } catch (e) {
    statusEl.textContent = 'Error';
    statusEl.className = 'capture-status disabled';
    if (detailEl) detailEl.textContent = String(e);
  }
}

async function startCapture() {
  const api = await backend();
  if (!api?.StartCaptureWails) {
    alert('Capture API unavailable');
    return;
  }
  const btn = $('#btn-capture-start');
  setBusy(btn, true, 'Starting…');
  try {
    await api.StartCaptureWails();
    toggleLogDrawer(true);
    await refreshCaptureStatus();
  } catch (e) {
    alert(String(e));
  } finally {
    setBusy(btn, false, 'Start');
    await refreshCaptureStatus();
  }
}

async function stopCapture() {
  const api = await backend();
  if (!api?.StopCaptureWails) {
    alert('Capture API unavailable');
    return;
  }
  const btn = $('#btn-capture-stop');
  setBusy(btn, true, 'Stopping…');
  try {
    await api.StopCaptureWails();
    toggleLogDrawer(true);
    await refreshCaptureStatus();
  } catch (e) {
    alert(String(e));
  } finally {
    setBusy(btn, false, 'Stop');
    await refreshCaptureStatus();
  }
}

async function refreshStatus() {
  const api = await backend();
  if (!api?.GetVMStatusWails) {
    $('#vm-status').textContent = 'Wails backend unavailable';
    return;
  }
  const st = await api.GetVMStatusWails();
  let line = `${st.vmName || ''} — ${st.state || 'unknown'}`;
  if (st.networkMode) line += ` · net ${st.networkMode}`;
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
  const warnNote = (m.warnings || []).length
    ? `<ul class="warn-list">${(m.warnings || []).map((w) => `<li>${escapeHtml(w)}</li>`).join('')}</ul>`
    : '';
  panel.innerHTML = `
    <p><strong>${m.fromSnapshot || ''}</strong> → <strong>${m.toSnapshot || ''}</strong></p>
    <p class="muted">Registry source: ${escapeHtml(m.registryDiffSource || s.registryDiffSource || 'manifest')}${
      (m.fromUserRegistryCount || m.toUserRegistryCount)
        ? ` · index entries ${m.fromUserRegistryCount || 0} → ${m.toUserRegistryCount || 0}`
        : ''
    }</p>
    ${noiseNote}
    ${warnNote}
    <div class="stat-grid">
      <div class="stat"><div class="n">${s.filesAdded || 0}</div>Files added</div>
      <div class="stat"><div class="n">${s.filesRemoved || 0}</div>Files removed</div>
      <div class="stat"><div class="n">${s.filesModified || 0}</div>Files modified</div>
      <div class="stat"><div class="n">${s.registryAdded || 0}</div>Registry added</div>
      <div class="stat"><div class="n">${s.registryRemoved || 0}</div>Registry removed</div>
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

function showRegTab(name) {
  regChangeTab = name;
  document.querySelectorAll('.reg-tabs button').forEach((b) => {
    b.classList.toggle('active', b.dataset.regTab === name);
  });
  renderRegistryTree().catch((e) => alert(e));
}

function filterDiffForRegTab(diff, tab) {
  const reg = diff.registry || {};
  return {
    ...diff,
    registry: {
      added: tab === 'added' ? (reg.added || []) : [],
      removed: tab === 'removed' ? (reg.removed || []) : [],
      modified: tab === 'modified' ? (reg.modified || []) : [],
    },
  };
}

function updateRegTabCounts(diff) {
  const reg = diff?.registry || {};
  const setCount = (id, n) => {
    const el = $(id);
    if (el) el.textContent = n ? `(${n})` : '';
  };
  setCount('#reg-count-added', (reg.added || []).length);
  setCount('#reg-count-removed', (reg.removed || []).length);
  setCount('#reg-count-modified', (reg.modified || []).length);
}

function regTabEmptyMessage(tab) {
  if (tab === 'added') return 'No new registry values in this diff.';
  if (tab === 'removed') return 'No deleted registry values in this diff.';
  return 'No changed registry values in this diff.';
}

function expandTreeAncestors(row) {
  let el = row?.parentElement;
  while (el) {
    if (el.classList?.contains('tree-children') && el.classList.contains('collapsed')) {
      el.classList.remove('collapsed');
      const toggleRow = el.previousElementSibling;
      const t = toggleRow?.querySelector?.('.tree-toggle');
      if (t && !t.disabled) {
        t.textContent = '▾';
        t.setAttribute('aria-label', 'Collapse');
      }
    }
    el = el.parentElement;
  }
}

function collectFileLeaves(node, out = []) {
  const children = Object.values(node.children || {});
  if (!children.length) {
    if (node.path) out.push(node);
    return out;
  }
  children.forEach((c) => collectFileLeaves(c, out));
  return out;
}

function collectRegistryLeaves(node, out = []) {
  for (const v of node.values || []) {
    out.push({ path: node.path || '', value: v });
  }
  Object.values(node.children || {}).forEach((c) => collectRegistryLeaves(c, out));
  return out;
}

function formatRegValueData(v) {
  if (v.change === 'modified') {
    return `<span class="reg-before">${escapeHtml(formatRegData(v.before))}</span>` +
      `<span class="reg-arrow">→</span>` +
      `<span class="reg-after">${escapeHtml(formatRegData(v.after ?? v.v))}</span>`;
  }
  return escapeHtml(formatRegData(v.v));
}

function navigateFileLeaf(path, byPath, onSelect) {
  const target = byPath.get(path);
  if (!target) return;
  expandTreeAncestors(target.row);
  $('#file-tree')?.querySelectorAll('.file-row.selected').forEach((el) => el.classList.remove('selected'));
  target.row.classList.add('selected');
  target.row.scrollIntoView({ block: 'nearest' });
  onSelect(target.node);
}

function fillFileFlatPane(node, previewEl, byPath, onSelect) {
  const scope = node.path || node.name || '';
  const leaves = collectFileLeaves(node).sort((a, b) =>
    String(a.path || '').localeCompare(String(b.path || ''), undefined, { sensitivity: 'base' })
  );
  let html = `<div class="reg-path muted">${escapeHtml(scope)}</div>`;
  html += `<div class="reg-section-title">${leaves.length} file${leaves.length === 1 ? '' : 's'} under this folder</div>`;
  if (!leaves.length) {
    html += '<span class="muted">(no files under this node)</span>';
    previewEl.classList.remove('preview-unavailable');
    previewEl.innerHTML = html;
    return;
  }
  html += leaves.map((f) => {
    const changeCls = f.change ? ` change-${f.change}` : '';
    return `<div class="flat-leaf${changeCls}" data-nav-path="${escapeHtml(f.path || '')}">` +
      `<code class="flat-leaf-path">${escapeHtml(f.path || '')}</code>` +
      `<span class="reg-type">${escapeHtml(f.change || 'file')}</span></div>`;
  }).join('');
  previewEl.classList.remove('preview-unavailable');
  previewEl.innerHTML = html;
  previewEl.querySelectorAll('.flat-leaf[data-nav-path]').forEach((el) => {
    el.onclick = () => navigateFileLeaf(el.getAttribute('data-nav-path'), byPath, onSelect);
  });
}

function renderTreeNode(node, container, onSelect, depth = 0, expand = true, byPath = null) {
  if (!node) return;
  const map = byPath || new Map();
  const childrenMap = node.children && typeof node.children === 'object' ? node.children : {};
  const children = Object.values(childrenMap).sort((a, b) =>
    String(a.name || a.path || '').localeCompare(String(b.name || b.path || ''), undefined, { sensitivity: 'base' })
  );
  const hasChildren = children.length > 0;

  const row = document.createElement('div');
  let cls = 'tree-row file-row';
  if (node.change) cls += ` change-${node.change}`;
  if (node.previewUnavailable) cls += ' preview-unavailable';
  row.className = cls;
  row.style.paddingLeft = `${depth * 14}px`;
  row.title = node.previewUnavailable
    ? 'Seen in session; not on snapshot disk'
    : (node.path || '');

  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'tree-toggle';
  toggle.textContent = hasChildren ? (expand ? '▾' : '▸') : '';
  toggle.disabled = !hasChildren;
  toggle.setAttribute('aria-label', expand ? 'Collapse' : 'Expand');

  const label = document.createElement('span');
  label.className = 'tree-label';
  label.textContent = node.name || node.path || '(root)';

  row.appendChild(toggle);
  row.appendChild(label);

  const childHost = document.createElement('div');
  childHost.className = 'tree-children' + (expand ? '' : ' collapsed');

  toggle.onclick = (ev) => {
    ev.stopPropagation();
    if (!hasChildren) return;
    const open = childHost.classList.toggle('collapsed') === false;
    toggle.textContent = open ? '▾' : '▸';
    toggle.setAttribute('aria-label', open ? 'Collapse' : 'Expand');
  };

  if (node.path) {
    map.set(node.path, { row, node, children, hasChildren });
  }

  row.onclick = (ev) => {
    if (ev.target === toggle) return;
    $('#file-tree')?.querySelectorAll('.file-row.selected').forEach((el) => el.classList.remove('selected'));
    row.classList.add('selected');
    if (hasChildren) {
      fillFileFlatPane(node, $('#file-preview'), map, onSelect);
      return;
    }
    onSelect(node);
  };

  container.appendChild(row);
  if (hasChildren) {
    container.appendChild(childHost);
    children.forEach((child) => renderTreeNode(child, childHost, onSelect, depth + 1, depth < 1, map));
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
        const preview = $('#file-preview');
        preview.classList.toggle('preview-unavailable', !!res.unavailable);
        preview.textContent = res.content || '(empty)';
      } else {
        $('#file-preview').textContent = node.path;
      }
    } catch (e) {
      const preview = $('#file-preview');
      preview.classList.remove('preview-unavailable');
      preview.textContent = String(e);
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
      if (i === parts.length - 1) {
        node.change = change;
        if (change === 'added' && isEphemeralTempPath(path)) node.previewUnavailable = true;
      }
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
  values.innerHTML = '<span class="muted">Select a registry key</span>';
  const d = activeDiff();
  if (!d) return;
  updateRegTabCounts(d);
  const filtered = filterDiffForRegTab(d, regChangeTab);
  const reg = filtered.registry || {};
  const count = (reg[regChangeTab] || []).length;
  if (!count) {
    host.innerHTML = `<p class="muted">${regTabEmptyMessage(regChangeTab)}</p>`;
    return;
  }
  const api = await backend();
  const json = JSON.stringify(filtered);
  const tree = api?.BuildRegistryTreeWails ? await api.BuildRegistryTreeWails(json) : null;
  if (!tree) {
    const src = d.meta?.registryDiffSource || '';
    if (src !== 'hive-index' && (d.meta?.toUserRegistryCount ?? d.meta?.fromUserRegistryCount) === 0) {
      host.innerHTML = '<p class="muted">No HKCU registry in manifests — log in as payload user (jkcooper) before capture for user registry diffs.</p>';
    } else {
      host.textContent = 'No registry tree';
    }
    return;
  }
  renderRegistryNode(tree, host, values, 0, true);
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatRegData(v) {
  if (v == null) return '';
  return typeof v === 'string' ? v : JSON.stringify(v);
}

function collectRegSegmentLabels(node, out = new Map()) {
  if (node && node.name && node.label && node.label !== node.name) {
    out.set(node.name, node.label);
  }
  Object.values(node.children || {}).forEach((c) => collectRegSegmentLabels(c, out));
  return out;
}

function friendlyRegPath(path, labels) {
  if (!path || !labels?.size) return path || '';
  return String(path).split('\\').map((part) => {
    if (!part) return part;
    if (labels.has(part)) return labels.get(part);
    for (const [raw, label] of labels) {
      if (raw.toLowerCase() === part.toLowerCase()) return label;
    }
    return part;
  }).join('\\');
}

function navigateRegistryKey(path, byPath, valuesEl, labels, highlightName) {
  const target = byPath.get(path);
  if (!target) return;
  expandTreeAncestors(target.row);
  $('#registry-tree')?.querySelectorAll('.reg-row.selected').forEach((el) => el.classList.remove('selected'));
  target.row.classList.add('selected');
  target.row.scrollIntoView({ block: 'nearest' });
  fillRegistryLocalPane(target.node, valuesEl, labels, highlightName);
}

function fillRegistryLocalPane(node, valuesEl, labels, highlightName) {
  const path = friendlyRegPath(node.path || '', labels);
  const vals = node.values || [];
  let html = `<div class="reg-path muted">${escapeHtml(path)}</div>`;
  if (!vals.length) {
    html += '<span class="muted">(no values at this key)</span>';
    valuesEl.innerHTML = html;
    return;
  }
  html += vals.map((v) => {
    const name = v.n === '' || v.n == null ? '(Default)' : v.n;
    const changeCls = v.change ? ` change-${v.change}` : '';
    const hi = highlightName != null && String(v.n ?? '') === String(highlightName) ? ' flat-leaf-active' : '';
    const typ = v.t || v.afterType || v.beforeType || '';
    return `<div class="reg-value${changeCls}${hi}" data-value-name="${escapeHtml(String(v.n ?? ''))}">` +
      `<code>${escapeHtml(name)}</code>` +
      `<span class="reg-type">${escapeHtml(typ)}</span>` +
      `<span class="reg-data">${formatRegValueData(v)}</span></div>`;
  }).join('');
  valuesEl.innerHTML = html;
  const active = valuesEl.querySelector('.flat-leaf-active');
  if (active) active.scrollIntoView({ block: 'nearest' });
}

function fillRegistryFlatPane(node, valuesEl, byPath, labels) {
  const scope = friendlyRegPath(node.path || '', labels);
  const leaves = collectRegistryLeaves(node).sort((a, b) => {
    const pk = String(a.path || '').localeCompare(String(b.path || ''), undefined, { sensitivity: 'base' });
    if (pk) return pk;
    return String(a.value?.n ?? '').localeCompare(String(b.value?.n ?? ''), undefined, { sensitivity: 'base' });
  });
  let html = `<div class="reg-path muted">${escapeHtml(scope)}</div>`;
  html += `<div class="reg-section-title">${leaves.length} value${leaves.length === 1 ? '' : 's'} under this key</div>`;
  if (!leaves.length) {
    html += '<span class="muted">(no values under this node)</span>';
    valuesEl.innerHTML = html;
    return;
  }
  html += leaves.map((leaf) => {
    const v = leaf.value || {};
    const name = v.n === '' || v.n == null ? '(Default)' : v.n;
    const changeCls = v.change ? ` change-${v.change}` : '';
    const typ = v.t || v.afterType || v.beforeType || '';
    const dispKey = friendlyRegPath(leaf.path || '', labels);
    const full = dispKey ? `${dispKey}\\${name}` : name;
    return `<div class="flat-leaf${changeCls}" data-nav-path="${escapeHtml(leaf.path || '')}" data-value-name="${escapeHtml(String(v.n ?? ''))}">` +
      `<code class="flat-leaf-path">${escapeHtml(full)}</code>` +
      `<span class="reg-type">${escapeHtml(typ || v.change || '')}</span>` +
      `<span class="reg-data">${formatRegValueData(v)}</span></div>`;
  }).join('');
  valuesEl.innerHTML = html;
  valuesEl.querySelectorAll('.flat-leaf[data-nav-path]').forEach((el) => {
    el.onclick = () => {
      navigateRegistryKey(
        el.getAttribute('data-nav-path'),
        byPath,
        valuesEl,
        labels,
        el.getAttribute('data-value-name')
      );
    };
  });
}

function renderRegistryNode(node, container, valuesEl, depth, expand, byPath = null, labels = null) {
  if (!node) return;
  const map = byPath || new Map();
  const sidLabels = labels || collectRegSegmentLabels(node);
  const children = Object.values(node.children || {}).sort((a, b) =>
    String(a.label || a.name || '').localeCompare(String(b.label || b.name || ''), undefined, { sensitivity: 'base' })
  );
  const hasChildren = children.length > 0;
  const isRoot = !node.path && !node.name;

  if (!isRoot) {
    const row = document.createElement('div');
    let cls = 'tree-row reg-row';
    if (node.change) cls += ` change-${node.change}`;
    row.className = cls;
    row.style.paddingLeft = `${depth * 14}px`;
    row.title = node.path || '';

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'tree-toggle';
    toggle.textContent = hasChildren ? (expand ? '▾' : '▸') : '';
    toggle.disabled = !hasChildren;
    toggle.setAttribute('aria-label', expand ? 'Collapse' : 'Expand');

    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = node.label || node.name || node.path || '';
    if (node.label && node.label !== node.name && /^S-1-/i.test(node.name || '')) {
      label.title = node.name;
    } else if (node.path) {
      label.title = node.path;
    }

    row.appendChild(toggle);
    row.appendChild(label);
    if (node.path) {
      map.set(node.path, { row, node, children, hasChildren });
    }
    row.onclick = (ev) => {
      if (ev.target === toggle) return;
      $('#registry-tree')?.querySelectorAll('.reg-row.selected').forEach((el) => el.classList.remove('selected'));
      row.classList.add('selected');
      if (hasChildren) {
        fillRegistryFlatPane(node, valuesEl, map, sidLabels);
      } else {
        fillRegistryLocalPane(node, valuesEl, sidLabels);
      }
    };

    const childHost = document.createElement('div');
    childHost.className = 'tree-children' + (expand ? '' : ' collapsed');

    toggle.onclick = (ev) => {
      ev.stopPropagation();
      if (!hasChildren) return;
      const open = childHost.classList.toggle('collapsed') === false;
      toggle.textContent = open ? '▾' : '▸';
      toggle.setAttribute('aria-label', open ? 'Collapse' : 'Expand');
    };

    container.appendChild(row);
    container.appendChild(childHost);
    children.forEach((c) => renderRegistryNode(c, childHost, valuesEl, depth + 1, depth < 1, map, sidLabels));
    return;
  }

  children.forEach((c) => renderRegistryNode(c, container, valuesEl, depth, true, map, sidLabels));
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
  if (hideNoiseEnabled()) {
    html += '<p class="muted">Routine Microsoft / connectivity noise hidden — uncheck Hide routine noise to show all.</p>';
  }
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
document.querySelectorAll('.file-tabs button[data-file-tab]').forEach((b) => {
  b.addEventListener('click', () => showFileTab(b.dataset.fileTab));
});
document.querySelectorAll('.reg-tabs button[data-reg-tab]').forEach((b) => {
  b.addEventListener('click', () => showRegTab(b.dataset.regTab));
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
$('#btn-capture-start')?.addEventListener('click', () => startCapture());
$('#btn-capture-stop')?.addEventListener('click', () => stopCapture());
$('#btn-capture-refresh')?.addEventListener('click', () => refreshCaptureStatus().catch(alert));
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
  await refreshGatewayStatus();
  await refreshCaptureStatus();
  await loadSnapshots();
  renderOverview();
  setInterval(() => {
    refreshCaptureStatus().catch(() => {});
    refreshGatewayStatus().catch(() => {});
  }, 10000);
})().catch((e) => {
  $('#snap-action-msg').textContent = String(e);
});
