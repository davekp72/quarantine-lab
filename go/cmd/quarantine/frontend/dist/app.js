import { EventsOn } from './wailsjs/runtime/runtime.js';
import { filterDiff, isEphemeralTempPath, isUsnLeafPath } from './noise.js';
import { resolveHttpFlow } from './http_body.js';
import { renderTraffic, invalidateTrafficCache } from './traffic_view.js';
import {
  escapeHtml,
  escapeAttr,
  buildSafeTable,
  setMutedMessage,
  appendMuted,
} from './safe_dom.js';

let diffData = null;
let toSnapshot = '';
let snapshotNames = [];
let logDrawerOpen = false;
let fileChangeTab = 'added';
let regChangeTab = 'added';
let FILE_PREVIEW_MAX_BYTES = 4096 * 1024;

function formatByteSize(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

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

const LOG_LEVEL_RANK = { debug: 10, cmd: 10, info: 20, warn: 30, warning: 30, error: 40 };
const LOG_LEVEL_KEY = 'quarantine.logMinLevel';

function logLevelRank(level) {
  return LOG_LEVEL_RANK[String(level || '').toLowerCase()] || 20;
}

function currentMinLogLevel() {
  const sel = $('#log-level');
  return (sel?.value || localStorage.getItem(LOG_LEVEL_KEY) || 'info').toLowerCase();
}

function activityPassesFilter(entry) {
  return logLevelRank(entry?.level) >= logLevelRank(currentMinLogLevel());
}

function restoreLogLevelSelect() {
  const sel = $('#log-level');
  if (!sel) return;
  const saved = localStorage.getItem(LOG_LEVEL_KEY);
  if (saved && [...sel.options].some((o) => o.value === saved)) {
    sel.value = saved;
  }
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
    const min = currentMinLogLevel();
    let lines = [];
    if (api?.GetAppLogFilteredWails) {
      lines = await api.GetAppLogFilteredWails(min) || [];
    } else if (api?.GetAppLogWails) {
      lines = (await api.GetAppLogWails() || []).filter((e) => logLevelRank(e.level) >= logLevelRank(min));
    }
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
  if (!activityPassesFilter(entry)) return;
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

function parsePortList(s) {
  return String(s || '')
    .split(/[,\s]+/)
    .map((x) => Number(x))
    .filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
}

function fillPermissivePolicyForm(pol) {
  if (!pol) return;
  const tcp = $('#gw-tcp-ports');
  const udp = $('#gw-udp-ports');
  const dns = $('#gw-force-dns');
  const icmp = $('#gw-allow-icmp');
  if (tcp && Array.isArray(pol.tcpPorts)) tcp.value = pol.tcpPorts.join(', ');
  if (udp && Array.isArray(pol.udpPorts)) udp.value = pol.udpPorts.join(', ');
  if (dns) dns.checked = pol.forceDnsToGateway !== false;
  if (icmp) icmp.checked = pol.allowIcmp !== false;
}

async function savePermissivePolicy() {
  const api = await backend();
  if (!api?.SetPermissivePolicyWails) {
    alert('Restart the UI after this update (SetPermissivePolicyWails missing).');
    return;
  }
  const tcp = parsePortList($('#gw-tcp-ports')?.value);
  const udp = parsePortList($('#gw-udp-ports')?.value);
  const forceDns = !!$('#gw-force-dns')?.checked;
  const allowIcmp = !!$('#gw-allow-icmp')?.checked;
  const btn = $('#btn-gw-policy');
  setBusy(btn, true, 'Saving…');
  try {
    const st = await api.SetPermissivePolicyWails(tcp, udp, forceDns, allowIcmp);
    fillPermissivePolicyForm(st?.permissive);
    const el = $('#snap-action-msg');
    if (el) el.textContent = (st?.message || 'Allowlist saved').split('\n')[0];
    await refreshGatewayStatus();
  } finally {
    setBusy(btn, false, 'Save allowlist');
  }
}

async function refreshGatewayStatus() {
  const api = await backend();
  const statusEl = $('#gateway-status');
  const detailEl = $('#gateway-detail');
  const trafficEl = $('#gateway-traffic');
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
    const traffic = (st.trafficMode || 'fakenet').toLowerCase();
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
    if (trafficEl) {
      trafficEl.textContent = traffic === 'fakenet'
        ? 'Traffic: FakeNet sinkhole (no real internet)'
        : 'Traffic: Permissive (allowlisted internet + MITM)';
    }
    fillPermissivePolicyForm(st.permissive);
    const permBtn = $('#btn-gw-permissive');
    const fakeBtn = $('#btn-gw-fakenet');
    if (permBtn) permBtn.classList.toggle('btn-primary', traffic === 'permissive');
    if (fakeBtn) fakeBtn.classList.toggle('btn-primary', traffic === 'fakenet');
    const canSwitch = vmState === 'running';
    if (permBtn) permBtn.disabled = !canSwitch;
    if (fakeBtn) fakeBtn.disabled = !canSwitch;
  } catch (e) {
    statusEl.textContent = 'Error';
    statusEl.className = 'capture-status disabled';
    if (detailEl) detailEl.textContent = String(e);
  }
}

async function setGatewayTrafficMode(mode) {
  const api = await backend();
  if (!api?.SetGatewayTrafficModeWails) {
    alert('Gateway traffic-mode API unavailable');
    return;
  }
  if (mode === 'fakenet') {
    const ok = confirm(
      'Switch gateway to FakeNet sinkhole?\n\n' +
      'The lab guest will lose real internet. FakeNet answers DNS/HTTP/SMTP locally and PCAP still records.\n\n' +
      'OK = sinkhole   Cancel = stay as-is'
    );
    if (!ok) return;
  }
  if (mode === 'permissive') {
    const ok = confirm(
      'Switch gateway to Permissive (real Internet)?\n\n' +
      'This is uncontained WAN for allowlisted ports. HTTP(S) is MITM’d; other listed ports go to the public internet.\n' +
      'Use a VPN. PCAP on the LAN still records every frame, including dropped attempts.\n\n' +
      'OK = open allowlisted internet   Cancel = stay FakeNet'
    );
    if (!ok) return;
  }
  const btn = mode === 'fakenet' ? $('#btn-gw-fakenet') : $('#btn-gw-permissive');
  const label = mode === 'fakenet' ? 'FakeNet' : 'Permissive';
  setBusy(btn, true, 'Switching…');
  try {
    const st = await api.SetGatewayTrafficModeWails(mode);
    if (st?.message) {
      const detailEl = $('#gateway-detail');
      if (detailEl) detailEl.textContent = String(st.message).split('\n')[0];
      // Gateway switch already applied; guest probe failures are warnings only.
      if (/WARNING:/i.test(String(st.message))) {
        alert(String(st.message));
      }
    }
    await refreshGatewayStatus();
  } catch (e) {
    alert(String(e));
  } finally {
    setBusy(btn, false, label);
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

let statusRefreshInFlight = false;

async function refreshStatus() {
  if (statusRefreshInFlight) return;
  statusRefreshInFlight = true;
  try {
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
        const payload = st.agentPayloadSession === 'true' ? '' : ' (payload user not logged in — HKCU diff empty)';
        agentEl.textContent = `Agent OK — Sysmon ${st.agentSysmon === 'true' ? 'on' : 'off'}${usn}${payload}`;
      } else {
        agentEl.textContent = st.agentError || 'Agent not installed';
      }
    }
  } finally {
    statusRefreshInFlight = false;
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

function showEgressDialog(snapshotName, info) {
  return new Promise((resolve) => {
    const lookedUp = !!(info && info.lookedUp);
    const home = !!(info && info.homeIsp);
    const tone = !lookedUp ? 'unknown' : home ? 'home' : 'ok';
    const isp = (info && (info.isp || info.org)) || '';

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'egress-title');

    const modal = document.createElement('div');
    modal.className = `modal egress-modal egress-${tone}`;

    const title = document.createElement('h2');
    title.id = 'egress-title';
    title.textContent = 'VPN / public IP check';
    modal.appendChild(title);

    const about = document.createElement('p');
    about.className = 'egress-about';
    about.textContent = `About to launch: ${snapshotName}`;
    modal.appendChild(about);

    if (lookedUp) {
      const ip = document.createElement('p');
      ip.textContent = `Your host public IP address is: ${info.ip || '?'}`;
      modal.appendChild(ip);

      if (isp) {
        const ispRow = document.createElement('p');
        ispRow.className = 'egress-isp-row';
        ispRow.append('ISP / org: ');
        const name = document.createElement('span');
        name.className = `egress-isp-name ${tone}`;
        name.textContent = isp;
        ispRow.appendChild(name);
        modal.appendChild(ispRow);
      }

      const loc = [info.city, info.region, info.country].filter(Boolean).join(', ');
      if (loc) {
        const locEl = document.createElement('p');
        locEl.className = 'muted';
        locEl.textContent = `Location: ${loc}`;
        modal.appendChild(locEl);
      }
      if (info.source) {
        const src = document.createElement('p');
        src.className = 'muted';
        src.textContent = `(lookup: ${info.source})`;
        modal.appendChild(src);
      }
    } else {
      const fail = document.createElement('p');
      fail.textContent = 'Could not look up your public IP.';
      modal.appendChild(fail);
      if (info && info.error) {
        const err = document.createElement('p');
        err.className = 'muted';
        err.textContent = `Error: ${info.error}`;
        modal.appendChild(err);
      }
    }

    const warn = document.createElement('p');
    warn.className = 'egress-warning';
    warn.textContent = (info && info.warning) || 'Confirm this is your VPN egress (not your home ISP) before malware work.';
    modal.appendChild(warn);

    const actions = document.createElement('div');
    actions.className = 'modal-actions';
    const ok = document.createElement('button');
    ok.type = 'button';
    ok.className = 'btn-primary';
    ok.textContent = 'Launch anyway';
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    actions.append(ok, cancel);
    modal.appendChild(actions);
    overlay.appendChild(modal);

    const close = (result) => {
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      resolve(result);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') close(false);
    };
    ok.addEventListener('click', () => close(true));
    cancel.addEventListener('click', () => close(false));
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) close(false);
    });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(overlay);
    (home || !lookedUp ? cancel : ok).focus();
  });
}

async function confirmVPNBeforeLaunch(api, snapshotName) {
  let warn = true;
  try {
    if (typeof api.ShouldWarnPublicIPBeforeLaunchWails === 'function') {
      warn = await api.ShouldWarnPublicIPBeforeLaunchWails();
    }
  } catch (_) { /* default on */ }
  if (!warn) return true;

  let info = null;
  try {
    if (typeof api.CheckHostPublicIPWails === 'function') {
      info = await api.CheckHostPublicIPWails();
    }
  } catch (e) {
    info = { lookedUp: false, error: String(e), warning: 'Public IP lookup failed. Verify your VPN is on before launching.' };
  }

  return showEgressDialog(snapshotName, info);
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
  setBusy(btn, true, 'Checking IP…');
  msg.textContent = 'Checking host public IP (VPN)…';
  try {
    const ok = await confirmVPNBeforeLaunch(api, name);
    if (!ok) {
      msg.textContent = 'Launch cancelled — turn on VPN if needed, then try again';
      return;
    }
    setBusy(btn, true, 'Launching…');
    msg.textContent = `Restoring and starting ${name}…`;
    const result = await api.LaunchSnapshotWails(name, false);
    msg.textContent = result || `Launched: ${name}`;
    await refreshStatus();
    await refreshCaptureStatus();
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
  msg.textContent = 'Preserving evidence… (stops capture, then snapshot)';
  try {
    const name = await api.PreserveEvidenceWails('');
    msg.textContent = `Evidence: ${name}`;
    await loadSnapshots($('#from-snap').value, name);
    await refreshStatus();
    await refreshCaptureStatus();
  } catch (e) {
    msg.textContent = String(e);
  } finally {
    setBusy(btn, false, 'Preserve evidence');
  }
}

function showTab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${name}`));
  if (name === 'traffic') {
    renderTrafficPanel().catch((e) => {
      const panel = $('#panel-traffic');
      if (panel) setMutedMessage(panel, String(e));
    });
  }
}

function applyUISettings(st, applySession) {
  if (!st) return;
  const kb = Number(st.filePreviewMaxKb) || 4096;
  FILE_PREVIEW_MAX_BYTES = Number(st.filePreviewMaxBytes) || kb * 1024;
  const previewEl = $('#ui-preview-max-kb');
  if (previewEl) previewEl.value = String(kb);
  const contentEl = $('#ui-content-max-kb');
  if (contentEl) contentEl.value = String(Number(st.contentMaxKb) || 51200);
  const hashEl = $('#ui-hash-max-mb');
  if (hashEl) hashEl.value = String(Number(st.hashMaxMb) || 100);
  const totalEl = $('#ui-total-embed-max-mb');
  if (totalEl) totalEl.value = String(Number(st.totalEmbedMaxMb) || 256);
  const hide = st.hideRoutineNoise !== false;
  const refresh = st.refreshOnCompare !== false;
  const warn = st.warnPublicIpBeforeLaunch !== false;
  const hideEl = $('#ui-hide-noise');
  if (hideEl) hideEl.checked = hide;
  const refEl = $('#ui-refresh-compare');
  if (refEl) refEl.checked = refresh;
  const warnEl = $('#ui-warn-ip');
  if (warnEl) warnEl.checked = warn;
  const ispEl = $('#ui-home-isp');
  if (ispEl) ispEl.value = st.homeIspPatternsText || (st.homeIspPatterns || []).join(', ');
  if (applySession) {
    const barHide = $('#hideNoise');
    if (barHide) barHide.checked = hide;
    const barRefresh = $('#refresh');
    if (barRefresh) barRefresh.checked = refresh;
  }
}

function openSettings() {
  const overlay = $('#settings-overlay');
  if (!overlay) return;
  overlay.classList.remove('hidden');
  const msg = $('#ui-save-msg');
  if (msg) msg.textContent = '';
  $('#ui-preview-max-kb')?.focus();
}

function closeSettings() {
  $('#settings-overlay')?.classList.add('hidden');
}

async function loadUISettings() {
  const api = await backend();
  if (!api?.UISettingsWails) return;
  applyUISettings(await api.UISettingsWails(), true);
}

async function saveUISettings() {
  const api = await backend();
  const msg = $('#ui-save-msg');
  if (!api?.SetUISettingsWails) {
    if (msg) msg.textContent = 'Restart the UI after this update (SetUISettingsWails missing).';
    return;
  }
  const kb = Number($('#ui-preview-max-kb')?.value) || 4096;
  const contentKb = Number($('#ui-content-max-kb')?.value) || 51200;
  const hashMb = Number($('#ui-hash-max-mb')?.value) || 100;
  const totalMb = Number($('#ui-total-embed-max-mb')?.value) || 256;
  const btn = $('#btn-ui-save');
  setBusy(btn, true, 'Saving…');
  try {
    const st = await api.SetUISettingsWails(
      kb,
      !!$('#ui-hide-noise')?.checked,
      !!$('#ui-refresh-compare')?.checked,
      !!$('#ui-warn-ip')?.checked,
      $('#ui-home-isp')?.value || '',
      contentKb,
      hashMb,
      totalMb,
    );
    applyUISettings(st, true);
    if (msg) msg.textContent = 'Saved';
    if (diffData) await rerenderDiff();
    setTimeout(() => closeSettings(), 400);
  } catch (e) {
    if (msg) msg.textContent = String(e);
  } finally {
    setBusy(btn, false, 'Save');
  }
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
    setMutedMessage(panel, 'Pick From/To snapshots and click Compare.');
    return;
  }
  const d = activeDiff();
  const s = d.summary || {};
  const m = d.meta || {};
  panel.replaceChildren();

  const title = document.createElement('p');
  const fromEl = document.createElement('strong');
  fromEl.textContent = m.fromSnapshot || '';
  const toEl = document.createElement('strong');
  toEl.textContent = m.toSnapshot || '';
  title.appendChild(fromEl);
  title.appendChild(document.createTextNode(' → '));
  title.appendChild(toEl);
  panel.appendChild(title);

  let regLine = `Registry source: ${m.registryDiffSource || s.registryDiffSource || 'manifest'}`;
  if (m.fromUserRegistryCount || m.toUserRegistryCount) {
    regLine += ` · index entries ${m.fromUserRegistryCount || 0} → ${m.toUserRegistryCount || 0}`;
  }
  appendMuted(panel, regLine);
  if (hideNoiseEnabled()) {
    appendMuted(panel, 'Routine noise hidden — uncheck to show all changes.');
  }
  if ((m.warnings || []).length) {
    const ul = document.createElement('ul');
    ul.className = 'warn-list';
	for (const w of m.warnings) {
      const text = w == null ? '' : String(w);
      if (/^source:/i.test(text.trim())) continue;
      const li = document.createElement('li');
      li.textContent = text;
      ul.appendChild(li);
    }
    if (ul.childElementCount) {
      panel.appendChild(ul);
    }
  }

  const grid = document.createElement('div');
  grid.className = 'stat-grid';
  const stats = [
    [s.filesAdded || 0, 'Files added'],
    [s.filesRemoved || 0, 'Files removed'],
    [s.filesModified || 0, 'Files modified'],
    [s.registryAdded || 0, 'Registry added'],
    [s.registryRemoved || 0, 'Registry removed'],
    [s.registryModified || 0, 'Registry modified'],
    [s.sysmonAdded || 0, 'Sysmon events'],
    [s.dnsQueries || 0, 'DNS lookups'],
    [s.networkRequests || 0, 'HTTP/proxy'],
  ];
  for (const [n, label] of stats) {
    const stat = document.createElement('div');
    stat.className = 'stat';
    const num = document.createElement('div');
    num.className = 'n';
    num.textContent = String(n);
    stat.appendChild(num);
    stat.appendChild(document.createTextNode(label));
    grid.appendChild(stat);
  }
  panel.appendChild(grid);
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
    const preview = $('#file-preview');
    const knownSize = Number(node.size) || 0;
    if (knownSize > FILE_PREVIEW_MAX_BYTES) {
      preview.classList.add('preview-unavailable');
      preview.textContent = `Preview skipped — file is ${formatByteSize(knownSize)} (limit ${formatByteSize(FILE_PREVIEW_MAX_BYTES)}).\n\nPath: ${node.path}`;
      return;
    }
    preview.textContent = 'Loading...';
    toSnapshot = diffData.meta?.toSnapshot || $('#to-snap').value;
    const fromSnapshot = diffData.meta?.fromSnapshot || $('#from-snap')?.value || '';
    const change = node.change || fileChangeTab;
    try {
      if (change === 'modified' && fromSnapshot && api?.DiffSnapshotFileWails) {
        const res = await api.DiffSnapshotFileWails(fromSnapshot, toSnapshot, node.path);
        const unavailable = !!(res.unavailable || res.toUnavailable);
        preview.classList.toggle('preview-unavailable', unavailable);
        if (unavailable && !res.fromContent && !res.toContent) {
          preview.textContent = res.content || res.toError || res.fromError || '(unavailable)';
        } else {
          const note = res.fromNote
            ? `<div class="muted preview-note">${escapeHtml(String(res.fromNote))}</div>`
            : '';
          const src = res.toSource || res.source
            ? `<div class="muted preview-note">source: ${escapeHtml(String(res.toSource || res.source))}` +
              (res.fromSource ? ` / before: ${escapeHtml(String(res.fromSource))}` : '') +
              `</div>`
            : '';
          preview.innerHTML = src + note + renderFileLineDiff(
            String(res.fromContent || ''),
            String(res.toContent || '')
          );
        }
      } else if (change === 'removed' && api?.ReadSnapshotFileWails) {
        // Removed rows live on the Evidence (To) sidecar — do not flatten CleanSession.
        const res = await api.ReadSnapshotFileWails(toSnapshot, node.path);
        preview.classList.toggle('preview-unavailable', !!res.unavailable);
        const src = res.source ? `source: ${res.source}\n\n` : '';
        preview.textContent = src + (res.content || '(deleted — no embedded content)');
      } else if (api?.ReadSnapshotFileWails) {
        const res = await api.ReadSnapshotFileWails(toSnapshot, node.path);
        preview.classList.toggle('preview-unavailable', !!res.unavailable);
        const src = res.source ? `source: ${res.source}\n\n` : '';
        preview.textContent = src + (res.content || '(empty)');
      } else {
        preview.textContent = node.path;
      }
    } catch (e) {
      preview.classList.remove('preview-unavailable');
      preview.textContent = String(e);
    }
  });
}

function simpleLineDiff(before, after) {
  const a = String(before || '').split('\n');
  const b = String(after || '').split('\n');
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

function renderFileLineDiff(before, after) {
  return simpleLineDiff(before, after).map((line) => {
    const cls = line.kind === 'add' ? 'diff-line-add' : line.kind === 'del' ? 'diff-line-del' : 'diff-line-same';
    const prefix = line.kind === 'add' ? '+ ' : line.kind === 'del' ? '- ' : '  ';
    return `<span class="${cls}">${escapeHtml(prefix + line.text)}</span>`;
  }).join('');
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
        if (file?.size) node.size = file.size;
        if (file?.noise) node.noise = file.noise;
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
      host.innerHTML = '<p class="muted">No HKCU registry in manifests — log in as the payload user before capture for user registry diffs.</p>';
    } else {
      host.textContent = 'No registry tree';
    }
    return;
  }
  renderRegistryNode(tree, host, values, 0, true);
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
    setMutedMessage(panel, 'No Sysmon events in diff.');
    return;
  }
  panel.replaceChildren(buildSafeTable(
    ['Time', 'EID', 'Target'],
    rows.slice(0, 500).map((e) => ({
      cells: [
        e.time || e.t || '',
        e.eid || '',
        e.target || e.targetFilename || e.image || e.queryName || '',
      ],
    })),
  ));
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
    setMutedMessage(panel, 'No USN events in diff.');
    return;
  }
  panel.replaceChildren(buildSafeTable(
    ['File', 'Reasons', 'USN'],
    rows.slice(0, 500).map((e) => ({
      cells: [e.fileName || '', usnReasonText(e), e.usn || ''],
    })),
  ));
}

const NETWORK_DISPLAY_LIMIT = 5000;
let httpDomainFilter = '';

/** Prefer newest rows when capping so the list bottom matches latest activity. */
function networkRowsForDisplay(rows, limit = NETWORK_DISPLAY_LIMIT) {
  const all = Array.isArray(rows) ? rows : [];
  if (all.length <= limit) {
    return { rows: all, offset: 0, capped: false, total: all.length };
  }
  const offset = all.length - limit;
  return { rows: all.slice(offset), offset, capped: true, total: all.length };
}

function httpRequestHost(r) {
  const host = String(r?.host || '').trim();
  if (host) return host;
  try {
    if (r?.url) return new URL(r.url).hostname || '';
  } catch (_) { /* plain path */ }
  return '';
}

function httpRequestMatchesDomain(r, q) {
  const needle = String(q || '').trim().toLowerCase();
  if (!needle) return true;
  const host = httpRequestHost(r).toLowerCase();
  const url = String(r?.url || r?.path || '').toLowerCase();
  if (!host && !url) return false;
  return host === needle
    || host.endsWith(`.${needle}`)
    || host.includes(needle)
    || url.includes(needle);
}

function renderNetwork() {
  const panel = $('#panel-network');
  const d = activeDiff();
  const net = d?.network;
  if (!net) {
    setMutedMessage(panel, 'No network section in this diff.');
    return;
  }
  const prevDomainFocus = document.activeElement?.id === 'http-domain' ? {
    start: document.activeElement.selectionStart,
    end: document.activeElement.selectionEnd,
  } : null;
  const allReqs = net.requests || [];
  const filtered = allReqs.filter((r) => httpRequestMatchesDomain(r, httpDomainFilter));
  const shown = networkRowsForDisplay(filtered);
  const domains = [...new Set(allReqs.map(httpRequestHost).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const windowText = net.windowFrom && net.windowTo
    ? `${net.windowFrom} → ${net.windowTo}`
    : 'snapshot capture window';
  panel.replaceChildren();
  const countText = httpDomainFilter.trim()
    ? `${filtered.length} of ${allReqs.length} HTTP/proxy`
    : `${allReqs.length} HTTP/proxy`;
  appendMuted(panel, `${windowText} · ${countText}`);
  if (shown.capped) {
    appendMuted(panel, `Showing latest ${shown.rows.length} of ${shown.total} (older rows omitted).`);
  }

  const bar = document.createElement('div');
  bar.className = 'traffic-filters';
  const domainLabel = document.createElement('label');
  domainLabel.textContent = 'Domain';
  const domainSel = document.createElement('select');
  domainSel.id = 'http-domain-select';
  const allOpt = document.createElement('option');
  allOpt.value = '';
  allOpt.textContent = 'All domains';
  domainSel.appendChild(allOpt);
  for (const host of domains) {
    const opt = document.createElement('option');
    opt.value = host;
    opt.textContent = host;
    domainSel.appendChild(opt);
  }
  const exactMatch = domains.find((h) => h.toLowerCase() === httpDomainFilter.trim().toLowerCase());
  domainSel.value = exactMatch || '';
  domainSel.addEventListener('change', () => {
    httpDomainFilter = domainSel.value;
    renderNetwork();
  });
  domainLabel.appendChild(domainSel);
  bar.appendChild(domainLabel);

  const searchLabel = document.createElement('label');
  searchLabel.textContent = 'Filter';
  const searchInput = document.createElement('input');
  searchInput.type = 'search';
  searchInput.id = 'http-domain';
  searchInput.placeholder = 'whatsapp.com, /api/, status…';
  searchInput.value = httpDomainFilter;
  searchInput.addEventListener('input', () => {
    httpDomainFilter = searchInput.value;
    renderNetwork();
  });
  searchLabel.appendChild(searchInput);
  bar.appendChild(searchLabel);
  panel.appendChild(bar);
  if (prevDomainFocus) {
    searchInput.focus();
    try { searchInput.setSelectionRange(prevDomainFocus.start, prevDomainFocus.end); } catch (_) { /* ignore */ }
  }

  if (!allReqs.length) {
    appendMuted(panel, 'No HTTP/proxy requests in this window. DNS is on the DNS tab.');
    return;
  }
  if (!filtered.length) {
    appendMuted(panel, 'No HTTP/proxy requests match the domain filter.');
    return;
  }

  const split = document.createElement('div');
  split.className = 'network-split';
  const list = document.createElement('div');
  list.className = 'net-req-list';
  const table = buildSafeTable(
    ['Method', 'Status', 'Host', 'URL', 'Time'],
    shown.rows.map((r, i) => ({
      className: `net-req-row${r.hasBody ? ' has-body' : ''}`,
      attrs: { 'data-req-idx': String(shown.offset + i) },
      cells: [
        r.method || '',
        r.status ?? '',
        r.host || '',
        { text: truncate(r.url || r.path || '', 80), title: r.url || '' },
        { text: formatListTime(r.t), title: r.t || '' },
      ],
    })),
  );
  table.id = 'net-req-table';
  list.appendChild(table);
  const detail = document.createElement('div');
  detail.id = 'net-req-detail';
  detail.className = 'net-req-detail muted';
  detail.textContent = 'Click a request to view decrypted request/response (mitm).';
  split.appendChild(list);
  split.appendChild(detail);
  panel.appendChild(split);

  panel.querySelectorAll('.net-req-row').forEach((tr) => {
    tr.addEventListener('click', () => {
      panel.querySelectorAll('.net-req-row.selected').forEach((x) => x.classList.remove('selected'));
      tr.classList.add('selected');
      const idx = Number(tr.getAttribute('data-req-idx'));
      const r = filtered[idx];
      const detailEl = panel.querySelector('#net-req-detail');
      if (!detailEl || !r) return;
      detailEl.classList.remove('muted');
      detailEl.replaceChildren();
      appendMuted(detailEl, 'Loading body…');
      (async () => {
        const api = await backend();
        const decoded = await resolveHttpFlow(r, api || {});
        if (!detailEl.isConnected) return;
        detailEl.innerHTML = renderHttpFlowHtml(decoded);
        if (decoded.loadError) {
          appendMuted(detailEl, `Flow file load: ${decoded.loadError}`);
        }
      })().catch((e) => {
        if (!detailEl.isConnected) return;
        detailEl.innerHTML = renderHttpFlowHtml(r);
        appendMuted(detailEl, `Decode: ${String(e)}`);
      });
    });
  });
}

function renderDns() {
  const panel = $('#panel-dns');
  if (!panel) return;
  const d = activeDiff();
  const net = d?.network;
  if (!net) {
    setMutedMessage(panel, 'No network section in this diff.');
    return;
  }
  const dns = net.dns || [];
  const shown = networkRowsForDisplay(dns);
  const windowText = net.windowFrom && net.windowTo
    ? `${net.windowFrom} → ${net.windowTo}`
    : 'snapshot capture window';
  panel.replaceChildren();
  appendMuted(panel, `${windowText} · ${dns.length} name lookups`);
  if (shown.capped) {
    appendMuted(panel, `Showing latest ${shown.rows.length} of ${shown.total} (older rows omitted).`);
  }
  if (!dns.length) {
    appendMuted(panel, 'No DNS / host resolution entries in this window.');
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'dns-table-wrap';
  const table = buildSafeTable(
    ['Source', 'Name', 'Resolved', 'Type', 'Time'],
    shown.rows.map((r) => {
      const answers = Array.isArray(r.answers) ? r.answers.filter(Boolean).join(', ') : '';
      return {
        cells: [
          r.source || '',
          r.qname || r.query || '',
          answers || '—',
          r.qtype || r.type || '',
          r.t || '',
        ],
      };
    }),
  );
  table.id = 'dns-table';
  wrap.appendChild(table);
  panel.appendChild(wrap);
}

function truncate(s, n) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** Compact UTC time for list columns: nearest second, no fractional noise. */
function formatListTime(t) {
  const raw = String(t || '').trim();
  if (!raw) return '';
  const m = raw.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
  if (m) return `${m[1]} ${m[2]}Z`;
  const d = new Date(raw);
  if (!Number.isNaN(d.getTime())) {
    return d.toISOString().replace(/\.\d{3}Z$/, 'Z').replace('T', ' ');
  }
  return raw;
}

function renderHttpFlowPartHtml(title, p) {
  if (!p) {
    return `<div class="http-flow-pane">
  <div class="http-flow-pane-head">${escapeAttr(title)}</div>
  <div class="http-flow-pane-scroll"><p class="muted">(none)</p></div>
</div>`;
  }
  const bits = [];
  if (p.contentType) bits.push(p.contentType);
  if (p.bodyBytes != null) bits.push(`${p.bodyBytes} bytes`);
  if (p.bodyTruncated) bits.push('truncated');
  if (p.decompressed) bits.push(`decompressed:${p.decompressed}`);
  else if (p.encoding && p.encoding !== 'utf-8') bits.push(p.encoding);
  if (p.decodeError) bits.push(`decode-error`);
  const hdrs = p.headers && typeof p.headers === 'object'
    ? Object.entries(p.headers).map(([k, v]) => `${k}: ${v}`).join('\n')
    : '';
  const bodyText = p.decodeError
    ? `(decompress failed: ${p.decodeError})\n\n${p.body != null ? p.body : ''}`
    : (p.body != null && p.body !== '' ? p.body : '');
  const hl = (typeof QuarantineHighlight !== 'undefined' && QuarantineHighlight.highlightBody)
    ? QuarantineHighlight.highlightBody(bodyText, p.contentType || '')
    : { html: escapeAttr(bodyText || '(empty body)'), lang: 'plain', pretty: false };
  if (hl.pretty) bits.push('pretty');
  if (hl.lang && hl.lang !== 'plain') bits.push(hl.lang);
  const hdrHtml = hdrs
    ? ((typeof QuarantineHighlight !== 'undefined' && QuarantineHighlight.highlightHeaders)
      ? QuarantineHighlight.highlightHeaders(hdrs)
      : escapeAttr(hdrs))
    : '';
  const bodyHtml = (p.body == null || p.body === '') && !p.decodeError
    ? escapeAttr('(empty body)')
    : hl.html;
  return `<div class="http-flow-pane">
  <div class="http-flow-pane-head">${escapeAttr(title)}${bits.length ? ` · <span class="muted">${escapeAttr(bits.join(' · '))}</span>` : ''}</div>
  <div class="http-flow-pane-scroll">
    ${hdrHtml ? `<pre class="content-block headers hl-code">${hdrHtml}</pre>` : ''}
    <pre class="content-block body hl-code lang-${escapeAttr(hl.lang || 'plain')}">${bodyHtml}</pre>
  </div>
</div>`;
}

function renderHttpFlowHtml(n) {
  if (!n.hasBody && !n.request && !n.response) {
    return `<p><strong>${escapeAttr(n.method || '')}</strong> ${escapeAttr(n.url || '')}</p>
<p class="muted">No decrypted body in this evidence. Start a new Launch (updates mitm) → browse → Preserve, then Compare.</p>
<pre class="content-block">${escapeAttr(JSON.stringify(n, null, 2))}</pre>`;
  }
  const resolved = Array.isArray(n.resolvedIps) ? n.resolvedIps.filter(Boolean).join(', ') : '';
  return `<div class="http-flow-meta">
  <p><strong>${escapeAttr(n.method || '')}</strong> ${escapeAttr(n.url || '')}
 ${n.status != null ? `· <em>${n.status}</em>` : ''} · ${escapeAttr(n.source || '')}</p>
  ${resolved ? `<p class="muted">Resolved → ${escapeAttr(resolved)}</p>` : ''}
</div>
<div class="http-flow-panes">
  ${renderHttpFlowPartHtml('Request', n.request)}
  ${renderHttpFlowPartHtml(n.status != null ? `Response (${n.status})` : 'Response', n.response)}
</div>`;
}

async function rerenderDiff() {
  if (!diffData) return;
  renderOverview();
  await renderFileTree();
  await renderRegistryTree();
  renderSysmon();
  renderUsn();
  renderNetwork();
  renderDns();
  renderTrafficPanel().catch(() => {});
}

async function renderTrafficPanel() {
  const panel = $('#panel-traffic');
  if (!panel || !panel.classList.contains('active')) return;
  await renderTraffic(panel, {
    snapshot: toSnapshot || $('#to-snap')?.value || '',
    hideNoise: hideNoiseEnabled(),
    backend,
  });
}

async function loadDiff(jsonStr) {
  diffData = JSON.parse(jsonStr);
  toSnapshot = diffData.meta?.toSnapshot || $('#to-snap').value;
  httpDomainFilter = '';
  invalidateTrafficCache();
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
$('#btn-settings')?.addEventListener('click', () => {
  loadUISettings().then(() => openSettings()).catch((e) => alert(e));
});
$('#btn-settings-close')?.addEventListener('click', () => closeSettings());
$('#btn-settings-cancel')?.addEventListener('click', () => closeSettings());
$('#settings-overlay')?.addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeSettings();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#settings-overlay')?.classList.contains('hidden')) {
    closeSettings();
  }
});
$('#btn-ui-save')?.addEventListener('click', () => saveUISettings().catch((e) => {
  const el = $('#ui-save-msg');
  if (el) el.textContent = String(e);
}));
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
  setBusy(btn, true, 'Staging…');
  try {
    const msg = await api.InstallAgentWails();
    $('#snap-action-msg').textContent = msg || 'Agent staged — run install script elevated in guest';
    toggleLogDrawer(true);
    await refreshStatus();
  } catch (e) {
    alert(String(e));
  } finally {
    setBusy(btn, false, 'Stage VM agent');
  }
});
$('#btn-capture-start')?.addEventListener('click', () => startCapture());
$('#btn-capture-stop')?.addEventListener('click', () => stopCapture());
$('#btn-capture-refresh')?.addEventListener('click', () => refreshCaptureStatus().catch(alert));
$('#btn-gw-permissive')?.addEventListener('click', () => setGatewayTrafficMode('permissive').catch(alert));
$('#btn-gw-fakenet')?.addEventListener('click', () => setGatewayTrafficMode('fakenet').catch(alert));
$('#btn-gw-policy')?.addEventListener('click', () => savePermissivePolicy().catch(alert));
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
$('#log-level')?.addEventListener('change', () => {
  localStorage.setItem(LOG_LEVEL_KEY, currentMinLogLevel());
  refreshLogView().catch((e) => renderLogView(String(e)));
});

EventsOn('applog', (entry) => {
  if (!logDrawerOpen || $('#log-source').value !== 'activity') return;
  appendActivityLine(entry);
});

(async () => {
  restoreLogLevelSelect();
  // Load panels independently so one slow/hung call cannot leave the whole UI on "Loading…".
  const results = await Promise.allSettled([
    loadUISettings(),
    refreshStatus(),
    refreshGatewayStatus(),
    refreshCaptureStatus(),
    loadSnapshots(),
  ]);
  const failed = results.filter((r) => r.status === 'rejected');
  if (failed.length) {
    const msg = failed.map((r) => String(r.reason)).join('; ');
    const el = $('#snap-action-msg');
    if (el) el.textContent = msg;
    if ($('#vm-status')?.textContent === 'Loading...') {
      $('#vm-status').textContent = 'Status error — see activity log';
    }
  }
  renderOverview();
  setInterval(() => {
    refreshStatus().catch(() => {});
    refreshCaptureStatus().catch(() => {});
    refreshGatewayStatus().catch(() => {});
  }, 10000);
})().catch((e) => {
  $('#snap-action-msg').textContent = String(e);
  if ($('#vm-status')?.textContent === 'Loading...') {
    $('#vm-status').textContent = 'Failed to load';
  }
});
