(function () {
  'use strict';

  const HIGH_SIGNAL_FILE_EXTENSIONS = /\.(exe|dll|sys|ps1|bat|cmd|vbs|js|hta|lnk)$/i;

  /** WebView2/Chromium churn under Client.CBS — narrow paths only, not the whole package. */
  const EBWEBVIEW_NOISE_PATTERNS = [
    /\\EBWebView\\Default\\[^\\]+\.tmp$/i,
    /\\EBWebView\\Default\\Cache\\/i,
    /\\EBWebView\\Default\\Code Cache\\/i,
    /\\EBWebView\\Default\\GPUCache\\/i,
    /\\EBWebView\\Default\\Service Worker\\CacheStorage\\/i
  ];

  const EBWEBVIEW_PATH = /\\EBWebView\\/i;
  const LARGE_WEBVIEW_FILE_BYTES = 2 * 1024 * 1024;

  /** Windows Error Reporting report queue/archive churn (not malware-relevant). */
  const WER_NOISE_PATTERNS = [
    /\\ProgramData\\Microsoft\\Windows\\WER\\/i,
    /\\Microsoft\\Windows\\WER\\/i
  ];

  const PERSISTENCE_REGISTRY_KEY_PATTERNS = [
    /\\CurrentVersion\\Run$/i,
    /\\CurrentVersion\\RunOnce/i,
    /\\Policies\\Explorer\\Run/i,
    /\\Winlogon\\/i,
    /\\Services\\/i,
    /\\StartupApproved\\Run/i
  ];

  let persistenceReferencedPaths = new Set();

  const NOISE_PATTERNS = [
    /\\Microsoft\\EdgeUpdate\\/i,
    /\\Microsoft\\OneDrive\\ListSync/i,
    /\\Microsoft\\Windows\\AppRepository\\/i,
    /\\Microsoft\\InstallService\\/i,
    /\\Users\\Public\\Quarantine\\/i,
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

  const NETWORK_HOST_SUFFIXES = [
    'msftconnecttest.com',
    'microsoft.com',
    'microsoft.net',
    'msn.com',
    'bing.com',
    'windowsupdate.com',
    'office.com',
    'office365.com',
    'live.com',
    'microsoftpersonalcontent.com',
    'onedrive.com',
    'sharepoint.com',
    'skype.com',
    'windows.com',
    'xboxlive.com',
    'xboxab.com',
    'azure.com',
    'azureedge.net',
    'trafficmanager.net',
    'msedge.net',
    'msauth.net',
    'msidentity.com',
    'hotmail.com',
    'outlook.com',
    'visualstudio.com',
    'digicert.com',
    'akamaihd.net',
    'akamaiedge.net',
    'akamai.net',
    'aspnetcdn.com',
    'windows.net',
    'officeapps.live.com',
    'mp.microsoft.com',
    'events.data.microsoft.com',
    'data.microsoft.com',
    'telemetry.microsoft.com',
    'msftncsi.com',
    'cloud.microsoft',
    'office.net',
    'sfx.ms',
    's-microsoft.com',
    'akamaized.net'
  ];

  const NETWORK_NOISE_PATTERNS = [
    // Routine OS / Microsoft connectivity and telemetry (wildcard-style)
    /\.msftconnecttest\.com/i,
    /\.microsoft\.com(\/|$)/i,
    /\.msn\.com(\/|$)/i,
    /\.bing\.com(\/|$)/i,
    /\.windowsupdate\.com(\/|$)/i,
    /\.office\.com(\/|$)/i,
    /\.live\.com(\/|$)/i,
    /\.microsoftpersonalcontent\.com(\/|$)/i,
    /\.onedrive\.com(\/|$)/i,
    /\.microsoft\.net(\/|$)/i,
    /\.windows\.com(\/|$)/i,
    /\.update\.microsoft\.com(\/|$)/i,
    /\.mp\.microsoft\.com(\/|$)/i,
    /\.data\.microsoft\.com(\/|$)/i,
    /msftncsi\.com/i,
    /\.office365\.com(\/|$)/i,
    /\.msauth\.net(\/|$)/i,
    /\.msidentity\.com(\/|$)/i,
    /\.azure\.com(\/|$)/i,
    /\.azureedge\.net(\/|$)/i,
    /\.trafficmanager\.net(\/|$)/i,
    /\.msedge\.net(\/|$)/i,
    /edge\.microsoft\.com/i,
    /\.digicert\.com(\/|$)/i,
    /\.akamai(hd)?\.net(\/|$)/i,
    /\.akamaiedge\.net(\/|$)/i,
    /\.aspnetcdn\.com(\/|$)/i,
    /\.windows\.net(\/|$)/i,
    /\.hotmail\.com(\/|$)/i,
    /\.outlook\.com(\/|$)/i,
    /\.skype\.com(\/|$)/i,
    /\.visualstudio\.com(\/|$)/i,
    /\.github\.com\/microsoft/i,
    /ctldl\.windowsupdate\.com/i,
    /settings-win\.data\.microsoft\.com/i,
    /v\d+\.events\.data\.microsoft\.com/i,
    /watson\.microsoft\.com/i,
    /watson\.telemetry\.microsoft\.com/i,
    /crl\.microsoft\.com/i,
    /ocsp\.digicert\.com/i
  ];

  const SYSMON_TYPE_LABELS = {
    ProcessCreate: 'Process',
    FileCreate: 'File create',
    FileCreateTime: 'File modified',
    FileCreateStream: 'File stream',
    RegistryEvent: 'Registry',
    DnsQuery: 'DNS',
    FileDelete: 'File delete',
    FileDeleteDetected: 'File delete',
    ServiceInstall: 'Service install'
  };

  const DISPLAY_ROW_LIMIT = 400;

  let diff = null;
  let activeTab = 'overview';
  let statFilter = null;
  let selectedRowId = null;
  let selectedRegistryKey = null;
  let registryIncludeSubkeys = false;
  const expandedRegistryPaths = new Set();
  let networkSubFilter = null;
  const expandedPanels = new Set();

  const $ = (sel) => document.querySelector(sel);
  const app = $('#app');
  const dropzone = $('#dropzone');
  const detailPanel = $('#detail-panel');

  function normalizePath(path) {
    return String(path || '').replace(/\//g, '\\');
  }

  function isHighSignalFilePath(path) {
    return HIGH_SIGNAL_FILE_EXTENSIONS.test(normalizePath(path));
  }

  function extractPathsFromText(text) {
    const found = [];
    const s = String(text || '');
    const re = /[A-Za-z]:\\[^"\s]+/g;
    let m;
    while ((m = re.exec(s)) !== null) {
      found.push(normalizePath(m[0]).toLowerCase());
    }
    return found;
  }

  function rebuildPersistencePathIndex() {
    persistenceReferencedPaths = new Set();
    if (!diff) return;

    const addRef = (raw) => {
      extractPathsFromText(raw).forEach((p) => persistenceReferencedPaths.add(p));
    };

    (diff.registry?.added || []).forEach((r) => {
      if (PERSISTENCE_REGISTRY_KEY_PATTERNS.some((re) => re.test(r.key || ''))) {
        addRef(r.value);
        addRef(r.key);
      }
    });
    (diff.registry?.modified || []).forEach((r) => {
      if (PERSISTENCE_REGISTRY_KEY_PATTERNS.some((re) => re.test(r.key || ''))) {
        addRef(r.value);
        addRef(r.toValue || r.value);
      }
    });

    const taskBuckets = [
      ...(diff.tasks?.added || []),
      ...(diff.tasks?.modified || []),
      ...(diff.tasks?.volatileOnly || [])
    ];
    taskBuckets.forEach((t) => {
      addRef(t.TaskToRun || t.taskToRun || t.command || '');
    });

    (diff.sysmon?.added || []).forEach((ev) => {
      const blob = `${ev.targetObject || ''} ${ev.image || ''} ${ev.commandLine || ''}`;
      if (/\\CurrentVersion\\Run/i.test(blob) || /\\RunOnce/i.test(blob) || /\\CurrentControlSet\\Services/i.test(blob)) {
        addRef(blob);
      }
    });

    (diff.serviceInstalls?.added || []).forEach((ev) => {
      addRef(ev.imagePath || ev.image || '');
      addRef(ev.serviceName || '');
    });
  }

  function isPersistenceReferencedPath(path) {
    const norm = normalizePath(path).toLowerCase();
    if (!norm || persistenceReferencedPaths.size === 0) return false;
    if (persistenceReferencedPaths.has(norm)) return true;
    for (const ref of persistenceReferencedPaths) {
      if (ref.length < 8) continue;
      if (norm === ref || norm.startsWith(ref + '\\') || ref.startsWith(norm + '\\')) return true;
      if (norm.length >= 16 && ref.length >= 16 && (norm.includes(ref) || ref.includes(norm))) return true;
    }
    return false;
  }

  function isWerNoisePath(path) {
    const norm = normalizePath(path);
    return WER_NOISE_PATTERNS.some((re) => re.test(norm));
  }

  function isEbWebViewNoisePath(path, file) {
    const norm = normalizePath(path);
    if (!EBWEBVIEW_PATH.test(norm)) return false;
    if (!EBWEBVIEW_NOISE_PATTERNS.some((re) => re.test(norm))) return false;

    const size = Number(file?.size ?? file?.toSize ?? file?.fromSize);
    if (Number.isFinite(size) && size >= LARGE_WEBVIEW_FILE_BYTES) return false;

    return true;
  }

  function isPathNoise(path) {
    if (!path) return false;
    const normalized = normalizePath(path);
    return NOISE_PATTERNS.some((re) => re.test(normalized));
  }

  function isFileNoise(fileOrPath) {
    const f = typeof fileOrPath === 'string' ? { path: fileOrPath } : normalizeFile(fileOrPath);
    const path = f.path || '';
    if (!path) return false;

    if (isHighSignalFilePath(path)) return false;
    if (isPersistenceReferencedPath(path)) return false;
    if (isWerNoisePath(path)) return true;
    if (isEbWebViewNoisePath(path, f)) return true;

    return isPathNoise(path);
  }

  function extractNetworkHost(text) {
    const raw = String(text || '').trim().toLowerCase();
    if (!raw) return '';
    try {
      if (raw.includes('://')) {
        return new URL(raw).hostname.toLowerCase();
      }
    } catch (_) { /* plain hostname */ }
    return raw.split('/')[0].split('?')[0].split(':')[0];
  }

  function isNetworkHostNoise(text) {
    const host = extractNetworkHost(text);
    if (!host) return false;
    return NETWORK_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith('.' + suffix));
  }

  function isNoise(text) {
    if (!text) return false;
    const normalized = normalizePath(text);
    if (isNetworkHostNoise(normalized)) return true;
    return isPathNoise(normalized)
      || NETWORK_NOISE_PATTERNS.some((re) => re.test(normalized));
  }

  function normalizeFile(item) {
    if (!item) return { path: '' };
    if (typeof item === 'string') return { path: item };
    if (item.path) return item;
    if (item.p) return { ...item, path: item.p };
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

  function isDisplayNarrowed(filters) {
    return Boolean(
      filters.q
      || filters.category !== 'all'
      || filters.change !== 'all'
      || statFilter
      || networkSubFilter
    );
  }

  function rowsForDisplay(rows, panelKey, filters) {
    const total = rows.length;
    if (total <= DISPLAY_ROW_LIMIT) {
      return { visible: rows, total, capped: false };
    }
    if (expandedPanels.has(panelKey) || isDisplayNarrowed(filters)) {
      return { visible: rows, total, capped: false };
    }
    return { visible: rows.slice(0, DISPLAY_ROW_LIMIT), total, capped: true };
  }

  function appendDisplayCapNote(container, panelKey, total, filters) {
    const note = document.createElement('p');
    note.className = 'content-note display-cap-note';
    note.appendChild(document.createTextNode(`Showing ${DISPLAY_ROW_LIMIT} of ${total} rows. `));
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'display-cap-btn';
    btn.textContent = `Show all ${total}`;
    btn.addEventListener('click', () => {
      expandedPanels.add(panelKey);
      render();
    });
    note.appendChild(btn);
    note.appendChild(document.createTextNode(' — or use search/filters to narrow and browse the full set.'));
    container.appendChild(note);
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
        category: 'files', kind: 'added', noise: isFileNoise(f),
        searchText: f.path, label: f.path, fileDetail: f, selectable: true,
        cells: [badge('added', 'added'), f.path, fmtBytes(f.size), (f.hash || '—').slice(0, 16) + src]
      });
    });
    (diff.files.removed || []).forEach((item) => {
      const f = normalizeFile(item);
      const src = f.source ? ` · ${f.source}` : '';
      rows.push({
        id: `file:removed:${f.path}`,
        category: 'files', kind: 'removed', noise: isFileNoise(f),
        searchText: f.path, label: f.path, fileDetail: f, selectable: true,
        cells: [badge('removed', 'removed'), f.path, fmtBytes(f.size), (f.hash || '—').slice(0, 16) + src]
      });
    });
    (diff.files.modified || []).forEach((f) => {
      const src = f.source ? ` · ${f.source}` : '';
      rows.push({
        id: `file:modified:${f.path}`,
        category: 'files', kind: 'modified', noise: isFileNoise(f),
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
        searchText: `${text} ${r.value}`, label: text,
        registryKey: r.key, valueName: r.name,
        registryDetail: r, selectable: true,
        cells: [badge('added', 'added'), text, r.value]
      });
    });
    (diff.registry.removed || []).forEach((r) => {
      const text = `${r.key}[${r.name}]`;
      rows.push({
        id: `reg:removed:${text}`,
        category: 'registry', kind: 'removed', noise: false,
        searchText: `${text} ${r.value}`, label: text,
        registryKey: r.key, valueName: r.name,
        registryDetail: r, selectable: true,
        cells: [badge('removed', 'removed'), text, r.value]
      });
    });
    (diff.registry.modified || []).forEach((r) => {
      const text = `${r.key}[${r.name}]`;
      rows.push({
        id: `reg:modified:${text}`,
        category: 'registry', kind: 'modified', noise: false,
        searchText: `${text} ${r.fromValue} ${r.toValue}`, label: text,
        registryKey: r.key, valueName: r.name,
        registryDetail: r, selectable: true,
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
        noise: isNoise(label) || isNoise(ev.image || '') || isNoise(ev.commandLine || '') || isNoise(ev.queryName || ''),
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

    (diff.serviceInstalls?.added || []).forEach((ev, idx) => {
      const label = ev.summary || `${ev.serviceName || 'Service'} -> ${ev.imagePath || '?'}`;
      const typeLabel = SYSMON_TYPE_LABELS.ServiceInstall;
      rows.push({
        id: `service-install:added:${ev.id || idx}:${ev.t}`,
        category: 'sysmon',
        kind: 'added',
        noise: false,
        searchText: `${typeLabel} ${label} ${ev.serviceName || ''} ${ev.imagePath || ''} ${ev.accountName || ''}`,
        label,
        sysmonDetail: ev,
        selectable: true,
        cells: [
          badge('added', typeLabel),
          label,
          ev.t || '—',
          ev.accountName || ev.startType || '—'
        ]
      });
    });

    (diff.network?.dns || []).forEach((d, idx) => {
      const label = d.query || '(unknown)';
      const answers = Array.isArray(d.answers) ? d.answers.filter(Boolean) : [];
      const answerText = answers.length ? answers.join(', ') : '—';
      rows.push({
        id: `network:dns:${idx}:${d.t}:${label}`,
        category: 'network',
        networkKind: 'dns',
        kind: 'added',
        noise: isNetworkHostNoise(label) || isNoise(`${label} ${d.image || ''}`),
        searchText: `${label} ${answerText} ${d.type || ''} ${d.source || ''} ${d.image || ''}`,
        label,
        networkDetail: d,
        selectable: true,
        cells: [
          badge('added', d.source || 'dns'),
          label,
          answerText,
          d.type || '—',
          d.t || '—'
        ]
      });
    });

    (diff.network?.requests || []).forEach((r, idx) => {
      const label = r.url || r.host || '(unknown)';
      rows.push({
        id: `network:req:${idx}:${r.t}:${label}`,
        category: 'network',
        networkKind: 'request',
        kind: 'added',
        noise: isNetworkHostNoise(r.host || label) || isNoise(`${label} ${r.host || ''}`),
        searchText: `${r.method || ''} ${label} ${r.host || ''} ${r.source || ''}`,
        label,
        networkDetail: r,
        selectable: true,
        cells: [
          badge('added', r.method || 'HTTP'),
          label,
          r.host || '—',
          r.t || '—'
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
      return;
    }

    if (row.networkDetail) {
      const n = row.networkDetail;
      if (row.networkKind === 'dns') {
        const kind = n.type === 'sni' ? 'TLS SNI' : n.type === 'inferred' ? 'Host (proxy)' : 'DNS lookup';
        const answers = Array.isArray(n.answers) ? n.answers.filter(Boolean) : [];
        meta.textContent = answers.length
          ? `${kind} · ${n.source || 'unknown'} → ${answers.join(', ')}`
          : `${kind} · ${n.source || 'unknown source'}`;
        const pre = document.createElement('pre');
        pre.className = 'content-block';
        pre.textContent = JSON.stringify(n, null, 2);
        body.appendChild(pre);
        return;
      }

      const status = n.status != null ? ` · HTTP ${n.status}` : '';
      meta.textContent = `${n.method || 'HTTP'} · ${n.source || 'proxy'}${status}`;
      if (n.hasBody || n.request || n.response) {
        body.appendChild(renderHttpFlowDetail(n));
      } else {
        const pre = document.createElement('pre');
        pre.className = 'content-block';
        pre.textContent = JSON.stringify(n, null, 2);
        body.appendChild(pre);
        const note = document.createElement('p');
        note.className = 'muted';
        note.textContent = 'No decrypted body in this evidence. Launch again after the mitm flows.jsonl update, then Preserve.';
        body.appendChild(note);
      }
    }
  }

  function renderHttpFlowDetail(n) {
    const wrap = document.createElement('div');
    wrap.className = 'http-flow-detail';

    const urlEl = document.createElement('p');
    const methodEl = document.createElement('strong');
    methodEl.textContent = n.method || '';
    urlEl.appendChild(methodEl);
    urlEl.appendChild(document.createTextNode(` ${n.url || ''}`));
    wrap.appendChild(urlEl);

    const resolved = Array.isArray(n.resolvedIps) ? n.resolvedIps.filter(Boolean) : [];
    if (resolved.length) {
      const r = document.createElement('p');
      r.className = 'muted';
      r.textContent = `Resolved → ${resolved.join(', ')}`;
      wrap.appendChild(r);
    }

    const panes = document.createElement('div');
    panes.className = 'http-flow-panes';

    const makePane = (title, part) => {
      const pane = document.createElement('div');
      pane.className = 'http-flow-pane';
      const head = document.createElement('div');
      head.className = 'http-flow-pane-head';
      head.textContent = title;
      pane.appendChild(head);
      const scroll = document.createElement('div');
      scroll.className = 'http-flow-pane-scroll';
      if (!part) {
        const p = document.createElement('p');
        p.className = 'muted';
        p.textContent = '(none)';
        scroll.appendChild(p);
        pane.appendChild(scroll);
        return pane;
      }
      const metaLine = document.createElement('p');
      metaLine.className = 'muted';
      const bits = [];
      if (part.contentType) bits.push(part.contentType);
      if (part.bodyBytes != null) bits.push(`${part.bodyBytes} bytes`);
      if (part.bodyTruncated) bits.push('truncated');
      if (part.encoding && part.encoding !== 'utf-8') bits.push(part.encoding);
      metaLine.textContent = bits.join(' · ') || '';
      scroll.appendChild(metaLine);

      if (part.headers && typeof part.headers === 'object') {
        const hdr = document.createElement('pre');
        hdr.className = 'content-block headers hl-code';
        const hdrText = Object.entries(part.headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');
        hdr.innerHTML = (typeof QuarantineHighlight !== 'undefined' && QuarantineHighlight.highlightHeaders)
          ? QuarantineHighlight.highlightHeaders(hdrText)
          : escapeHtml(hdrText);
        scroll.appendChild(hdr);
      }
      const bodyPre = document.createElement('pre');
      const hl = (typeof QuarantineHighlight !== 'undefined' && QuarantineHighlight.highlightBody)
        ? QuarantineHighlight.highlightBody(part.body != null && part.body !== '' ? part.body : '', part.contentType || '')
        : { html: escapeHtml(part.body != null && part.body !== '' ? part.body : '(empty body)'), lang: 'plain', pretty: false };
      bodyPre.className = `content-block body hl-code lang-${hl.lang || 'plain'}`;
      if (part.body == null || part.body === '') {
        bodyPre.textContent = '(empty body)';
      } else {
        bodyPre.innerHTML = hl.html;
      }
      if (hl.pretty) {
        metaLine.textContent = (metaLine.textContent ? metaLine.textContent + ' · ' : '') + 'pretty · ' + (hl.lang || '');
      } else if (hl.lang && hl.lang !== 'plain') {
        metaLine.textContent = (metaLine.textContent ? metaLine.textContent + ' · ' : '') + hl.lang;
      }
      scroll.appendChild(bodyPre);
      pane.appendChild(scroll);
      return pane;
    };

    panes.appendChild(makePane('Request', n.request));
    panes.appendChild(makePane(n.status != null ? `Response (${n.status})` : 'Response', n.response));
    wrap.appendChild(panes);
    return wrap;
  }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
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
      ['sysmon', 'added', 'Sysmon events', 'added'],
      ['sysmon', 'added', 'Service installs', 'service-installs'],
      ['network', 'added', 'DNS lookups', 'dns'],
      ['network', 'added', 'HTTP requests', 'requests']
    ];

    cards.forEach(([cat, kind, label, filterKind]) => {
      let val = counts[`${cat}:${kind}`] || 0;
      if (cat === 'network' && filterKind === 'dns') {
        val = rows.filter((r) => r.category === 'network' && r.networkKind === 'dns' && (!filters.hideNoise || !r.noise)).length;
      } else if (cat === 'network' && filterKind === 'requests') {
        val = rows.filter((r) => r.category === 'network' && r.networkKind === 'request' && (!filters.hideNoise || !r.noise)).length;
      } else if (cat === 'sysmon' && filterKind === 'service-installs') {
        val = rows.filter((r) => r.category === 'sysmon' && r.id.startsWith('service-install:') && (!filters.hideNoise || !r.noise)).length;
      } else if (cat === 'sysmon' && filterKind === 'added') {
        val = rows.filter((r) => r.category === 'sysmon' && !r.id.startsWith('service-install:') && (!filters.hideNoise || !r.noise)).length;
      }
      const card = document.createElement('div');
      card.className = 'stat-card';
      const activeKind = filterKind === 'dns' || filterKind === 'requests' ? 'added' : kind;
      if (statFilter === activeKind && filters.category === cat) card.classList.add('active');
      const labelEl = document.createElement('div');
      labelEl.className = 'label';
      labelEl.textContent = label;
      const valueEl = document.createElement('div');
      valueEl.className = 'value';
      valueEl.textContent = String(val);
      card.appendChild(labelEl);
      card.appendChild(valueEl);
      card.addEventListener('click', () => {
        statFilter = activeKind;
        $('#changeFilter').value = 'added';
        $('#categoryFilter').value = cat;
        activeTab = cat === 'tasks' ? 'tasks'
          : cat === 'registry' ? 'registry'
          : cat === 'sysmon' ? 'sysmon'
          : cat === 'network' && filterKind === 'dns' ? 'dns'
          : cat === 'network' ? 'network'
          : 'files';
        if (cat === 'network') {
          networkSubFilter = filterKind;
        }
        setActiveTab(activeTab);
        render();
      });
      statsEl.appendChild(card);
    });
  }

  function renderTable(container, headers, rows, panelKey) {
    container.innerHTML = '';
    if (!rows.length) {
      container.innerHTML = '<div class="empty">No matching changes. Click a row to inspect file contents.</div>';
      return;
    }

    const filters = getFilters();
    const display = panelKey ? rowsForDisplay(rows, panelKey, filters) : { visible: rows, total: rows.length, capped: false };
    const visibleRows = display.visible;

    const wrapper = document.createElement('div');
    wrapper.className = 'table-scroll';

    const table = document.createElement('table');
    table.className = 'diff-table';
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
    visibleRows.forEach((row) => {
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
        const colClass = idx === 0 ? 'col-change'
          : idx === 1 ? 'col-key path'
          : 'col-value mono';
        if (typeof cell === 'string') {
          td.className = colClass;
          td.textContent = cell;
          if (idx === 1 && row.label) td.appendChild(copyBtn(row.label));
        } else {
          td.className = colClass;
          td.appendChild(cell);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrapper.appendChild(table);
    container.appendChild(wrapper);
    if (display.capped && panelKey) {
      appendDisplayCapNote(container, panelKey, display.total, filters);
    }
  }

  function splitRegistryKey(key) {
    if (!key) return [];
    return String(key).split('\\').filter((part) => part.length > 0);
  }

  function joinRegistryPath(parts, endIndex) {
    if (!parts.length || endIndex < 0) return '';
    if (endIndex === 0) return parts[0];
    return parts.slice(0, endIndex + 1).join('\\');
  }

  function ensureRegistryPathExpanded(path) {
    const parts = splitRegistryKey(path);
    for (let i = 0; i < parts.length; i++) {
      expandedRegistryPaths.add(joinRegistryPath(parts, i));
    }
  }

  function buildRegistryTree(rows) {
    const root = { name: '', path: '', children: new Map(), rows: [], total: 0 };

    function getOrCreate(parent, segment, path) {
      if (!parent.children.has(segment)) {
        parent.children.set(segment, {
          name: segment,
          path,
          children: new Map(),
          rows: [],
          total: 0
        });
      }
      return parent.children.get(segment);
    }

    rows.forEach((row) => {
      const parts = splitRegistryKey(row.registryKey || '');
      if (!parts.length) return;
      let node = root;
      for (let i = 0; i < parts.length; i++) {
        const path = joinRegistryPath(parts, i);
        node = getOrCreate(node, parts[i], path);
        node.total++;
      }
      node.rows.push(row);
    });

    return root;
  }

  function sortRegistryNodes(children) {
    return Array.from(children.values()).sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  }

  function registryRowsForSelection(rows, key, includeSubkeys) {
    if (!key) return rows;
    if (!includeSubkeys) return rows.filter((r) => r.registryKey === key);
    const prefix = `${key}\\`;
    return rows.filter((r) => r.registryKey === key || (r.registryKey || '').startsWith(prefix));
  }

  function pickDefaultRegistryKey(rows) {
    const keys = Array.from(new Set(rows.map((r) => r.registryKey).filter(Boolean))).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    return keys[0] || null;
  }

  function renderRegistryTreeNode(node, depth, container, onSelect) {
    sortRegistryNodes(node.children).forEach((child) => {
      const hasChildren = child.children.size > 0;
      const isExpanded = expandedRegistryPaths.has(child.path);
      const isSelected = selectedRegistryKey === child.path;

      const row = document.createElement('div');
      row.className = 'registry-tree-row';
      row.style.paddingLeft = `${depth * 0.85 + 0.35}rem`;

      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'registry-tree-toggle';
      toggle.textContent = hasChildren ? (isExpanded ? '▾' : '▸') : '·';
      toggle.disabled = !hasChildren;
      toggle.title = hasChildren ? (isExpanded ? 'Collapse' : 'Expand') : '';
      toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        if (!hasChildren) return;
        if (isExpanded) expandedRegistryPaths.delete(child.path);
        else expandedRegistryPaths.add(child.path);
        render();
      });

      const label = document.createElement('button');
      label.type = 'button';
      label.className = 'registry-tree-node' + (isSelected ? ' selected' : '');
      label.title = child.path;
      const nameSpan = document.createElement('span');
      nameSpan.className = 'registry-tree-name';
      nameSpan.textContent = child.name;
      const countSpan = document.createElement('span');
      countSpan.className = 'registry-node-count';
      countSpan.textContent = String(child.total);
      label.appendChild(nameSpan);
      label.appendChild(countSpan);
      label.addEventListener('click', () => {
        selectedRegistryKey = child.path;
        ensureRegistryPathExpanded(child.path);
        onSelect();
      });

      row.appendChild(toggle);
      row.appendChild(label);
      container.appendChild(row);

      if (hasChildren && isExpanded) {
        renderRegistryTreeNode(child, depth + 1, container, onSelect);
      }
    });
  }

  function renderRegistryPanel(rows) {
    const panel = $('#panel-registry');
    panel.innerHTML = '';

    if (!rows.length) {
      panel.innerHTML = '<div class="empty">No matching registry changes.</div>';
      return;
    }

    const keyPaths = new Set();
    rows.forEach((r) => {
      const parts = splitRegistryKey(r.registryKey || '');
      for (let i = 0; i < parts.length; i++) {
        keyPaths.add(joinRegistryPath(parts, i));
      }
    });
    if (!selectedRegistryKey || !keyPaths.has(selectedRegistryKey)) {
      selectedRegistryKey = pickDefaultRegistryKey(rows);
    }
    if (selectedRegistryKey) ensureRegistryPathExpanded(selectedRegistryKey);

    const toolbar = document.createElement('div');
    toolbar.className = 'registry-toolbar';
    const subkeysLabel = document.createElement('label');
    subkeysLabel.className = 'registry-subkeys-toggle';
    const subkeysInput = document.createElement('input');
    subkeysInput.type = 'checkbox';
    subkeysInput.checked = registryIncludeSubkeys;
    subkeysInput.addEventListener('change', () => {
      registryIncludeSubkeys = subkeysInput.checked;
      render();
    });
    subkeysLabel.appendChild(subkeysInput);
    subkeysLabel.appendChild(document.createTextNode(' Include subkeys'));
    toolbar.appendChild(subkeysLabel);
    panel.appendChild(toolbar);

    const browser = document.createElement('div');
    browser.className = 'registry-browser';

    const treePanel = document.createElement('aside');
    treePanel.className = 'registry-tree-panel';
    const treeTitle = document.createElement('div');
    treeTitle.className = 'registry-panel-title';
    treeTitle.textContent = 'Registry keys';
    treePanel.appendChild(treeTitle);
    const treeHost = document.createElement('div');
    treeHost.className = 'registry-tree';
    const tree = buildRegistryTree(rows);
    renderRegistryTreeNode(tree, 0, treeHost, () => render());
    treePanel.appendChild(treeHost);

    const valuesPanel = document.createElement('div');
    valuesPanel.className = 'registry-values-panel';
    const keyHeader = document.createElement('div');
    keyHeader.className = 'registry-key-header';
    keyHeader.textContent = selectedRegistryKey || '(no key selected)';
    if (selectedRegistryKey) keyHeader.appendChild(copyBtn(selectedRegistryKey));
    valuesPanel.appendChild(keyHeader);

    const visibleRows = registryRowsForSelection(rows, selectedRegistryKey, registryIncludeSubkeys);
    const valueNote = document.createElement('p');
    valueNote.className = 'content-note registry-value-note';
    valueNote.textContent = registryIncludeSubkeys
      ? `${visibleRows.length} value change(s) at this key and below`
      : `${visibleRows.length} value change(s) at this key`;
    valuesPanel.appendChild(valueNote);

    const valueRows = visibleRows.map((row) => ({
      ...row,
      cells: [
        row.cells[0],
        row.valueName || '(default)',
        row.kind === 'modified'
          ? row.registryDetail.fromValue + ' → ' + row.registryDetail.toValue
          : (row.registryDetail.value || '—')
      ]
    }));

    const tableHost = document.createElement('div');
    valuesPanel.appendChild(tableHost);
    renderTable(tableHost, ['Change', 'Value name', 'Value / delta'], valueRows, 'registry-values');

    browser.appendChild(treePanel);
    browser.appendChild(valuesPanel);
    panel.appendChild(browser);
  }

  function renderOverview(filtered) {
    const panel = $('#panel-overview');
    panel.replaceChildren();

    const byDir = {};
    filtered.filter((r) => r.category === 'files' && r.kind !== 'volatile').forEach((r) => {
      const p = String(r.label || '');
      const m = p.match(/^([A-Z]:\\[^\\]+\\[^\\]+)/i);
      const bucket = m ? m[1] : '(other)';
      byDir[bucket] = (byDir[bucket] || 0) + 1;
    });

    const folderHeading = document.createElement('h3');
    folderHeading.textContent = 'File changes by top-level folder';
    panel.appendChild(folderHeading);

    const entries = Object.entries(byDir).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No file changes match current filters.';
      panel.appendChild(empty);
    } else {
      panel.appendChild(buildPlainTable(
        ['Folder prefix', 'Changes'],
        entries.map(([dir, count]) => [
          { text: dir, className: 'path' },
          String(count),
        ])
      ));
    }

    const interesting = filtered.filter((r) => !r.noise && r.kind !== 'volatile');
    const notableHeading = document.createElement('h3');
    notableHeading.style.marginTop = '1.5rem';
    notableHeading.append('Notable changes ');
    const pill = document.createElement('span');
    pill.className = 'count-pill';
    pill.textContent = `(${interesting.length})`;
    notableHeading.appendChild(pill);
    panel.appendChild(notableHeading);

    const note = document.createElement('p');
    note.className = 'content-note';
    note.style.paddingTop = '0';
    note.textContent = 'Open Files, Registry, Network, or Sysmon tabs and click a row for details.';
    panel.appendChild(note);

    if (!interesting.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'Nothing notable after noise filter — toggle "Hide routine noise".';
      panel.appendChild(empty);
      return;
    }

    const rowsById = new Map();
    interesting.forEach((r) => {
      if (r && typeof r.id === 'string' && r.id) rowsById.set(r.id, r);
    });

    const shown = interesting.slice(0, 80);
    const table = buildPlainTable(
      ['Type', 'Item', 'Detail'],
      shown.map((r) => {
        const detail = r.cells.slice(2).map((c) => (typeof c === 'string' ? c : '')).join(' · ');
        return {
          rowId: r.id,
          cells: [
            { node: r.cells[0] instanceof HTMLElement ? r.cells[0].cloneNode(true) : null, text: r.kind },
            { text: r.label || '', className: 'path' },
            detail,
          ],
        };
      })
    );
    table.querySelectorAll('tbody tr[data-row-id]').forEach((tr) => {
      tr.classList.add('selectable', 'overview-row');
      tr.addEventListener('click', () => {
        const rowId = tr.getAttribute('data-row-id');
        if (!isSafeOverviewRowId(rowId) || !rowsById.has(rowId)) return;
        const row = rowsById.get(rowId);
        const tab = row.category === 'tasks' ? 'tasks'
          : row.category === 'registry' ? 'registry'
          : row.category === 'sysmon' ? 'sysmon'
          : row.category === 'network' && row.networkKind === 'dns' ? 'dns'
          : row.category === 'network' ? 'network'
          : 'files';
        if (row.registryKey) {
          selectedRegistryKey = row.registryKey;
          ensureRegistryPathExpanded(row.registryKey);
        }
        setActiveTab(tab);
        showDetail(row);
        render();
      });
    });
    panel.appendChild(table);

    if (interesting.length > 80) {
      const more = document.createElement('p');
      more.className = 'muted';
      more.textContent = `… and ${interesting.length - 80} more (use tabs/filters)`;
      panel.appendChild(more);
    }
  }

  /** Overview row ids come from buildRows; reject control chars / absurd length. */
  function isSafeOverviewRowId(id) {
    if (typeof id !== 'string' || !id || id.length > 4096) return false;
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(id)) return false;
    return /^(file|registry|tasks|sysmon|network|usn):/.test(id);
  }

  function buildPlainTable(headers, rows) {
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    headers.forEach((h) => {
      const th = document.createElement('th');
      th.textContent = h;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    rows.forEach((row) => {
      const cells = Array.isArray(row) ? row : (row.cells || []);
      const tr = document.createElement('tr');
      if (row && typeof row.rowId === 'string' && row.rowId) {
        tr.setAttribute('data-row-id', row.rowId);
      }
      cells.forEach((cell) => {
        const td = document.createElement('td');
        if (cell && typeof cell === 'object' && !Array.isArray(cell)) {
          if (cell.className) td.className = cell.className;
          if (cell.node instanceof Node) {
            td.appendChild(cell.node);
          } else {
            td.textContent = cell.text != null ? String(cell.text) : '';
          }
        } else {
          td.textContent = cell == null ? '' : String(cell);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  function renderSysmonPanel() {
    const panel = $('#panel-sysmon');
    if (!panel) return;

    const sysmon = diff.sysmon;
    const serviceInstalls = diff.serviceInstalls;
    const sysmonCount = (sysmon?.added || []).length;
    const serviceInstallCount = (serviceInstalls?.added || []).length;
    if ((!sysmon || sysmon.available === false) && serviceInstallCount === 0) {
      panel.replaceChildren();
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = sysmon?.message || serviceInstalls?.message || 'Sysmon not captured. Install Sysmon in the guest and re-capture with -Refresh.';
      panel.appendChild(empty);
      return;
    }

    const filters = getFilters();
    const rows = buildRows().filter((r) => r.category === 'sysmon' && rowPasses(r, filters));

    const header = document.createElement('p');
    header.className = 'content-note';
    const isSnapshotPair = diff.meta?.compareMode === 'snapshot-pair';
    const totalEvents = sysmonCount + serviceInstallCount;
    let headerText = isSnapshotPair
      ? `Events in To (${diff.meta?.toSnapshot || 'To'}) not in From (${diff.meta?.fromSnapshot || 'From'}) · ${totalEvents} new (${sysmonCount} Sysmon, ${serviceInstallCount} service install)`
      : `Events in the To snapshot not present in From · ${totalEvents} new (${sysmonCount} Sysmon, ${serviceInstallCount} service install)`;
    if (!isSnapshotPair && sysmon?.baselineAt) {
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
    renderTable(tableHost, ['Type', 'Summary', 'Time (UTC)', 'User / image'], rows, 'sysmon');
  }

  function renderNetworkPanel() {
    const panel = $('#panel-network');
    if (!panel) return;

    const network = diff.network;
    panel.innerHTML = '';

    if (!network) {
      panel.innerHTML = '<div class="empty">No network section in this diff. Re-run Compare to include proxy/PCAP data.</div>';
      return;
    }

    const filters = getFilters();
    const rows = buildRows().filter((r) => r.category === 'network' && r.networkKind === 'request' && rowPasses(r, filters));

    const header = document.createElement('p');
    header.className = 'content-note';
    const windowText = network.windowFrom && network.windowTo
      ? `${network.windowFrom} → ${network.windowTo}`
      : 'snapshot capture window';
    let headerText = `HTTP/proxy activity · ${windowText}`;
    headerText += ` · ${(network.requests || []).length} request(s)`;
    if (network.truncated) headerText += ' · list truncated';
    header.textContent = headerText;
    panel.appendChild(header);

    if (network.message) {
      const info = document.createElement('p');
      info.className = 'content-note';
      info.style.paddingTop = '0';
      info.textContent = network.message;
      panel.appendChild(info);
    }

    if (!rows.length) {
      const note = document.createElement('div');
      note.className = 'empty';
      note.textContent = 'No HTTP/proxy requests match current filters. DNS is on the DNS tab.';
      panel.appendChild(note);
      return;
    }

    const reqHost = document.createElement('div');
    panel.appendChild(reqHost);
    renderTable(reqHost, ['Method', 'URL', 'Host', 'Time (UTC)'], rows, 'network-requests');
  }

  function renderDnsPanel() {
    const panel = $('#panel-dns');
    if (!panel) return;

    const network = diff.network;
    panel.innerHTML = '';

    if (!network) {
      panel.innerHTML = '<div class="empty">No network section in this diff. Re-run Compare to include proxy/PCAP data.</div>';
      return;
    }

    const filters = getFilters();
    const rows = buildRows().filter((r) => r.category === 'network' && r.networkKind === 'dns' && rowPasses(r, filters));

    const header = document.createElement('p');
    header.className = 'content-note';
    const windowText = network.windowFrom && network.windowTo
      ? `${network.windowFrom} → ${network.windowTo}`
      : 'snapshot capture window';
    header.textContent = `Name resolution · ${windowText} · ${(network.dns || []).length} lookup(s)`;
    panel.appendChild(header);

    if (!rows.length) {
      const note = document.createElement('div');
      note.className = 'empty';
      note.textContent = 'No DNS / host resolution entries match current filters.';
      panel.appendChild(note);
      return;
    }

    const dnsHost = document.createElement('div');
    panel.appendChild(dnsHost);
    renderTable(dnsHost, ['Source', 'Name', 'Resolved', 'Type', 'Time (UTC)'], rows, 'network-dns');
  }

  function renderUsnPanel() {
    const panel = $('#panel-usn');
    if (!panel) return;
    panel.replaceChildren();
    const usn = diff.usn;
    if (!usn || usn.available === false) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = usn?.message || 'No USN journal data. Run manifest mark after restore, then capture after the test.';
      panel.appendChild(empty);
      return;
    }

    const filters = getFilters();
    let events = usn.events || [];
    if (filters.q) {
      const q = filters.q.toLowerCase();
      events = events.filter((e) => {
        const text = `${e.timestamp || ''} ${(e.reasons || []).join(' ')} ${e.fileName || ''}`.toLowerCase();
        return text.includes(q);
      });
    }

    const isSnapshotPair = diff.meta?.compareMode === 'snapshot-pair';
    const note = document.createElement('p');
    note.className = 'content-note';
    note.textContent = isSnapshotPair
      ? `Volume ${usn.volume || 'C:'} · ${(usn.events || []).length} USN events in To not in From (${diff.meta?.fromSnapshot || '?'} → ${diff.meta?.toSnapshot || '?'})`
      : `Volume ${usn.volume || 'C:'} · ${(usn.events || []).length} events since baseline (${usn.baselineAt || '?'})`;
    panel.appendChild(note);

    if (!events.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = filters.q
        ? 'No USN events match the current search.'
        : (isSnapshotPair
          ? 'No new USN file activity between these snapshots.'
          : 'No file activity recorded since USN baseline.');
      panel.appendChild(empty);
      return;
    }

    const display = rowsForDisplay(events, 'usn', filters);
    const visibleEvents = display.visible;

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    for (const h of ['Time (UTC)', 'Reason', 'File name']) {
      const th = document.createElement('th');
      th.textContent = h;
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    visibleEvents.forEach((e) => {
      const tr = document.createElement('tr');
      const tdTime = document.createElement('td');
      tdTime.className = 'mono';
      tdTime.textContent = e.timestamp || '';
      const tdReason = document.createElement('td');
      tdReason.textContent = (e.reasons || []).join(', ');
      const tdFile = document.createElement('td');
      tdFile.className = 'path';
      tdFile.textContent = e.fileName || '';
      tr.appendChild(tdTime);
      tr.appendChild(tdReason);
      tr.appendChild(tdFile);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    panel.appendChild(table);

    if (usn.truncated) {
      const trunc = document.createElement('p');
      trunc.className = 'content-note';
      trunc.textContent = 'Event list truncated at guest capture limit.';
      panel.appendChild(trunc);
    }

    if (display.capped) {
      appendDisplayCapNote(panel, 'usn', display.total, filters);
    }
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
      filtered.filter((r) => r.category === 'files'),
      'files'
    );
    renderRegistryPanel(filtered.filter((r) => r.category === 'registry'));
    renderTable(
      $('#panel-tasks'),
      ['Change', 'Task', 'Command / delta', 'Run as'],
      filtered.filter((r) => r.category === 'tasks'),
      'tasks'
    );
    renderSysmonPanel();
    renderNetworkPanel();
    renderDnsPanel();
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
    const warnings = ((diff.meta && diff.meta.warnings) || [])
      .filter((w) => !/Viewer lists capped at \d+ rows per bucket/i.test(w));
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
    rebuildPersistencePathIndex();
    selectedRowId = null;
    selectedRegistryKey = null;
    expandedRegistryPaths.clear();
    registryIncludeSubkeys = false;
    networkSubFilter = null;
    expandedPanels.clear();
    dropzone.classList.add('hidden');
    app.classList.remove('panel-layout', 'detail-open');
    detailPanel.classList.add('hidden');
    app.classList.remove('hidden');

    const m = diff.meta || {};
    const fromFiles = m.fromFileCount != null ? ` · ${m.fromFileCount} scanned` : '';
    const toFiles = m.toFileCount != null ? ` · ${m.toFileCount} scanned` : '';
    const fromHku = m.fromUserRegistryCount != null ? ` · ${m.fromUserRegistryCount} HKU reg` : '';
    const toHku = m.toUserRegistryCount != null ? ` · ${m.toUserRegistryCount} HKU reg` : '';
    const fileSrc = m.fileDiffSource ? ` · file diff: ${m.fileDiffSource}` : '';
    const metaEl = $('#meta');
    metaEl.replaceChildren();

    const fromDiv = document.createElement('div');
    const fromStrong = document.createElement('strong');
    fromStrong.textContent = 'From:';
    fromDiv.appendChild(fromStrong);
    fromDiv.appendChild(document.createTextNode(` ${m.fromSnapshot || '?'} `));
    const fromMono = document.createElement('span');
    fromMono.className = 'mono';
    fromMono.textContent = `${m.fromCaptured || ''}${fromFiles}${fromHku}${m.fromScanMode ? ` · ${m.fromScanMode}` : ''}`;
    fromDiv.appendChild(fromMono);
    metaEl.appendChild(fromDiv);

    const toDiv = document.createElement('div');
    const toStrong = document.createElement('strong');
    toStrong.textContent = 'To:';
    toDiv.appendChild(toStrong);
    toDiv.appendChild(document.createTextNode(` ${m.toSnapshot || '?'} `));
    const toMono = document.createElement('span');
    toMono.className = 'mono';
    toMono.textContent = `${m.toCaptured || ''}${toFiles}${toHku}${m.toScanMode ? ` · ${m.toScanMode}` : ''}`;
    toDiv.appendChild(toMono);
    metaEl.appendChild(toDiv);

    const paths = document.createElement('div');
    paths.className = 'mono';
    paths.style.marginTop = '0.25rem';
    paths.style.fontSize = '0.8rem';
    paths.appendChild(document.createTextNode(m.fromManifest || ''));
    paths.appendChild(document.createElement('br'));
    paths.appendChild(document.createTextNode(`${m.toManifest || ''}${fileSrc}`));
    metaEl.appendChild(paths);

    if (m.compareMode === 'snapshot-pair') {
      const compareNote = document.createElement('div');
      compareNote.className = 'content-note';
      compareNote.style.marginTop = '0.35rem';
      compareNote.textContent = 'Comparing two snapshots (To minus From) — not vs session baseline.';
      metaEl.appendChild(compareNote);
    }
    if (m.toScanMode === 'events' || m.fromScanMode === 'events') {
      const scanNote = document.createElement('div');
      scanNote.className = 'content-note';
      scanNote.style.marginTop = '0.35rem';
      scanNote.appendChild(document.createTextNode('Event-first capture (USN/Sysmon). Run '));
      const cmd = document.createElement('span');
      cmd.className = 'mono';
      cmd.textContent = 'manifest enrich -SnapshotName …';
      scanNote.appendChild(cmd);
      scanNote.appendChild(document.createTextNode(' to hash changed paths.'));
      metaEl.appendChild(scanNote);
    }

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
      expandedPanels.clear();
      render();
    });
    $(`#${id}`).addEventListener('change', () => {
      statFilter = null;
      expandedPanels.clear();
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

  // Expose DOM-safe helpers for offline regression tests (no secrets).
  globalThis.QuarantineViewerSafeDOM = {
    isSafeOverviewRowId,
    buildPlainTable,
  };
})();
