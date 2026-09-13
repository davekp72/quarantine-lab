/** Noise heuristics shared with manifest/viewer (routine OS / lab churn). */

const HIGH_SIGNAL_FILE_EXTENSIONS = /\.(exe|dll|sys|ps1|bat|cmd|vbs|js|hta|lnk)$/i;

const EBWEBVIEW_NOISE_PATTERNS = [
  /\\EBWebView\\Default\\[^\\]+\.tmp$/i,
  /\\EBWebView\\Default\\Cache\\/i,
  /\\EBWebView\\Default\\Code Cache\\/i,
  /\\EBWebView\\Default\\GPUCache\\/i,
  /\\EBWebView\\Default\\Service Worker\\CacheStorage\\/i,
];

const EBWEBVIEW_PATH = /\\EBWebView\\/i;
const LARGE_WEBVIEW_FILE_BYTES = 2 * 1024 * 1024;

const WER_NOISE_PATTERNS = [
  /\\ProgramData\\Microsoft\\Windows\\WER\\/i,
  /\\Microsoft\\Windows\\WER\\/i,
];

const EPHEMERAL_TEMP_PATTERNS = [
  /\\(?:SystemTemp|Temp)\\__?PSScriptPolicyTest_[^\\]+\.ps1$/i,
];

export const DEFAULT_NOISE_FILES = [
  '\\Microsoft\\EdgeUpdate\\',
  '\\Microsoft\\OneDrive\\ListSync',
  '\\AppData\\Local\\Microsoft\\OneDrive\\',
  '\\$Extend\\',
  '\\Windows\\ServiceState\\',
  '\\Microsoft\\Windows\\AppRepository\\',
  '\\Microsoft\\InstallService\\',
  '\\Users\\Public\\Quarantine\\',
  '\\Windows Security Health\\',
  '\\PowerGrid\\',
  'manifest-capture.json',
  'Get-QuarantineGuestManifest.ps1',
  'Get-QuarantineGuestSysmonEvents.ps1',
  '.etl',
  '\\Windows\\Temp\\',
  '\\Temp\\',
  '\\SearchIndexer.exe',
  '\\svchost.exe',
  '\\MsMpEng.exe',
  '\\SecurityHealthService.exe',
];

let noiseFiles = DEFAULT_NOISE_FILES.slice();

export function setNoiseFiles(list) {
  if (!Array.isArray(list)) {
    noiseFiles = DEFAULT_NOISE_FILES.slice();
    return noiseFiles.slice();
  }
  const seen = new Set();
  noiseFiles = [];
  for (const raw of list) {
    const p = String(raw || '').trim().replace(/\//g, '\\');
    if (!p) continue;
    const key = p.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    noiseFiles.push(p);
  }
  return noiseFiles.slice();
}

export function getNoiseFiles() {
  return noiseFiles.slice();
}

export const DEFAULT_NOISE_REGISTRY = [
  '\\IrisService\\Cache\\',
  '\\TaskCache\\Tasks\\{',
  '\\Explorer\\SessionInfo\\',
  '\\ContentDeliveryManager\\',
  '\\InstallService\\State',
  '\\Volatile Environment\\',
];

let noiseRegistry = DEFAULT_NOISE_REGISTRY.slice();

export function setNoiseRegistry(list) {
  if (!Array.isArray(list)) {
    noiseRegistry = DEFAULT_NOISE_REGISTRY.slice();
    return noiseRegistry.slice();
  }
  const seen = new Set();
  noiseRegistry = [];
  for (const raw of list) {
    const p = String(raw || '').trim().replace(/\//g, '\\');
    if (!p) continue;
    const key = p.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    noiseRegistry.push(p);
  }
  return noiseRegistry.slice();
}

export function getNoiseRegistry() {
  return noiseRegistry.slice();
}

export function isRegistryNoise(entryOrKey) {
  const key = typeof entryOrKey === 'string'
    ? entryOrKey
    : (entryOrKey?.k || entryOrKey?.key || '');
  const n = String(key || '').trim().replace(/\//g, '\\').toLowerCase();
  if (!n) return false;
  return noiseRegistry.some((p) => {
    const needle = String(p || '').replace(/\//g, '\\').toLowerCase();
    return needle && n.includes(needle);
  });
}

export const DEFAULT_NOISE_DOMAINS = [
  'msftconnecttest.com', 'microsoft.com', 'microsoft.net', 'msn.com', 'bing.com',
  'windowsupdate.com', 'office.com', 'office365.com', 'live.com', 'microsoftpersonalcontent.com',
  'onedrive.com', 'sharepoint.com', 'skype.com', 'windows.com', 'xboxlive.com', 'xboxab.com',
  'azure.com', 'azureedge.net', 'trafficmanager.net', 'msedge.net', 'msauth.net', 'msidentity.com',
  'hotmail.com', 'outlook.com', 'visualstudio.com', 'digicert.com', 'akamaihd.net', 'akamaiedge.net',
  'akamai.net', 'aspnetcdn.com', 'windows.net', 'officeapps.live.com', 'mp.microsoft.com',
  'events.data.microsoft.com', 'data.microsoft.com', 'telemetry.microsoft.com', 'msftncsi.com',
  'cloud.microsoft', 'office.net', 'sfx.ms', 's-microsoft.com', 'akamaized.net',
];

let noiseDomains = DEFAULT_NOISE_DOMAINS.slice();

export function setNoiseDomains(list) {
  if (!Array.isArray(list)) {
    noiseDomains = DEFAULT_NOISE_DOMAINS.slice();
    return noiseDomains.slice();
  }
  const seen = new Set();
  noiseDomains = [];
  for (const raw of list) {
    let d = String(raw || '').trim().toLowerCase();
    if (d.startsWith('.')) d = d.slice(1);
    if (!d || seen.has(d)) continue;
    seen.add(d);
    noiseDomains.push(d);
  }
  return noiseDomains.slice();
}

export function getNoiseDomains() {
  return noiseDomains.slice();
}

export function normalizePath(path) {
  return String(path || '').replace(/\//g, '\\');
}

function isHighSignalFilePath(path) {
  return HIGH_SIGNAL_FILE_EXTENSIONS.test(normalizePath(path));
}

function isWerNoisePath(path) {
  return WER_NOISE_PATTERNS.some((re) => re.test(normalizePath(path)));
}

function isEbWebViewNoisePath(path, file) {
  const norm = normalizePath(path);
  if (!EBWEBVIEW_PATH.test(norm)) return false;
  if (!EBWEBVIEW_NOISE_PATTERNS.some((re) => re.test(norm))) return false;
  const size = Number(file?.size ?? file?.toSize ?? file?.fromSize);
  if (Number.isFinite(size) && size >= LARGE_WEBVIEW_FILE_BYTES) return false;
  return true;
}

export function isEphemeralTempPath(path) {
  const norm = normalizePath(path);
  return EPHEMERAL_TEMP_PATTERNS.some((re) => re.test(norm));
}

function isPathNoise(path) {
  if (!path) return false;
  const norm = normalizePath(path).toLowerCase();
  return noiseFiles.some((p) => {
    const needle = String(p || '').replace(/\//g, '\\').toLowerCase();
    return needle && norm.includes(needle);
  });
}

function normalizeFile(item) {
  if (!item) return { path: '' };
  if (typeof item === 'string') return { path: item };
  if (item.path) return item;
  if (item.p) return { ...item, path: item.p };
  return item;
}

export function isFileNoise(fileOrPath) {
  const f = typeof fileOrPath === 'string' ? { path: fileOrPath } : normalizeFile(fileOrPath);
  if (f.noise || fileOrPath?.noise || f.after?.noise) return true;
  const path = f.path || f.after?.path || fileOrPath?.fileName || '';
  if (!path) return false;
  if (isEphemeralTempPath(path)) return true;
  if (isCompilerTempNoise(path)) return true;
  if (isHighSignalFilePath(path)) return false;
  if (isWerNoisePath(path)) return true;
  if (isEbWebViewNoisePath(path, f)) return true;
  return isPathNoise(path);
}

function isCompilerTempNoise(path) {
  const norm = normalizePath(path);
  if (/\.0\.cs$/i.test(norm) || /\.cmdline$/i.test(norm)) return true;
  if (/\\Windows\\SystemTemp\\[a-z0-9]{8}(?:\\[a-z0-9]{8}\.(?:dll|err|out))?$/i.test(norm)) return true;
  if (/^[a-z0-9]{8}\.(?:dll|err|out|0\.cs|cmdline)$/i.test(norm)) return true;
  return /psscriptpolicytest/i.test(norm);
}

function extractNetworkHost(text) {
  const raw = String(text || '').trim().toLowerCase();
  if (!raw) return '';
  try {
    if (raw.includes('://')) return new URL(raw).hostname.toLowerCase();
  } catch (_) { /* plain hostname */ }
  return raw.split('/')[0].split('?')[0].split(':')[0];
}

export function isNetworkHostNoise(text) {
  const host = extractNetworkHost(text);
  if (!host) return false;
  if (host === 'home.arpa' || host.endsWith('.home.arpa')) return true;
  if (host.endsWith('.local') || host === 'localhost' || host === 'localhost.') return true;
  return noiseDomains.some((suffix) => host === suffix || host.endsWith('.' + suffix));
}

export function isNetworkDnsNoise(entry) {
  if (!entry) return false;
  return isNetworkHostNoise(entry.query || entry.qname || entry.host || '');
}

export function isNetworkRequestNoise(entry) {
  if (!entry) return false;
  return isNetworkHostNoise(entry.host || entry.url || entry.path || '');
}

const TRAFFIC_NOISE_PROTOS = new Set([
  'ARP', 'IGMP', 'IGMPV2', 'IGMPV3', 'SSDP', 'AGENT',
]);

/** Link-local / lab-control chatter for the non-HTTP Traffic tab. */
export function isTrafficFlowNoise(flow) {
  if (!flow) return false;
  const proto = String(flow.protocol || '').toUpperCase();
  if (TRAFFIC_NOISE_PROTOS.has(proto)) return true;
  if (flow.srcPort === 9443 || flow.dstPort === 9443) return true;
  if (proto === 'ICMPV6') return true;
  const info = String(flow.info || '');
  if (/wpad/i.test(info) && /LLMNR|NBNS/i.test(proto)) return true;
  return isNetworkHostNoise(flow.srcIp) || isNetworkHostNoise(flow.dstIp)
    || (flow.names || []).some((n) => isNetworkHostNoise(n));
}

export function isNoise(text) {
  if (!text) return false;
  const normalized = normalizePath(text);
  if (isNetworkHostNoise(normalized)) return true;
  return isPathNoise(normalized);
}

export function isSysmonNoise(ev) {
  if (!ev) return false;
  const label = ev.summary || ev.target || ev.targetObject || ev.image || ev.queryName || ev.type || '';
  return isNoise(label)
    || isNoise(ev.image || '')
    || isNoise(ev.commandLine || '')
    || isNoise(ev.queryName || '');
}

export function isUsnNoise(ev) {
  return isFileNoise(ev?.fileName || '');
}

export function isUsnLeafPath(path, file) {
  const p = normalizePath(path || normalizeFile(file).path);
  if (!p) return false;
  if (/\\_usn_leaf\\/i.test(p)) return true;
  if (!p.includes('\\') && !(p.length >= 2 && p[1] === ':')) return true;
  if (!/^[A-Za-z]:\\[^\\]+$/.test(p)) return false;
  const f = normalizeFile(file);
  const hash = f.hash ?? f.h;
  const size = f.size ?? f.s ?? f.toSize;
  return !hash && (size == null || size === 0);
}

export function stripUsnLeafFiles(diff) {
  if (!diff?.files) return diff;
  const keep = (f) => !isUsnLeafPath(null, f);
  const keepMod = (f) => !isUsnLeafPath(null, f) && !isUsnLeafPath(null, f?.before) && !isUsnLeafPath(null, f?.after);
  const files = {
    added: (diff.files.added || []).filter(keep),
    removed: (diff.files.removed || []).filter(keep),
    modified: (diff.files.modified || []).filter(keepMod),
  };
  return {
    ...diff,
    files,
    summary: {
      ...(diff.summary || {}),
      filesAdded: files.added.length,
      filesRemoved: files.removed.length,
      filesModified: files.modified.length,
    },
  };
}

export function filterDiff(diff, hideNoise) {
  const base = stripUsnLeafFiles(diff);
  if (!base || !hideNoise) return base;
  const files = base.files || {};
  const dns = (base.network?.dns || []).filter((e) => !isNetworkDnsNoise(e));
  const requests = (base.network?.requests || []).filter((e) => !isNetworkRequestNoise(e));
  const reg = base.registry || {};
  const registry = {
    added: (reg.added || []).filter((e) => !isRegistryNoise(e)),
    removed: (reg.removed || []).filter((e) => !isRegistryNoise(e)),
    modified: (reg.modified || []).filter((e) => !isRegistryNoise(e)),
  };
  const dropped = ((reg.added || []).length - registry.added.length)
    + ((reg.removed || []).length - registry.removed.length)
    + ((reg.modified || []).length - registry.modified.length);
  const filtered = {
    ...base,
    files: {
      added: (files.added || []).filter((f) => !isFileNoise(f)),
      removed: (files.removed || []).filter((f) => !isFileNoise(f)),
      modified: (files.modified || []).filter((f) => !isFileNoise(f)),
    },
    registry: {
      ...(base.registry || {}),
      ...registry,
    },
    sysmon: {
      ...(base.sysmon || {}),
      added: (base.sysmon?.added || []).filter((e) => !isSysmonNoise(e)),
    },
    usn: base.usn ? {
      ...base.usn,
      events: (base.usn.events || []).filter((e) => !isUsnNoise(e)),
    } : base.usn,
    network: base.network ? {
      ...base.network,
      dns,
      requests,
    } : base.network,
  };
  filtered.summary = {
    ...(base.summary || {}),
    filesAdded: filtered.files.added.length,
    filesRemoved: filtered.files.removed.length,
    filesModified: filtered.files.modified.length,
    sysmonAdded: filtered.sysmon.added.length,
    dnsQueries: dns.length,
    networkRequests: requests.length,
    registryAdded: registry.added.length,
    registryRemoved: registry.removed.length,
    registryModified: registry.modified.length,
    registryVolatileFiltered: (base.summary?.registryVolatileFiltered || 0) + dropped,
  };
  return filtered;
}
