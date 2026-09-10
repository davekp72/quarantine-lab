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

const NOISE_PATTERNS = [
  /\\Microsoft\\EdgeUpdate\\/i,
  /\\Microsoft\\OneDrive\\ListSync/i,
  /\\AppData\\Local\\Microsoft\\OneDrive\\/i,
  /\\\$Extend\\/i,
  /\\Windows\\ServiceState\\/i,
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
  /\\SecurityHealthService\.exe/i,
];

const NETWORK_HOST_SUFFIXES = [
  'msftconnecttest.com', 'microsoft.com', 'microsoft.net', 'msn.com', 'bing.com',
  'windowsupdate.com', 'office.com', 'office365.com', 'live.com', 'microsoftpersonalcontent.com',
  'onedrive.com', 'sharepoint.com', 'skype.com', 'windows.com', 'xboxlive.com', 'xboxab.com',
  'azure.com', 'azureedge.net', 'trafficmanager.net', 'msedge.net', 'msauth.net', 'msidentity.com',
  'hotmail.com', 'outlook.com', 'visualstudio.com', 'digicert.com', 'akamaihd.net', 'akamaiedge.net',
  'akamai.net', 'aspnetcdn.com', 'windows.net', 'officeapps.live.com', 'mp.microsoft.com',
  'events.data.microsoft.com', 'data.microsoft.com', 'telemetry.microsoft.com', 'msftncsi.com',
  'cloud.microsoft', 'office.net', 'sfx.ms', 's-microsoft.com', 'akamaized.net',
];

const NETWORK_NOISE_PATTERNS = [
  /\.msftconnecttest\.com/i, /\.microsoft\.com(\/|$)/i, /\.msn\.com(\/|$)/i, /\.bing\.com(\/|$)/i,
  /\.windowsupdate\.com(\/|$)/i, /\.office\.com(\/|$)/i, /\.live\.com(\/|$)/i,
  /\.microsoftpersonalcontent\.com(\/|$)/i, /\.onedrive\.com(\/|$)/i, /\.microsoft\.net(\/|$)/i,
  /\.windows\.com(\/|$)/i, /\.update\.microsoft\.com(\/|$)/i, /\.mp\.microsoft\.com(\/|$)/i,
  /\.data\.microsoft\.com(\/|$)/i, /msftncsi\.com/i, /\.office365\.com(\/|$)/i, /\.msauth\.net(\/|$)/i,
  /\.msidentity\.com(\/|$)/i, /\.azure\.com(\/|$)/i, /\.azureedge\.net(\/|$)/i,
  /\.trafficmanager\.net(\/|$)/i, /\.msedge\.net(\/|$)/i, /edge\.microsoft\.com/i,
  /\.digicert\.com(\/|$)/i, /\.akamai(hd)?\.net(\/|$)/i, /\.akamaiedge\.net(\/|$)/i,
  /\.aspnetcdn\.com(\/|$)/i, /\.windows\.net(\/|$)/i, /\.hotmail\.com(\/|$)/i,
  /\.outlook\.com(\/|$)/i, /\.skype\.com(\/|$)/i, /\.visualstudio\.com(\/|$)/i,
  /ctldl\.windowsupdate\.com/i, /settings-win\.data\.microsoft\.com/i,
  /v\d+\.events\.data\.microsoft\.com/i, /watson\.microsoft\.com/i,
  /watson\.telemetry\.microsoft\.com/i, /crl\.microsoft\.com/i, /ocsp\.digicert\.com/i,
];

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
  return NOISE_PATTERNS.some((re) => re.test(normalizePath(path)));
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
  const path = f.path || fileOrPath?.fileName || '';
  if (!path) return false;
  if (isEphemeralTempPath(path)) return true;
  if (isCompilerTempNoise(path)) return true;
  if (/\\\$Extend\\/i.test(normalizePath(path))) return true;
  if (/\\AppData\\Local\\Microsoft\\OneDrive\\/i.test(normalizePath(path))) return true;
  if (/\\Windows\\ServiceState\\/i.test(normalizePath(path))) return true;
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
  return NETWORK_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith('.' + suffix));
}

export function isNetworkDnsNoise(entry) {
  if (!entry) return false;
  return isNetworkHostNoise(entry.query || entry.qname || entry.host || '');
}

export function isNetworkRequestNoise(entry) {
  if (!entry) return false;
  return isNetworkHostNoise(entry.host || entry.url || entry.path || '');
}

export function isNoise(text) {
  if (!text) return false;
  const normalized = normalizePath(text);
  if (isNetworkHostNoise(normalized)) return true;
  return isPathNoise(normalized) || NETWORK_NOISE_PATTERNS.some((re) => re.test(normalized));
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
  const filtered = {
    ...base,
    files: {
      added: (files.added || []).filter((f) => !isFileNoise(f)),
      removed: (files.removed || []).filter((f) => !isFileNoise(f)),
      modified: (files.modified || []).filter((f) => !isFileNoise(f)),
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
    registryAdded: (base.registry?.added || []).length,
    registryRemoved: (base.registry?.removed || []).length,
    registryModified: (base.registry?.modified || []).length,
  };
  return filtered;
}
