import {
  buildSafeTable,
  setMutedMessage,
  appendMuted,
  escapeAttr,
} from './safe_dom.js';
import { isTrafficFlowNoise } from './noise.js';

let cache = { key: '', snapshot: '', data: null, error: '', loading: false };
let filters = { proto: '', transport: '', q: '', breaches: false };
let selectedId = '';
let payloadMode = 'ascii';

const TRANSPORTS = [
  ['', 'All transports'],
  ['tcp', 'TCP'],
  ['udp', 'UDP'],
  ['icmp', 'ICMP'],
  ['arp', 'ARP'],
  ['igmp', 'IGMP'],
  ['other', 'Other'],
];

function protoClass(proto) {
  const p = String(proto || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
  if (/dns|mdns|llmnr|nbns/.test(p)) return 'proto-dns';
  if (/smtp|imap|pop/.test(p)) return 'proto-mail';
  if (/ssh|telnet/.test(p)) return 'proto-ssh';
  if (/icmp/.test(p)) return 'proto-icmp';
  if (/dhcp/.test(p)) return 'proto-dhcp';
  if (/ntp|snmp/.test(p)) return 'proto-udp';
  if (/smb|rdp|vnc|ftp/.test(p)) return 'proto-svc';
  if (p === 'arp' || p === 'igmp' || p === 'ssdp') return 'proto-link';
  if (p === 'tcp') return 'proto-tcp';
  if (p === 'udp') return 'proto-udp';
  return 'proto-other';
}

function flowMatches(flow, f) {
  if (f.proto && String(flow.protocol || '').toUpperCase() !== f.proto.toUpperCase()) return false;
  if (f.transport && String(flow.transport || '').toLowerCase() !== f.transport) return false;
  if (f.breaches && !flow.policyBreach) return false;
  const q = String(f.q || '').trim().toLowerCase();
  if (!q) return true;
  const hay = [
    flow.srcIp, flow.dstIp, flow.info, flow.protocol, flow.transport, flow.id,
    ...(flow.names || []),
  ].join(' ').toLowerCase();
  return hay.includes(q);
}

function endpoint(flow) {
  const src = flow.srcPort ? `${flow.srcIp}:${flow.srcPort}` : (flow.srcIp || '');
  const dst = flow.dstPort ? `${flow.dstIp}:${flow.dstPort}` : (flow.dstIp || '');
  if (!src && !dst) return '—';
  return `${src} → ${dst}`;
}

export function invalidateTrafficCache() {
  cache = { key: '', snapshot: '', data: null, error: '', loading: false };
  selectedId = '';
}

export async function renderTraffic(panel, { snapshot, hideNoise, backend, caseId }) {
  if (!panel) return;
  const prevQ = document.activeElement?.id === 'traffic-q' ? {
    start: document.activeElement.selectionStart,
    end: document.activeElement.selectionEnd,
  } : null;
  const cacheKey = `${caseId || 'live'}::${snapshot || ''}`;
  if (!snapshot && !caseId) {
    setMutedMessage(panel, 'Compare snapshots first — Traffic reads the evidence PCAP for the To snapshot.');
    return;
  }

  if (cache.key !== cacheKey || (!cache.data && !cache.loading && !cache.error)) {
    cache = { key: cacheKey, snapshot, data: null, error: '', loading: true };
    panel.replaceChildren();
    appendMuted(panel, 'Dissecting PCAP with tshark…');
    try {
      const api = await backend();
      if (!api?.ListPcapFlowsWails) {
        throw new Error('Restart the UI after this update (ListPcapFlowsWails missing).');
      }
      cache.data = await api.ListPcapFlowsWails(snapshot);
      cache.error = '';
    } catch (e) {
      cache.error = String(e);
      cache.data = null;
    } finally {
      cache.loading = false;
    }
  }

  if (cache.loading) {
    setMutedMessage(panel, 'Dissecting PCAP with tshark…');
    return;
  }
  if (cache.error) {
    setMutedMessage(panel, cache.error);
    return;
  }

  const data = cache.data || {};
  let flows = Array.isArray(data.flows) ? data.flows : [];
  if (hideNoise) {
    flows = flows.filter((f) => !isTrafficFlowNoise(f));
  }
  const visible = flows.filter((f) => flowMatches(f, filters));
  const protos = [...new Set(flows.map((f) => f.protocol).filter(Boolean))].sort();

  const breachN = Number(data.breaches || 0);
  panel.replaceChildren();
  appendMuted(panel, `${data.message || ''} · HTTP/S excluded`.trim());
  if (hideNoise) {
    appendMuted(panel, 'Routine ARP / IGMP / SSDP / lab-agent noise hidden.');
  }
  if (breachN) {
    appendMuted(panel, `${breachN} conversation(s) attempted a destination/port outside the permissive allowlist (still in PCAP).`);
  }

  const bar = document.createElement('div');
  bar.className = 'traffic-filters';
  bar.appendChild(selectControl('Protocol', 'traffic-proto', [['', 'All protocols'], ...protos.map((p) => [p, p])], filters.proto, (v) => {
    filters.proto = v;
    renderTraffic(panel, { snapshot, hideNoise, backend, caseId });
  }));
  bar.appendChild(selectControl('Transport', 'traffic-transport', TRANSPORTS, filters.transport, (v) => {
    filters.transport = v;
    renderTraffic(panel, { snapshot, hideNoise, backend, caseId });
  }));
  const pcapBtn = document.createElement('button');
  pcapBtn.type = 'button';
  pcapBtn.textContent = 'Download PCAP';
  pcapBtn.disabled = !data.pcap;
  pcapBtn.title = data.pcap ? 'Save the evidence capture' : 'No PCAP in this evidence';
  const pcapMsg = document.createElement('span');
  pcapMsg.className = 'muted action-msg';
  pcapBtn.addEventListener('click', async () => {
    pcapBtn.disabled = true;
    pcapBtn.textContent = 'Saving…';
    try {
      const api = await backend();
      if (!api?.ExportPcapWails) {
        throw new Error('Restart the UI after this update (ExportPcapWails missing).');
      }
      const dest = await api.ExportPcapWails(snapshot);
      pcapMsg.textContent = dest ? `Saved ${dest}` : '';
    } catch (e) {
      pcapMsg.textContent = String(e);
    } finally {
      pcapBtn.disabled = !data.pcap;
      pcapBtn.textContent = 'Download PCAP';
    }
  });
  bar.appendChild(pcapBtn);
  bar.appendChild(pcapMsg);
  const hostLabel = document.createElement('label');
  hostLabel.textContent = 'Host / name';
  const hostInput = document.createElement('input');
  hostInput.type = 'search';
  hostInput.id = 'traffic-q';
  hostInput.placeholder = '10.66.0.15, example.test, smtp…';
  hostInput.value = filters.q;
  hostInput.addEventListener('input', () => {
    filters.q = hostInput.value;
    renderTraffic(panel, { snapshot, hideNoise, backend, caseId });
  });
  hostLabel.appendChild(hostInput);
  bar.appendChild(hostLabel);
  const breachLabel = document.createElement('label');
  breachLabel.className = 'check';
  const breachBox = document.createElement('input');
  breachBox.type = 'checkbox';
  breachBox.checked = !!filters.breaches;
  breachBox.addEventListener('change', () => {
    filters.breaches = breachBox.checked;
    renderTraffic(panel, { snapshot, hideNoise, backend, caseId });
  });
  breachLabel.appendChild(breachBox);
  breachLabel.appendChild(document.createTextNode(' Policy breaches only'));
  bar.appendChild(breachLabel);
  panel.appendChild(bar);
  if (prevQ) {
    hostInput.focus();
    try { hostInput.setSelectionRange(prevQ.start, prevQ.end); } catch (_) { /* ignore */ }
  }

  if (!visible.length) {
    appendMuted(panel, data.available === false
      ? (data.message || 'No PCAP for this snapshot.')
      : 'No conversations match the current filters.');
    return;
  }

  const split = document.createElement('div');
  split.className = 'network-split';
  const list = document.createElement('div');
  list.className = 'net-req-list';
  const table = buildSafeTable(
    ['Proto', 'Transport', 'Endpoints', 'Pkts', 'Info', 'Time'],
    visible.map((f) => ({
      className: `net-req-row traffic-row${f.id === selectedId ? ' selected' : ''}${f.hasPayload ? ' has-body' : ''}${f.policyBreach ? ' policy-breach' : ''}`,
      attrs: { 'data-flow-id': f.id },
      cells: [
        { text: f.protocol || '', className: `proto-badge ${protoClass(f.protocol)}` },
        (f.transport || '').toUpperCase(),
        { text: endpoint(f), title: (f.names || []).join(', ') },
        f.packets ?? '',
        { text: truncate((f.policyBreach ? '[breach] ' : '') + (f.policyReason || f.info || (f.names || []).join(', ')), 72), title: f.policyReason || f.info || '' },
        f.last || f.first || '',
      ],
    })),
  );
  table.id = 'traffic-table';
  list.appendChild(table);

  const detail = document.createElement('div');
  detail.id = 'traffic-detail';
  detail.className = 'net-req-detail muted';
  detail.textContent = 'Click a conversation to inspect payload (tshark follow / dissection).';
  split.appendChild(list);
  split.appendChild(detail);
  panel.appendChild(split);

  list.querySelectorAll('.traffic-row').forEach((tr) => {
    tr.addEventListener('click', () => {
      const id = tr.getAttribute('data-flow-id');
      const flow = visible.find((f) => f.id === id);
      selectedId = id;
      list.querySelectorAll('.traffic-row.selected').forEach((x) => x.classList.remove('selected'));
      tr.classList.add('selected');
      inspectFlow(detail, snapshot, flow, backend);
    });
  });

  if (selectedId && visible.some((f) => f.id === selectedId)) {
    const flow = visible.find((f) => f.id === selectedId);
    inspectFlow(detail, snapshot, flow, backend);
  }
}

async function inspectFlow(detail, snapshot, flow, backend) {
  if (!detail || !flow) return;
  detail.classList.remove('muted');
  detail.replaceChildren();
  appendMuted(detail, 'Loading payload…');
  try {
    const api = await backend();
    const format = payloadMode === 'hex' ? 'hex' : payloadMode === 'summary' ? 'summary' : 'ascii';
    const res = await api.InspectPcapFlowWails(snapshot, flow.id, format);
    if (!detail.isConnected) return;
    renderInspect(detail, flow, res);
  } catch (e) {
    if (!detail.isConnected) return;
    detail.replaceChildren();
    appendMuted(detail, String(e));
  }
}

function renderInspect(detail, flow, res) {
  detail.replaceChildren();
  const meta = document.createElement('div');
  meta.className = 'http-flow-meta';
  const title = document.createElement('p');
  const badge = document.createElement('span');
  badge.className = `proto-badge ${protoClass(flow.protocol)}`;
  badge.textContent = flow.protocol || res.protocol || '';
  title.appendChild(badge);
  title.appendChild(document.createTextNode(`  ${endpoint(flow)}  ·  ${flow.packets || 0} pkts  ·  ${flow.bytes || 0} B`));
  meta.appendChild(title);
  if (flow.policyBreach) {
    const b = document.createElement('p');
    b.className = 'policy-breach-note';
    b.textContent = 'Policy breach: ' + (flow.policyReason || 'destination/port outside the permissive allowlist');
    meta.appendChild(b);
  }
  if (flow.names?.length) {
    const n = document.createElement('p');
    n.className = 'muted';
    n.textContent = `Names: ${flow.names.join(', ')}`;
    meta.appendChild(n);
  }
  if (res.node0 || res.node1) {
    const n = document.createElement('p');
    n.className = 'muted';
    n.textContent = `${res.node0 || ''}  ↔  ${res.node1 || ''}`;
    meta.appendChild(n);
  }
  detail.appendChild(meta);

  const modes = document.createElement('div');
  modes.className = 'traffic-modes';
  for (const [id, label] of [['ascii', 'ASCII'], ['hex', 'Hex'], ['summary', 'Packets']]) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    btn.className = payloadMode === id ? 'active' : '';
    btn.addEventListener('click', () => {
      payloadMode = id;
      const snap = cache.snapshot;
      inspectFlow(detail, snap, flow, async () => window.go?.app?.App);
    });
    modes.appendChild(btn);
  }
  detail.appendChild(modes);

  const panes = document.createElement('div');
  panes.className = 'http-flow-panes traffic-panes';
  const body = payloadMode === 'hex' ? (res.hex || res.ascii || '')
    : payloadMode === 'summary' ? (res.summary || []).join('\n')
      : (res.ascii || '');
  const hl = payloadMode === 'hex'
    ? { html: escapeAttr(body || '(empty)'), lang: 'hex' }
    : ((typeof QuarantineHighlight !== 'undefined' && QuarantineHighlight.highlightProtocol)
      ? QuarantineHighlight.highlightProtocol(body, flow.protocol)
      : { html: escapeAttr(body || '(empty)'), lang: 'plain' });

  const pane = document.createElement('div');
  pane.className = 'http-flow-pane';
  const head = document.createElement('div');
  head.className = 'http-flow-pane-head';
  head.textContent = payloadMode === 'hex' ? 'Payload (hex)' : payloadMode === 'summary' ? 'Packet info' : 'Payload (ascii)';
  if (res.truncated) {
    const t = document.createElement('span');
    t.className = 'muted';
    t.textContent = ' · truncated';
    head.appendChild(t);
  }
  const scroll = document.createElement('div');
  scroll.className = 'http-flow-pane-scroll';
  const pre = document.createElement('pre');
  pre.className = `content-block body hl-code lang-${hl.lang || 'plain'}`;
  pre.innerHTML = hl.html;
  scroll.appendChild(pre);
  pane.appendChild(head);
  pane.appendChild(scroll);
  panes.appendChild(pane);
  detail.appendChild(panes);
}

function selectControl(labelText, id, options, value, onChange) {
  const label = document.createElement('label');
  label.textContent = labelText;
  const sel = document.createElement('select');
  sel.id = id;
  for (const [v, text] of options) {
    const opt = document.createElement('option');
    opt.value = v;
    opt.textContent = text;
    sel.appendChild(opt);
  }
  sel.value = value;
  sel.addEventListener('change', () => onChange(sel.value));
  label.appendChild(sel);
  return label;
}

function truncate(s, n) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}
