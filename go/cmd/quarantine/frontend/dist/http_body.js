/** View-time HTTP body decode. Prefer on-disk flows.jsonl over mangled diff previews. */

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const want = String(name || '').toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === want) return String(v ?? '');
  }
  return '';
}

export function contentEncodingOf(part) {
  return headerValue(part?.headers, 'content-encoding');
}

export function needsHttpBodyDecode(part) {
  if (!part || part.body == null || part.body === '') return false;
  const ce = contentEncodingOf(part).toLowerCase();
  if (!ce || ce === 'identity') return false;
  return /\b(br|brotli|gzip|x-gzip|deflate)\b/.test(ce);
}

/**
 * @param {any} part
 * @param {(encoding:string, contentEncoding:string, body:string)=>Promise<any>} decodeFn
 */
export async function decodeHttpPart(part, decodeFn) {
  if (!needsHttpBodyDecode(part) || typeof decodeFn !== 'function') {
    return part;
  }
  try {
    const out = await decodeFn(part.encoding || 'latin-1', contentEncodingOf(part), String(part.body));
    if (!out || out.error) {
      return { ...part, decodeError: out?.error || 'decode failed' };
    }
    return {
      ...part,
      body: out.body,
      encoding: out.encoding || 'utf-8',
      decompressed: out.decompressed || contentEncodingOf(part),
      bodyTruncated: part.bodyTruncated || !!out.truncated,
      decodeError: undefined,
    };
  } catch (e) {
    return { ...part, decodeError: String(e) };
  }
}

/**
 * Resolve a network request for the detail pane.
 * Loads full bodies from flows.jsonl when flowFile/flowLine are present.
 */
export async function resolveHttpFlow(flow, api) {
  if (!flow) return flow;
  const file = flow.flowFile;
  const line = Number(flow.flowLine);
  if (file && line > 0 && typeof api?.LoadHTTPFlowWails === 'function') {
    try {
      const full = await api.LoadHTTPFlowWails(file, line);
      if (full && (full.request || full.response)) {
        return {
          ...flow,
          ...full,
          url: full.url || flow.url,
          method: full.method || flow.method,
          status: full.status != null ? full.status : flow.status,
          resolvedIps: full.resolvedIps || flow.resolvedIps,
          source: full.source || flow.source,
          hasBody: true,
        };
      }
    } catch (e) {
      flow = { ...flow, loadError: String(e) };
    }
  }
  const decodeFn = typeof api?.DecodeHTTPBodyWails === 'function'
    ? (enc, ce, body) => api.DecodeHTTPBodyWails(enc, ce, body)
    : null;
  if (!decodeFn) return flow;
  const request = await decodeHttpPart(flow.request, decodeFn);
  const response = await decodeHttpPart(flow.response, decodeFn);
  return { ...flow, request, response };
}
