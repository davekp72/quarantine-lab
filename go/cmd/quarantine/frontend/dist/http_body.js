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

function bodyLooksCompressed(part) {
  const body = String(part?.body ?? '');
  if (body.length < 2) return false;
  const b0 = body.charCodeAt(0);
  const b1 = body.charCodeAt(1);
  if (b0 === 0x1f && b1 === 0x8b) return true; // gzip
  if (b0 === 0x1f && b1 === 0x9d) return true; // compress
  if (body.length >= 3 && b0 === 0x42 && b1 === 0x5a && body.charCodeAt(2) === 0x68) return true; // bzip2
  if (
    body.length >= 4 &&
    b0 === 0x28 &&
    b1 === 0xb5 &&
    body.charCodeAt(2) === 0x2f &&
    body.charCodeAt(3) === 0xfd
  ) {
    return true; // zstd
  }
  if (
    body.length >= 4 &&
    b0 === 0x04 &&
    b1 === 0x22 &&
    body.charCodeAt(2) === 0x4d &&
    body.charCodeAt(3) === 0x18
  ) {
    return true; // lz4 frame
  }
  if (
    body.length >= 6 &&
    b0 === 0xfd &&
    b1 === 0x37 &&
    body.charCodeAt(2) === 0x7a &&
    body.charCodeAt(3) === 0x58 &&
    body.charCodeAt(4) === 0x5a &&
    body.charCodeAt(5) === 0x00
  ) {
    return true; // xz
  }
  // zlib/deflate: CMF=0x08 method, header % 31 == 0
  if (body.length >= 2 && (b0 & 0x0f) === 8 && (((b0 << 8) | b1) % 31) === 0) return true;
  return false;
}

export function needsHttpBodyDecode(part) {
  if (!part || part.body == null || part.body === '') return false;
  if (bodyLooksCompressed(part)) return true;
  const ce = contentEncodingOf(part).toLowerCase();
  if (!ce || ce === 'identity') return false;
  return /\b(br|brotli|gzip|x-gzip|deflate|zstd|compress|x-compress|bzip2|bz2|x-bzip2|lz4|lz4frame|x-lz4|xz|lzma|x-xz|snappy|x-snappy-framed)\b/.test(ce);
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
