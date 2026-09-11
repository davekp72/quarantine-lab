/**
 * Regression: guest-controlled paths/keys must not become live HTML in the overview.
 * Run: node manifest/viewer/test-overview-xss.mjs
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appSrc = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const openViewerPs1 = fs.readFileSync(path.join(__dirname, 'Open-ManifestDiffViewer.ps1'), 'utf8');

// --- Source / CSP guards ---
assert.match(
  indexHtml,
  /http-equiv="Content-Security-Policy"/i,
  'index.html must declare a CSP'
);
assert.match(
  indexHtml,
  /script-src 'self'/,
  'standalone viewer CSP should allow only same-origin scripts'
);
assert.match(
  openViewerPs1,
  /script-src 'nonce-\$cspNonce'/,
  'session.html generator must use nonce script-src (inline embed)'
);
assert.match(
  openViewerPs1,
  /nonce="\$cspNonce"/,
  'session.html generator must stamp nonces on inline scripts/styles'
);
assert.doesNotMatch(
  appSrc,
  /panel\.innerHTML\s*=\s*html/,
  'overview must not assign a built HTML string to panel.innerHTML'
);
assert.doesNotMatch(
  appSrc,
  /\$\{r\.label/,
  'r.label must not be interpolated into HTML templates'
);
assert.doesNotMatch(
  appSrc,
  /data-row-id="\$\{/,
  'data-row-id must not be string-interpolated into HTML'
);
assert.match(appSrc, /function buildPlainTable/, 'buildPlainTable helper required');
assert.match(appSrc, /function isSafeOverviewRowId/, 'isSafeOverviewRowId helper required');

function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing function ${name}`);
  let i = src.indexOf('{', start);
  assert.ok(i >= 0, `missing body for ${name}`);
  let depth = 0;
  for (; i < src.length; i++) {
    const ch = src[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        return src.slice(start, i + 1);
      }
    }
  }
  throw new Error(`unclosed function ${name}`);
}

// --- Minimal DOM for buildPlainTable ---
function createMinimalDocument() {
  class Node {
    constructor() {
      this.childNodes = [];
      this.parentNode = null;
    }
    appendChild(child) {
      if (child.parentNode) {
        const sibs = child.parentNode.childNodes;
        const idx = sibs.indexOf(child);
        if (idx >= 0) sibs.splice(idx, 1);
      }
      child.parentNode = this;
      this.childNodes.push(child);
      return child;
    }
    get textContent() {
      if (this.nodeType === 3) return this.nodeValue;
      return this.childNodes.map((c) => c.textContent).join('');
    }
    set textContent(v) {
      this.childNodes = [];
      if (v != null && String(v) !== '') {
        const t = new TextNode(String(v));
        t.parentNode = this;
        this.childNodes.push(t);
      }
    }
  }

  class TextNode extends Node {
    constructor(value) {
      super();
      this.nodeType = 3;
      this.nodeValue = String(value);
    }
  }

  class Element extends Node {
    constructor(tag) {
      super();
      this.nodeType = 1;
      this.tagName = String(tag).toUpperCase();
      this.attributes = Object.create(null);
      this.className = '';
    }
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    }
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name)
        ? this.attributes[name]
        : null;
    }
    querySelectorAll(selector) {
      const out = [];
      const walk = (el) => {
        if (!(el instanceof Element)) return;
        if (selector === 'tbody tr[data-row-id]' && el.tagName === 'TR' && el.getAttribute('data-row-id')) {
          out.push(el);
        }
        if (selector === 'img' && el.tagName === 'IMG') out.push(el);
        if (selector === 'script' && el.tagName === 'SCRIPT') out.push(el);
        el.childNodes.forEach(walk);
      };
      walk(this);
      return out;
    }
  }

  return {
    createElement(tag) {
      return new Element(tag);
    },
    createTextNode(text) {
      return new TextNode(text);
    },
  };
}

const document = createMinimalDocument();
class Node {}
const helpersSrc = [
  extractFunction(appSrc, 'isSafeOverviewRowId'),
  extractFunction(appSrc, 'buildPlainTable'),
  '({ isSafeOverviewRowId, buildPlainTable });',
].join('\n');
const api = vm.runInNewContext(helpersSrc, { document, Node });

assert.equal(typeof api.buildPlainTable, 'function');
assert.equal(typeof api.isSafeOverviewRowId, 'function');

const payloads = [
  '<img src=x onerror=alert(1)>',
  '"><script>alert(1)</script>',
  'C:\\Users\\x\\<svg onload=alert(1)>.exe',
  'HKCU\\Software\\<img src=x onerror=alert(1)>\\Run',
  "file:added:C:\\evil\\john's file.exe",
];

for (const payload of payloads) {
  const table = api.buildPlainTable(
    ['Type', 'Item', 'Detail'],
    [
      {
        rowId: `file:added:${payload}`,
        cells: [
          { text: 'added' },
          { text: payload, className: 'path' },
          `detail ${payload}`,
        ],
      },
    ]
  );

  assert.equal(table.querySelectorAll('img').length, 0, `img node for payload: ${payload}`);
  assert.equal(table.querySelectorAll('script').length, 0, `script node for payload: ${payload}`);

  const tr = table.querySelectorAll('tbody tr[data-row-id]')[0];
  assert.ok(tr, 'row rendered');
  assert.equal(tr.getAttribute('data-row-id'), `file:added:${payload}`);
  assert.ok(
    tr.textContent.includes(payload),
    `payload must appear as text, not markup: ${payload}`
  );
}

assert.equal(api.isSafeOverviewRowId('file:added:C:\\Users\\a\\b.exe'), true);
assert.equal(api.isSafeOverviewRowId("file:added:C:\\Users\\a\\john's file.exe"), true);
assert.equal(api.isSafeOverviewRowId('registry:added:HKCU\\Software\\x'), true);
assert.equal(api.isSafeOverviewRowId('javascript:alert(1)'), false);
assert.equal(api.isSafeOverviewRowId('file:added:\u0000evil'), false);
assert.equal(api.isSafeOverviewRowId(''), false);

console.log('ok: overview XSS regression (%d payloads)', payloads.length);
