/**
 * Regression: guest-controlled evidence strings must not survive escape as active HTML.
 * Run: node go/cmd/quarantine/frontend/dist/evidence_escape_test.mjs
 */
import { createRequire } from 'module';
import {
  escapeHtml,
  escapeAttr,
  looksLikeHtmlInjection,
  buildSafeTable,
} from './safe_dom.js';

const require = createRequire(import.meta.url);
const highlight = require('./highlight.js');

const XSS_PAYLOADS = [
  '<img src=x onerror=alert(1)>',
  '"><img src=x onerror=alert(1)>',
  "';alert(1)//",
  '<svg onload=alert(1)>',
  'evil.com/<script>alert(1)</script>',
  'C:\\Users\\x\\<img src=x onerror=alert(1)>.exe',
  'dns.<img src=x onerror=alert(1)>.test',
];

let failed = 0;

function assert(cond, msg) {
  if (!cond) {
    failed += 1;
    console.error('FAIL:', msg);
  }
}

for (const payload of XSS_PAYLOADS) {
  assert(looksLikeHtmlInjection(payload) || payload.includes('<') || payload.includes('"') || payload.includes("'"),
    `detector should flag ${payload}`);
  const esc = escapeHtml(payload);
  assert(!esc.includes('<img'), `escapeHtml must neutralize img tag: ${payload} → ${esc}`);
  assert(!esc.includes('<script'), `escapeHtml must neutralize script: ${payload}`);
  assert(!esc.includes('<svg'), `escapeHtml must neutralize svg: ${payload}`);
  assert(esc === escapeAttr(payload), 'escapeAttr must match escapeHtml');

  const hl = highlight.highlightBody(payload, 'text/html');
  assert(!hl.html.includes('<img src'), `highlightBody must escape HTML body: ${hl.html}`);
  assert(!/onerror\s*=/i.test(hl.html.replace(/&[a-z]+;/gi, '')), `highlightBody must not leave raw onerror: ${hl.html}`);
}

// DOM table path: textContent must preserve payload as text, not nodes.
if (typeof document === 'undefined') {
  // Minimal DOM stub sufficient for buildSafeTable.
  globalThis.document = {
    createElement(tag) {
      const el = {
        tagName: tag.toUpperCase(),
        children: [],
        attrs: {},
        className: '',
        title: '',
        textContent: '',
        setAttribute(k, v) { this.attrs[k] = String(v); },
        appendChild(c) { this.children.push(c); return c; },
      };
      return el;
    },
  };
}

const table = buildSafeTable(
  ['File', 'Name'],
  [{ cells: ['<img src=x onerror=alert(1)>.exe', 'dns.<img src=x onerror=alert(1)>.test'] }],
);
const tbody = table.children.find((c) => c.tagName === 'TBODY');
const tr = tbody.children[0];
assert(tr.children[0].textContent === '<img src=x onerror=alert(1)>.exe', 'USN filename cell must use textContent');
assert(tr.children[1].textContent === 'dns.<img src=x onerror=alert(1)>.test', 'DNS name cell must use textContent');
assert(!tr.children[0].children.length, 'filename cell must not create child elements from HTML');

if (failed) {
  console.error(`${failed} assertion(s) failed`);
  process.exit(1);
}
console.log(`ok — ${XSS_PAYLOADS.length} payloads escaped; safe table uses textContent`);
