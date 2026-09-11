/**
 * Lightweight syntax highlighting for HTTP request/response bodies.
 * No external deps — safe for offline Wails builds.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  // Always expose the global for <script src="highlight.js"> (Wails / viewer).
  root.QuarantineHighlight = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function () {
  'use strict';

  const MAX_HIGHLIGHT = 2 << 20; // match Go httpbody maxDecodedBytes (2 MiB)

  function escapeHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function detectLang(contentType, body) {
    const ct = String(contentType || '').toLowerCase();
    const text = String(body || '').trim();
    const lower = text.slice(0, 200).toLowerCase();
    if (ct.includes('json') || ct.includes('+json')) return 'json';
    if (ct.includes('html') || ct.includes('xhtml')) return 'html';
    if (ct.includes('xml') || ct.includes('svg')) return 'xml';
    if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
    if (ct.includes('css')) return 'css';
    if (ct.includes('x-www-form-urlencoded')) return 'form';
    if (text.startsWith('{') || text.startsWith('[')) {
      if (ct.includes('text/') || !ct) return 'json';
    }
    if (text.startsWith('<')) {
      if (lower.includes('<!doctype html') || /<html[\s>]/.test(lower) || /<(div|span|body|head|script|style|meta|link|p|a|img|table|form)\b/.test(lower)) {
        return 'html';
      }
      if (ct.includes('text/') || ct.includes('xml') || !ct) return 'xml';
    }
    return 'plain';
  }

  function prettyJson(text) {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      return text;
    }
  }

  function highlightJson(src) {
    // Tokenize strings first so we don't colorize inside them.
    const out = [];
    let i = 0;
    const s = String(src);
    while (i < s.length) {
      const ch = s[i];
      if (ch === '"') {
        let j = i + 1;
        let esc = false;
        while (j < s.length) {
          if (esc) {
            esc = false;
            j++;
            continue;
          }
          if (s[j] === '\\') {
            esc = true;
            j++;
            continue;
          }
          if (s[j] === '"') {
            j++;
            break;
          }
          j++;
        }
        const str = s.slice(i, j);
        // Key if followed by optional space and ':'
        let k = j;
        while (k < s.length && /\s/.test(s[k])) k++;
        const isKey = s[k] === ':';
        out.push(`<span class="tok-${isKey ? 'key' : 'str'}">${escapeHtml(str)}</span>`);
        i = j;
        continue;
      }
      if (/[-\d]/.test(ch) && (ch !== '-' || /[\d.]/.test(s[i + 1] || ''))) {
        let j = i + 1;
        while (j < s.length && /[\d.eE+-]/.test(s[j])) j++;
        out.push(`<span class="tok-num">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      if (/[a-zA-Z]/.test(ch)) {
        let j = i + 1;
        while (j < s.length && /[a-zA-Z]/.test(s[j])) j++;
        const word = s.slice(i, j);
        if (word === 'true' || word === 'false' || word === 'null') {
          out.push(`<span class="tok-kw">${escapeHtml(word)}</span>`);
        } else {
          out.push(escapeHtml(word));
        }
        i = j;
        continue;
      }
      if ('{}[]:,'.includes(ch)) {
        out.push(`<span class="tok-punc">${escapeHtml(ch)}</span>`);
        i++;
        continue;
      }
      out.push(escapeHtml(ch));
      i++;
    }
    return out.join('');
  }

  function highlightMarkup(src) {
    // Tokenize on the raw string, then escape. Regex-on-escaped HTML fails on
    // attributes because &quot; / &#39; contain '&' and break [^&]* matchers.
    const out = [];
    let i = 0;
    const s = String(src);
    while (i < s.length) {
      if (s.startsWith('<!--', i)) {
        let j = s.indexOf('-->', i + 4);
        j = j < 0 ? s.length : j + 3;
        out.push(`<span class="tok-comment">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      if (s[i] === '<' && (s[i + 1] === '!' || s[i + 1] === '?')) {
        let j = s.indexOf('>', i + 2);
        j = j < 0 ? s.length : j + 1;
        out.push(`<span class="tok-comment">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      if (s[i] === '<' && (s[i + 1] === '/' || /[A-Za-z]/.test(s[i + 1] || ''))) {
        out.push(`<span class="tok-punc">${escapeHtml('<')}</span>`);
        i++;
        if (s[i] === '/') {
          out.push(`<span class="tok-punc">${escapeHtml('/')}</span>`);
          i++;
        }
        let j = i;
        while (j < s.length && /[\w:.-]/.test(s[j])) j++;
        if (j > i) {
          out.push(`<span class="tok-tag">${escapeHtml(s.slice(i, j))}</span>`);
          i = j;
        }
        while (i < s.length && s[i] !== '>') {
          if (/\s/.test(s[i])) {
            out.push(escapeHtml(s[i]));
            i++;
            continue;
          }
          if (s[i] === '/' && s[i + 1] === '>') {
            out.push(`<span class="tok-punc">${escapeHtml('/')}</span>`);
            i++;
            break;
          }
          j = i;
          while (j < s.length && /[\w:.-]/.test(s[j])) j++;
          if (j === i) {
            out.push(escapeHtml(s[i]));
            i++;
            continue;
          }
          out.push(`<span class="tok-attr">${escapeHtml(s.slice(i, j))}</span>`);
          i = j;
          while (i < s.length && /\s/.test(s[i])) {
            out.push(escapeHtml(s[i]));
            i++;
          }
          if (s[i] !== '=') continue;
          out.push(`<span class="tok-punc">=</span>`);
          i++;
          while (i < s.length && /\s/.test(s[i])) {
            out.push(escapeHtml(s[i]));
            i++;
          }
          const q = s[i];
          if (q === '"' || q === "'") {
            j = i + 1;
            while (j < s.length && s[j] !== q) j++;
            if (j < s.length) j++;
            out.push(`<span class="tok-str">${escapeHtml(s.slice(i, j))}</span>`);
            i = j;
            continue;
          }
          j = i;
          while (j < s.length && !/[\s>]/.test(s[j]) && !(s[j] === '/' && s[j + 1] === '>')) j++;
          if (j > i) {
            out.push(`<span class="tok-str">${escapeHtml(s.slice(i, j))}</span>`);
            i = j;
          }
        }
        if (s[i] === '>') {
          out.push(`<span class="tok-punc">${escapeHtml('>')}</span>`);
          i++;
        }
        continue;
      }
      if (s[i] === '<') {
        out.push(escapeHtml('<'));
        i++;
        continue;
      }
      let j = s.indexOf('<', i);
      if (j < 0) j = s.length;
      out.push(escapeHtml(s.slice(i, j)).replace(
        /(&amp;(?:#\d+|#x[\da-fA-F]+|[\w.:-]+);)/g,
        '<span class="tok-kw">$1</span>'
      ));
      i = j;
    }
    return out.join('');
  }

  function highlightJs(src) {
    // Simple-ish: comments, strings, keywords, numbers.
    const keywords = new Set([
      'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'do', 'switch',
      'case', 'break', 'try', 'catch', 'finally', 'throw', 'new', 'typeof', 'instanceof',
      'class', 'extends', 'import', 'export', 'from', 'default', 'async', 'await', 'yield',
      'true', 'false', 'null', 'undefined', 'this', 'of', 'in'
    ]);
    const out = [];
    let i = 0;
    const s = String(src);
    while (i < s.length) {
      if (s.startsWith('//', i)) {
        let j = s.indexOf('\n', i);
        if (j < 0) j = s.length;
        out.push(`<span class="tok-comment">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      if (s.startsWith('/*', i)) {
        let j = s.indexOf('*/', i + 2);
        j = j < 0 ? s.length : j + 2;
        out.push(`<span class="tok-comment">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      const q = s[i];
      if (q === '"' || q === "'" || q === '`') {
        let j = i + 1;
        let esc = false;
        while (j < s.length) {
          if (esc) {
            esc = false;
            j++;
            continue;
          }
          if (s[j] === '\\') {
            esc = true;
            j++;
            continue;
          }
          if (s[j] === q) {
            j++;
            break;
          }
          j++;
        }
        out.push(`<span class="tok-str">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      if (/[0-9]/.test(s[i])) {
        let j = i + 1;
        while (j < s.length && /[\dw.xX]/.test(s[j])) j++;
        out.push(`<span class="tok-num">${escapeHtml(s.slice(i, j))}</span>`);
        i = j;
        continue;
      }
      if (/[A-Za-z_$]/.test(s[i])) {
        let j = i + 1;
        while (j < s.length && /[\w$]/.test(s[j])) j++;
        const word = s.slice(i, j);
        out.push(keywords.has(word)
          ? `<span class="tok-kw">${escapeHtml(word)}</span>`
          : escapeHtml(word));
        i = j;
        continue;
      }
      out.push(escapeHtml(s[i]));
      i++;
    }
    return out.join('');
  }

  function highlightCss(src) {
    return escapeHtml(src)
      .replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="tok-comment">$1</span>')
      .replace(/([.#]?[\w-]+)(\s*\{)/g, '<span class="tok-tag">$1</span>$2')
      .replace(/([\w-]+)(\s*:)/g, '<span class="tok-attr">$1</span>$2')
      .replace(/(:\s*)([^;{}]+)(;)/g, '$1<span class="tok-str">$2</span>$3');
  }

  function highlightForm(src) {
    return String(src)
      .split('&')
      .map((pair) => {
        const eq = pair.indexOf('=');
        if (eq < 0) return `<span class="tok-key">${escapeHtml(decodeURIComponentSafe(pair))}</span>`;
        const k = decodeURIComponentSafe(pair.slice(0, eq));
        const v = decodeURIComponentSafe(pair.slice(eq + 1));
        return `<span class="tok-key">${escapeHtml(k)}</span>=<span class="tok-str">${escapeHtml(v)}</span>`;
      })
      .join('<span class="tok-punc">&amp;</span>');
  }

  function decodeURIComponentSafe(s) {
    try {
      return decodeURIComponent(s.replace(/\+/g, ' '));
    } catch {
      return s;
    }
  }

  function highlightHeaders(text) {
    return String(text || '')
      .split(/\r?\n/)
      .map((line) => {
        const i = line.indexOf(':');
        if (i < 0) return escapeHtml(line);
        return `<span class="tok-key">${escapeHtml(line.slice(0, i))}</span><span class="tok-punc">:</span>${escapeHtml(line.slice(i + 1))}`;
      })
      .join('\n');
  }

  function highlightBody(body, contentType) {
    let text = body == null ? '' : String(body);
    if (!text) {
      return { html: escapeHtml('(empty body)'), lang: 'plain', pretty: false };
    }
    let highlightTruncated = false;
    if (text.length > MAX_HIGHLIGHT) {
      // Still color the leading window; do not drop highlighting entirely
      // (Wikipedia pages often land just over a small cap).
      text = text.slice(0, MAX_HIGHLIGHT);
      highlightTruncated = true;
    }
    let lang = detectLang(contentType, text);
    let pretty = false;
    let html;
    if (lang === 'json') {
      const prettyText = prettyJson(text);
      if (prettyText !== text) pretty = true;
      text = prettyText;
      if (text.length > MAX_HIGHLIGHT) {
        text = text.slice(0, MAX_HIGHLIGHT);
        highlightTruncated = true;
      }
      html = highlightJson(text);
    } else if (lang === 'html' || lang === 'xml') {
      html = highlightMarkup(text);
    } else if (lang === 'js') {
      html = highlightJs(text);
    } else if (lang === 'css') {
      html = highlightCss(text);
    } else if (lang === 'form') {
      html = highlightForm(text);
    } else {
      html = escapeHtml(text);
      lang = 'plain';
    }
    if (highlightTruncated) {
      html += `\n<span class="tok-comment">${escapeHtml('… [highlight truncated]')}</span>`;
    }
    return { html, lang, pretty };
  }

  return {
    escapeHtml,
    detectLang,
    highlightBody,
    highlightHeaders,
    highlightJson
  };
});
