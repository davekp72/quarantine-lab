/**
 * Lightweight syntax highlighting for HTTP request/response bodies.
 * No external deps — safe for offline Wails builds.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.QuarantineHighlight = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : window, function () {
  'use strict';

  const MAX_HIGHLIGHT = 200000;

  function escapeHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function detectLang(contentType, body) {
    const ct = String(contentType || '').toLowerCase();
    const text = String(body || '').trim();
    if (ct.includes('json') || ct.includes('+json')) return 'json';
    if (ct.includes('html')) return 'html';
    if (ct.includes('xml') || ct.includes('svg')) return 'xml';
    if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
    if (ct.includes('css')) return 'css';
    if (ct.includes('x-www-form-urlencoded')) return 'form';
    if (ct.includes('text/plain') || ct.includes('text/')) {
      if (text.startsWith('{') || text.startsWith('[')) return 'json';
      if (text.startsWith('<')) return text.toLowerCase().includes('<!doctype html') || /<html[\s>]/i.test(text) ? 'html' : 'xml';
    }
    if (!ct) {
      if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) return 'json';
      if (text.startsWith('<')) return 'html';
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
    return escapeHtml(src)
      .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="tok-comment">$1</span>')
      .replace(/(&lt;\/?)([\w:.-]+)([^&]*?)(\/?&gt;)/g, (_, open, name, rest, close) => {
        const attrs = rest.replace(
          /([\w:.-]+)(=)(&quot;[\s\S]*?&quot;|&#39;[\s\S]*?&#39;|[^\s&]+)/g,
          '<span class="tok-attr">$1</span>$2<span class="tok-str">$3</span>'
        );
        return `${open}<span class="tok-tag">${name}</span>${attrs}${close}`;
      });
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
    if (text.length > MAX_HIGHLIGHT) {
      return { html: escapeHtml(text), lang: 'plain', pretty: false };
    }
    let lang = detectLang(contentType, text);
    let pretty = false;
    if (lang === 'json') {
      const prettyText = prettyJson(text);
      if (prettyText !== text) pretty = true;
      text = prettyText;
      return { html: highlightJson(text), lang, pretty };
    }
    if (lang === 'html' || lang === 'xml') {
      return { html: highlightMarkup(text), lang, pretty };
    }
    if (lang === 'js') {
      return { html: highlightJs(text), lang, pretty };
    }
    if (lang === 'css') {
      return { html: highlightCss(text), lang, pretty };
    }
    if (lang === 'form') {
      return { html: highlightForm(text), lang, pretty };
    }
    return { html: escapeHtml(text), lang: 'plain', pretty: false };
  }

  return {
    escapeHtml,
    detectLang,
    highlightBody,
    highlightHeaders,
    highlightJson
  };
});
