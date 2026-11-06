// Reads the translation source and formats its messages. The files in
// i18n/ are flat JSON (key to ICU MessageFormat text), so the desktop app can
// load the same files with any ICU library. The site uses only the subset
// below: {name} placeholders and <code> tags.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ALLOWED_TAGS = new Set(['code']);
const PLACEHOLDER = /\{([A-Za-z][A-Za-z0-9]*)\}/g;
const TAG = /<\/?([A-Za-z][A-Za-z0-9]*)>/g;

export function loadLanguages(dir) {
  return JSON.parse(readFileSync(join(dir, 'languages.json'), 'utf8'));
}

export function loadMessages(dir, code) {
  return JSON.parse(readFileSync(join(dir, `${code}.json`), 'utf8'));
}

export function tokens(message) {
  const placeholders = new Set([...message.matchAll(PLACEHOLDER)].map((m) => m[1]));
  const tags = [...message.matchAll(TAG)].map((m) => m[0]).sort();
  return { placeholders, tags };
}

function escapeHTML(text) {
  return text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

// format returns HTML. Everything is escaped except the allowed tags, so a
// translation cannot inject markup. A placeholder without a value throws.
export function format(message, vars = {}) {
  const parts = message.split(/(<\/?[A-Za-z][A-Za-z0-9]*>)/);
  const html = parts.map((part, i) => {
    if (i % 2 === 0) return escapeHTML(part);
    const name = part.replace(/[</>]/g, '');
    if (!ALLOWED_TAGS.has(name)) throw new Error(`tag not allowed: ${part}`);
    return part;
  }).join('');
  return html.replace(PLACEHOLDER, (_, name) => {
    if (!(name in vars)) throw new Error(`no value for placeholder {${name}}`);
    return escapeHTML(String(vars[name]));
  });
}

// validate compares a translation with the source and returns one line per
// problem. An empty list means the translation is complete.
export function validate(source, target, code) {
  const errors = [];
  for (const key of Object.keys(source)) {
    if (!(key in target)) {
      errors.push(`${code}: ${key}: missing`);
      continue;
    }
    const value = target[key];
    if (typeof value !== 'string' || value.trim() === '') {
      errors.push(`${code}: ${key}: empty`);
      continue;
    }
    const want = tokens(source[key]);
    const got = tokens(value);
    if ([...want.placeholders].sort().join() !== [...got.placeholders].sort().join()) {
      errors.push(`${code}: ${key}: placeholders differ from source`);
    }
    if (want.tags.join() !== got.tags.join()) {
      errors.push(`${code}: ${key}: tags differ from source`);
    }
  }
  for (const key of Object.keys(target)) {
    if (!(key in source)) errors.push(`${code}: ${key}: not in source`);
  }
  return errors;
}
