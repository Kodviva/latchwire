import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from './build.mjs';
import { loadLanguages } from './lib/messages.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const config = loadLanguages(join(root, 'i18n'));
let out;
const page = (language) => readFileSync(join(out, language.path, 'index.html'), 'utf8');

before(() => {
  out = mkdtempSync(join(tmpdir(), 'site-'));
  build(out);
});
after(() => rmSync(out, { recursive: true, force: true }));

test('every language gets a page with the right lang', () => {
  assert.equal(config.languages.length, 10);
  for (const language of config.languages) {
    assert.match(page(language), new RegExp(`<html lang="${language.code}" dir="ltr">`));
  }
});

test('hreflang set is complete with x-default', () => {
  for (const language of config.languages) {
    const html = page(language);
    for (const other of config.languages) {
      assert.ok(html.includes(`hreflang="${other.code}" href="https://latchwire.com/${other.path}/"`), other.code);
    }
    assert.ok(html.includes('hreflang="x-default" href="https://latchwire.com/"'));
  }
});

test('canonical, og:url, og:image and og:locale are per language', () => {
  for (const language of config.languages) {
    const html = page(language);
    const url = `https://latchwire.com/${language.path}/`;
    assert.ok(html.includes(`<link rel="canonical" href="${url}">`));
    assert.ok(html.includes(`<meta property="og:url" content="${url}">`));
    assert.ok(html.includes(`<meta property="og:locale" content="${language.ogLocale}">`));
    assert.ok(html.includes(`content="https://latchwire.com/og/${language.path}.png"`));
  }
});

test('meta title and description are translated', () => {
  const titles = new Set();
  const descriptions = new Set();
  for (const language of config.languages) {
    const html = page(language);
    titles.add(html.match(/<title>(.*?)<\/title>/)[1]);
    descriptions.add(html.match(/<meta name="description" content="(.*?)">/)[1]);
  }
  assert.equal(titles.size, 10);
  assert.equal(descriptions.size, 10);
});

test('no unresolved template tokens', () => {
  for (const language of config.languages) {
    assert.doesNotMatch(page(language), /\{\{|\}\}|\{[a-zA-Z]+\}/);
  }
});

test('trademark note on every page', () => {
  for (const language of config.languages) {
    assert.ok(page(language).includes('Jason A. Donenfeld'), language.code);
  }
});

test('draft notice on draft pages only', () => {
  for (const language of config.languages) {
    assert.equal(page(language).includes('class="draft"'), language.status === 'draft', language.code);
  }
});

test('sitemap lists every language with alternates', () => {
  const xml = readFileSync(join(out, 'sitemap.xml'), 'utf8');
  for (const language of config.languages) {
    assert.ok(xml.includes(`<loc>https://latchwire.com/${language.path}/</loc>`));
  }
  assert.equal((xml.match(/<url>/g) ?? []).length, 10);
  assert.equal((xml.match(/hreflang="x-default"/g) ?? []).length, 10);
});

test('install commands are identical in all languages', () => {
  const blocks = (html) => [...html.matchAll(/<pre[^>]*><code>([\s\S]*?)<\/code><\/pre>/g)].map((m) => m[1]);
  const first = blocks(page(config.languages[0]));
  assert.equal(first.length, 3);
  for (const language of config.languages) assert.deepEqual(blocks(page(language)), first);
});

test('install commands promise no packages', () => {
  const html = page(config.languages[0]);
  const commands = [...html.matchAll(/<pre[^>]*><code>([\s\S]*?)<\/code><\/pre>/g)].map((m) => m[1]).join('\n');
  assert.doesNotMatch(commands, /brew|apt|dnf|yum|winget|curl|\.deb|\.rpm/);
});

test('no third-party resources', () => {
  for (const language of config.languages) {
    const html = page(language);
    for (const m of html.matchAll(/<(?:script|link|img)[^>]*(?:src|href)="(https?:[^"]+)"/g)) {
      assert.ok(m[1].startsWith('https://latchwire.com/'), m[1]);
    }
  }
});
