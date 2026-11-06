import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { format, tokens, validate } from './lib/messages.mjs';
import { checkAll } from './check.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const source = { a: 'Go {go}+', b: 'use <code>pcscd</code>', c: 'plain' };
const good = { a: 'Go {go}+ tr', b: '<code>pcscd</code> tr', c: 'düz' };

test('complete translation passes', () => {
  assert.deepEqual(validate(source, good, 'xx'), []);
});

test('missing key fails', () => {
  const { c, ...rest } = good;
  assert.deepEqual(validate(source, rest, 'xx'), ['xx: c: missing']);
});

test('extra key fails', () => {
  assert.deepEqual(validate(source, { ...good, d: 'x' }, 'xx'), ['xx: d: not in source']);
});

test('empty value fails', () => {
  assert.deepEqual(validate(source, { ...good, c: '  ' }, 'xx'), ['xx: c: empty']);
});

test('placeholder mismatch fails', () => {
  assert.deepEqual(validate(source, { ...good, a: 'Go {versio}+' }, 'xx'), ['xx: a: placeholders differ from source']);
});

test('tag mismatch fails', () => {
  assert.deepEqual(validate(source, { ...good, b: 'pcscd' }, 'xx'), ['xx: b: tags differ from source']);
});

test('format escapes html', () => {
  assert.equal(format('a < b & "c"'), 'a &lt; b &amp; &quot;c&quot;');
});

test('format keeps code tag', () => {
  assert.equal(format('use <code>pcscd</code>'), 'use <code>pcscd</code>');
});

test('format refuses other tags', () => {
  assert.throws(() => format('<script>x</script>'), /tag not allowed/);
});

test('unknown placeholder throws', () => {
  assert.throws(() => format('{nope}', {}), /no value for placeholder/);
});

test('format fills placeholders', () => {
  assert.equal(format('Go {go}+', { go: '1.25' }), 'Go 1.25+');
});

test('tokens lists placeholders and tags', () => {
  const t = tokens('{a} <code>x</code>');
  assert.deepEqual([...t.placeholders], ['a']);
  assert.deepEqual(t.tags, ['</code>', '<code>']);
});

function withCopy(run) {
  const dir = mkdtempSync(join(tmpdir(), 'i18n-'));
  try {
    cpSync(join(root, 'i18n'), dir, { recursive: true });
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('real translations are complete', () => {
  assert.deepEqual(checkAll(join(root, 'i18n'), join(root, 'public')), []);
});

test('deleting a real key fails the check', () => {
  withCopy((dir) => {
    const file = join(dir, 'ko.json');
    const messages = JSON.parse(readFileSync(file, 'utf8'));
    delete messages['hero.h1'];
    writeFileSync(file, JSON.stringify(messages));
    assert.deepEqual(checkAll(dir), ['ko: hero.h1: missing']);
  });
});

test('dropping the trademark holder fails the check', () => {
  withCopy((dir) => {
    const file = join(dir, 'de.json');
    const messages = JSON.parse(readFileSync(file, 'utf8'));
    messages['foot.tm'] = 'WireGuard ist eine Marke.';
    writeFileSync(file, JSON.stringify(messages));
    assert.deepEqual(checkAll(dir), ['de: foot.tm: must name Jason A. Donenfeld']);
  });
});
