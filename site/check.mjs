// Fails when a translation is incomplete or a required note is missing.
// Run: node check.mjs. The Docker build runs it, so a gap stops the image.
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadLanguages, loadMessages, validate } from './lib/messages.mjs';

export function checkAll(i18nDir, publicDir) {
  const config = loadLanguages(i18nDir);
  const source = loadMessages(i18nDir, config.source);
  const errors = [];
  for (const language of config.languages) {
    if (!existsSync(join(i18nDir, `${language.code}.json`))) {
      errors.push(`${language.code}: translation file missing`);
      continue;
    }
    const messages = loadMessages(i18nDir, language.code);
    errors.push(...validate(source, messages, language.code));
    // The trademark note is a legal requirement, so its names must survive.
    const note = messages['foot.tm'] ?? '';
    for (const name of ['WireGuard', 'Jason A. Donenfeld']) {
      if (!note.includes(name)) errors.push(`${language.code}: foot.tm: must name ${name}`);
    }
    if (!(messages['hero.eyebrow'] ?? '').includes('WireGuard®')) {
      errors.push(`${language.code}: hero.eyebrow: must say WireGuard®`);
    }
    if (publicDir && !existsSync(join(publicDir, 'og', `${language.path}.png`))) {
      errors.push(`${language.code}: public/og/${language.path}.png missing`);
    }
  }
  return errors;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = dirname(fileURLToPath(import.meta.url));
  const errors = checkAll(join(root, 'i18n'), join(root, 'public'));
  for (const line of errors) console.error(line);
  if (errors.length > 0) {
    console.error(`check failed: ${errors.length} problem(s)`);
    process.exit(1);
  }
  console.log('translations complete');
}
