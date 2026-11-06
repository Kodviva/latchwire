// Generates the static site: one page per language, the sitemap and the
// root and 404 pages. Run: node build.mjs [outDir]. No dependencies.
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { format, loadLanguages, loadMessages } from './lib/messages.mjs';

const root = dirname(fileURLToPath(import.meta.url));

function attr(text) {
  return text.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
}

function hreflangLinks(config) {
  const lines = config.languages.map(
    (l) => `<link rel="alternate" hreflang="${l.code}" href="${config.origin}/${l.path}/">`,
  );
  lines.push(`<link rel="alternate" hreflang="x-default" href="${config.origin}/">`);
  return lines.join('\n');
}

function languageLinks(config, current) {
  return config.languages
    .map((l) => {
      const here = l.code === current.code ? ' aria-current="true"' : '';
      return `<li><a href="/${l.path}/" hreflang="${l.code}" lang="${l.code}"${here}>${l.endonym}</a></li>`;
    })
    .join('');
}

function ogAlternates(config, current) {
  return config.languages
    .filter((l) => l.code !== current.code)
    .map((l) => `<meta property="og:locale:alternate" content="${l.ogLocale}">`)
    .join('\n');
}

function draftNotice(language, messages, vars) {
  if (language.status !== 'draft') return '';
  const note = format(messages['draft.note'], vars);
  const link = format(messages['draft.link'], vars);
  return `<aside class="draft"><div class="wrap">${note} <a href="/en/" hreflang="en">${link}</a></div></aside>`;
}

function render(template, language, config, messages, assets, used) {
  const url = `${config.origin}/${language.path}/`;
  const values = {
    lang: language.code,
    url,
    ogLocale: language.ogLocale,
    ogAlternates: ogAlternates(config, language),
    ogImage: `${config.origin}/og/${language.path}.png`,
    hreflang: hreflangLinks(config),
    endonym: language.endonym,
    languages: languageLinks(config, language),
    draft: draftNotice(language, messages, config.vars),
    css: assets.css,
    js: assets.js,
    home: `/${language.path}/`,
  };
  used.add('draft.note');
  used.add('draft.link');
  used.add('e404.title');
  used.add('og.line');
  return template.replace(/\{\{(@?)([A-Za-z0-9.]+)\}\}/g, (_, computed, name) => {
    if (computed) {
      if (!(name in values)) throw new Error(`unknown template value @${name}`);
      return values[name];
    }
    if (!(name in messages)) throw new Error(`${language.code}: template uses unknown key ${name}`);
    used.add(name);
    return format(messages[name], config.vars);
  });
}

function sitemap(config) {
  const alternates = [
    ...config.languages.map((l) => [l.code, `${config.origin}/${l.path}/`]),
    ['x-default', `${config.origin}/`],
  ]
    .map(([code, href]) => `    <xhtml:link rel="alternate" hreflang="${code}" href="${href}"/>`)
    .join('\n');
  const urls = config.languages
    .map((l) => `  <url>\n    <loc>${config.origin}/${l.path}/</loc>\n${alternates}\n  </url>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${urls}\n</urlset>\n`;
}

// Caddy answers / with a language redirect. This page is the same fallback
// for any other static server.
function rootPage(config, source) {
  return `<!DOCTYPE html>
<html lang="${source}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Latchwire</title>
<meta http-equiv="refresh" content="0; url=/${source}/">
<link rel="canonical" href="${config.origin}/${source}/">
</head>
<body><a href="/${source}/">Latchwire</a></body>
</html>
`;
}

function notFoundPage(config, allMessages, assets) {
  const items = config.languages
    .map((l) => {
      const title = attr(allMessages[l.code]['e404.title']);
      return `<li><a href="/${l.path}/" hreflang="${l.code}" lang="${l.code}">${l.endonym}</a> <span lang="${l.code}">${title}</span></li>`;
    })
    .join('\n');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Latchwire: 404</title>
<meta name="robots" content="noindex">
<meta name="color-scheme" content="dark">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="${assets.css}">
</head>
<body>
<main class="wrap notfound">
<h1>404</h1>
<ul>
${items}
</ul>
</main>
</body>
</html>
`;
}

function asset(name, body) {
  const hash = createHash('sha256').update(body).digest('hex').slice(0, 10);
  return `/${name}?v=${hash}`;
}

export function build(outDir) {
  const i18n = join(root, 'i18n');
  const config = loadLanguages(i18n);
  const template = readFileSync(join(root, 'src', 'page.html'), 'utf8');
  const css = readFileSync(join(root, 'src', 'site.css'));
  const js = readFileSync(join(root, 'src', 'site.js'));
  const assets = { css: asset('site.css', css), js: asset('site.js', js) };

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  cpSync(join(root, 'public'), outDir, { recursive: true });
  writeFileSync(join(outDir, 'site.css'), css);
  writeFileSync(join(outDir, 'site.js'), js);

  const allMessages = {};
  const used = new Set();
  for (const language of config.languages) {
    const messages = loadMessages(i18n, language.code);
    allMessages[language.code] = messages;
    const dir = join(outDir, language.path);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'index.html'), render(template, language, config, messages, assets, used));
  }

  const unused = Object.keys(allMessages[config.source]).filter((key) => !used.has(key));
  if (unused.length > 0) throw new Error(`keys not used by the template: ${unused.join(', ')}`);

  writeFileSync(join(outDir, 'index.html'), rootPage(config, config.source));
  writeFileSync(join(outDir, '404.html'), notFoundPage(config, allMessages, assets));
  writeFileSync(join(outDir, 'sitemap.xml'), sitemap(config));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const outDir = process.argv[2] ?? join(root, 'dist');
  build(outDir);
  console.log(`built ${outDir}`);
}
