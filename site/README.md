# latchwire.com

Static site in 10 languages. Nothing here runs on a server except Caddy.

    node check.mjs         # fails on a missing, extra or broken translation
    node --test .          # tests for the check and the generator
    node build.mjs         # writes dist/
    docker build -t latchwire-site .   # runs the check, then builds

`src/page.html` is the template, `{{key}}` is a translated string and `{{@name}}`
is a value from `build.mjs`. A key that the template does not use fails the build.

## Translations

`i18n/en.json` is the source. Every other file has the same keys. The files are
flat JSON with ICU MessageFormat text, so the desktop app can load them too. The
site uses `{name}` placeholders (values in `i18n/languages.json`) and `<code>`
tags; both must match the source.

- Keep `WireGuard®` in `hero.eyebrow` and the trademark note in `foot.tm`.
- Never write a claim stronger than the English text.
- In Japanese and Chinese, `hero.h1` holds U+200B where the line may break.
- `status` in `languages.json` is `draft` until a person has reviewed the file.
  Draft pages show a notice. Set it to `reviewed` to remove the notice.
- After changing `hero.h1` or `og.line`, run `python3 tools/og.py` to redraw
  `public/og/*.png` (needs Playwright and Google Chrome). The images are committed.

To add a language: add it to `languages.json`, add its file, run `tools/og.py`,
then extend the `map` in `Caddyfile`.
