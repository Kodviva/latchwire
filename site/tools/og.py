#!/usr/bin/env python3
"""Renders public/og/<path>.png for each language. Run after changing hero.h1
or og.line: python3 tools/og.py. Needs Playwright and Google Chrome. The images are
committed, so the Docker build does not need a browser."""
import html
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PAGE = """<!doctype html><html lang="{lang}"><meta charset="utf-8"><style>
html,body{{margin:0;width:1200px;height:630px;background:#0a0e16;color:#e8edf4;overflow:hidden}}
body{{box-sizing:border-box;padding:84px 88px 0;border-bottom:8px solid #e8a13a;display:flex;flex-direction:column;
 background:radial-gradient(900px 500px at 88% 8%,rgba(232,161,58,.16),transparent),#0a0e16;
 font-family:-apple-system,"Hiragino Sans","PingFang SC","Apple SD Gothic Neo",sans-serif}}
html:lang(zh) body{{font-family:-apple-system,"PingFang SC",sans-serif}}
html:lang(ja) body{{font-family:-apple-system,"Hiragino Sans",sans-serif}}
html:lang(ko) body{{font-family:-apple-system,"Apple SD Gothic Neo",sans-serif}}
.b{{display:flex;align-items:center;gap:18px;font-size:50px;font-weight:700}}
svg{{width:76px;height:76px;color:#e8a13a}}
h1{{font-size:{size}px;line-height:1.12;margin:auto 0 26px;font-weight:700;word-break:keep-all;text-wrap:balance}}
p{{font-size:29px;color:#a3afc2;margin:0 0 76px;line-height:1.3}}
</style><div class="b"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="12" r="4.5"/><circle cx="7.5" cy="12" r="1.2"/><path d="M12 12h9.5M18.5 12v3.5M21.5 12v2.5"/></svg>Latchwire</div>
<h1>{title}</h1><p>{line}</p></html>"""


def main():
    config = json.loads((ROOT / "i18n/languages.json").read_text())
    out = ROOT / "public/og"
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(viewport={"width": 1200, "height": 630})
        for language in config["languages"]:
            messages = json.loads((ROOT / f"i18n/{language['code']}.json").read_text())
            title = messages["hero.h1"]
            page.set_content(PAGE.format(
                lang=language["code"],
                size=76 if len(title) < 42 else 66,
                title=html.escape(title),
                line=html.escape(messages["og.line"]),
            ))
            page.screenshot(path=str(out / f"{language['path']}.png"))
        browser.close()


if __name__ == "__main__":
    main()
