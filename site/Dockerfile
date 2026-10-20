# Latchwire static site — served by Caddy inside the container.
# TLS is terminated upstream (Cloudflare → edge01 Caddy); this listens on :80.
FROM caddy:2.10-alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY index.html favicon.svg og.png og.svg robots.txt sitemap.xml /srv/
EXPOSE 80
