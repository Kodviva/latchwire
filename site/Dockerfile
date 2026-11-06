# Latchwire static site — served by Caddy inside the container.
# TLS is terminated upstream (Cloudflare → edge01 Caddy); this listens on :80.
# The check stops the image when a translation is incomplete.
FROM node:lts-alpine AS build
WORKDIR /site
COPY . .
RUN node check.mjs && node build.mjs /dist

FROM caddy:2-alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build /dist/ /srv/
EXPOSE 80
