# Same custom Caddy build as the potato (xcaddy + a caddy-dns/* DDNS plugin).
# Kept as a sibling Dockerfile rather than a shared parent so each host can
# `docker compose build` standalone — Portainer-managed edge agents don't
# always share a build context.
#
# The DDNS provider plugin is configurable via build arg. Default mirrors what
# the Caddyfile expects; swap both together if you change DDNS providers.
ARG CADDY_DNS_PLUGIN=github.com/caddy-dns/duckdns

FROM caddy:2.8-builder-alpine AS builder
ARG CADDY_DNS_PLUGIN
RUN xcaddy build \
    --with ${CADDY_DNS_PLUGIN}

FROM caddy:2.8-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
