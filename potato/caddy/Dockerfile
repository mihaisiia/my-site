# Custom Caddy build with a caddy-dns/* DNS-01 plugin baked in. Used by both
# the potato and pi4 stacks (the pi4 imports this image via
# `image: local/edge-caddy:latest`, or you can
# `docker build -f potato/caddy/Dockerfile -t local/edge-caddy:latest potato/caddy`
# once and reference it from both compose files).
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
