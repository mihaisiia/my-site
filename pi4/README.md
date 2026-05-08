# web-stack (high-bandwidth content)

The pi4's role in this stack is to serve content fast (1 Gbps NIC) to
already-authorized users. It never sees an unauthorized request: every hit is
gated against the potato's auth-svc over the edge-net LAN before Caddy
proxies anything local.

```
authorized client ──HTTPS:8443──▶ pi4 Caddy
                                   │
                       forward_auth│ X-Auth-Mode: gate
                          (LAN)    ▼
                                potato auth-svc  → 200 / 302
                                   │
                            on 200 │
                                   ▼
                            ┌──────────────┐
                       /    │ pi4-web      │  React + Hero UI
                  /media/*  │ mediasrv     │  Jellyfin (BaseUrl=/media)
                            └──────────────┘
```

## Prereqs

- The potato stack is up and `auth-svc` is reachable on `edge-net` with the
  alias `auth-svc:8080` (the potato compose file sets that alias).
- Your DDNS provider token works — try `dig your-host.example.org` and
  confirm it resolves to your WAN IP.
- The `edge-net` network already exists on the pi4 (created by whatever
  cross-host driver you've chosen — overlay, Tailscale, etc.).
- UDR-7 has the new forward:
  - `8443/tcp` → pi4 LAN IP : 8443
  - `8443/udp` → pi4 LAN IP : 8443   (HTTP/3)
  - Leave 80/443 forwarded to the potato.

## Bring it up

```bash
cd pi4
cp .env.example .env
chmod 600 .env
$EDITOR .env   # set DDNS_TOKEN, ACME_EMAIL, leave HOSTNAME as-is

docker compose up -d --build
docker compose logs -f caddy
```

You should see Caddy obtain a cert via DNS-01:
```
{"level":"info","msg":"certificate obtained successfully","identifier":"your-host.example.org"}
```

## Where the web app lives

Caddy reverse-proxies `/` → `${WEB_UPSTREAM}` (default `pi4-web:3000`) and
`/media/*` → `${MEDIASRV_UPSTREAM}` (default `mediasrv:8096`).

When you ship the React + Hero UI app, run it as a separate compose stack on
the pi4 with `networks: [pi4-net]` and a service named `pi4-web` listening on
`:3000`. Same idea for Jellyfin: ensure `mediasrv` is resolvable on
`edge-net` (or wherever you point `MEDIASRV_UPSTREAM`).

## Verifying end-to-end

1. From a non-LAN device with no cookie, visit
   `https://your-host.example.org:8443/`.
2. Pi4 Caddy `forward_auth`s → potato auth-svc returns
   `302 Location: https://your-host.example.org/auth/login?next=/`.
3. Browser follows to potato:443, you get the login form.
4. Submit a valid token → potato auth-svc sets the cookie and 302s to
   `https://your-host.example.org:8443/`.
5. Pi4 forward_auths again — this time cookie is valid → 200, content served.

## Operations

- **Reload Caddy** after edits: `docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`.
- **Cert renewal** is automatic via DNS-01 every ~60 days.
- The pi4 has no persistent auth state — wiping `caddy_data` only clears the
  cert cache; sessions live entirely on the potato.
