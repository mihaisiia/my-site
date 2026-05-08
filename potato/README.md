# edge-stack (potato)

Low-bandwidth auth gate for this stack. The UDR-7 forwards public
80/443 here. Every request that isn't `/auth/*` is bounced to the pi4 (on its
1 Gbps NIC) — the potato never moves bulk content. Unauthorized clients only
ever see the gate; the pi4 is invisible to them.

```
       your-public-domain.example  ─301─▶  your-host.example.org
       (registrar forwarder)                   │
                                               ▼
                                       ┌──────────────┐
                                       │   UDR-7      │
                                       │              │
                                       │  WAN  →  LAN │
                                       │  80   →  potato:80   (HTTP→HTTPS)
                                       │  443  →  potato:443  (gate)
                                       │  8443 →  pi4:8443    (content)
                                       └──────┬───────┘
                                              │
              ┌────────────────────────────┐  │  ┌────────────────────────┐
              │ potato (this stack)        │◀─┘─▶│ pi4                    │
              │  ┌─────────┐  ┌─────────┐  │     │  ┌─────────┐           │
   anon  ────▶│  │ Caddy   │→│ auth-svc │──┼─LAN┼─▶│ Caddy   │→ pi4-web   │
              │  │ :443    │  │  :8080  │  │     │  │ :8443   │→ mediasrv │
              │  └────┬────┘  └─────────┘  │     │  └─────────┘           │
              │       │ logs               │     └────────────────────────┘
              │  ┌────▼─────┐              │
              │  │ fail2ban │── UDR API ───┼─ pushes deny IPs into the
              │  └──────────┘              │   "edge-deny" firewall group
              └────────────────────────────┘
```

## Request flow

**First visit (no cookie):**
1. `GET https://your-host.example.org/blog/post-1` → potato Caddy.
2. Caddy `forward_auth` → auth-svc `/auth/check` with `X-Auth-Mode: bounce`.
3. auth-svc: no valid cookie → `302 Location: https://your-host.example.org/auth/login?next=/blog/post-1`.
4. Browser follows; Caddy serves `/auth/login` (whitelisted from the gate).
5. User submits a valid token → auth-svc sets the session cookie on
   `your-host.example.org` and `302`s to
   `https://your-host.example.org:8443/blog/post-1`.
6. Browser follows to pi4:8443 (cookie comes along — cookies don't isolate
   by port). Pi4 `forward_auth`s back to potato auth-svc with
   `X-Auth-Mode: gate`, cookie validates → 200, pi4 serves the page over
   1 Gbps.

**Returning user (valid cookie):**
1. `GET https://your-host.example.org/` → potato Caddy.
2. forward_auth → auth-svc → cookie valid + bounce mode → `302 https://your-host.example.org:8443/`.
3. Browser follows to pi4. From here on, every request stays on :8443 and
   the potato never sees it.

**API client (no cookie, non-HTML):**
- auth-svc returns `401` instead of `302`. fail2ban's filter catches the
  401 and escalates to a UDR firewall block after `maxretry`.

## One-time setup

### On the UDR-7

1. **Service account.** Settings → Admins → Add Admin. Limited Admin role
   with permission to edit firewall groups.
2. **Deny group.** Settings → Security → Firewall → Profiles → IP/Port Groups
   → Create. Type: IPv4 Address/Subnet. Name: `edge-deny`.
3. **Deny rule.** Settings → Security → Firewall → Internet → Create rule
   "Drop edge-deny" → Action: Drop, Source: `edge-deny`, Dest: Any.
   Pin it to the top of the chain.
4. **Find the group `_id`** from any LAN host:
   ```bash
   curl -k -c c.txt -H 'Content-Type: application/json' \
     -d '{"username":"edge-fail2ban","password":"...","remember":true}' \
     https://<UDR_HOST>/api/auth/login
   curl -k -b c.txt \
     https://<UDR_HOST>/proxy/network/api/s/default/rest/firewallgroup | jq
   ```
5. **Port-forwards** (verify all five):
   - `80/tcp`   → potato : 80
   - `443/tcp`  → potato : 443
   - `443/udp`  → potato : 443     (HTTP/3 for the gate)
   - `8443/tcp` → pi4    : 8443
   - `8443/udp` → pi4    : 8443    (HTTP/3 for content)

### DDNS + vanity domain

You should already have `your-host.example.org` updating to your WAN IP via
your DDNS provider, and `your-public-domain.example` configured at your
registrar as a 301 forward to it. Two sanity checks:
```bash
dig +short your-host.example.org             # expect your WAN IP
curl -sIL http://your-public-domain.example  # expect 301 → DDNS hostname
```
Then grab your DDNS provider API token from your provider's dashboard and
drop it into both `potato/.env` and `pi4/.env`.

### On the potato

1. Install Docker + the compose plugin if you haven't:
   ```bash
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker "$USER" && newgrp docker
   ```
2. Create the cross-host network. Driver choice depends on how your three
   nodes are linked. Examples:
   ```bash
   # Swarm:
   docker network create --driver=overlay --attachable edge-net
   # Plain bridge (single host only — won't span pi4/mediasrv):
   docker network create --driver=bridge edge-net
   ```
   If your nodes are linked via Tailscale or some non-Docker fabric, skip the
   Docker network and override `AUTH_UPSTREAM` in `pi4/.env` with the LAN
   address of the potato (e.g. `100.64.0.5:8081` if you also publish
   auth-svc's port to the host — see "Cross-host fallback" below).
3. Set up `.env`:
   ```bash
   cd potato
   cp .env.example .env
   chmod 600 .env
   echo "AUTH_SESSION_KEY=$(openssl rand -base64 48)"  >> /tmp/secrets
   echo "AUTH_ADMIN_TOKEN=$(openssl rand -base64 32)" >> /tmp/secrets
   $EDITOR .env   # paste the secrets above + DDNS_TOKEN + UDR_*
   ```
4. Bring it up:
   ```bash
   docker compose up -d --build
   docker compose logs -f caddy auth-svc
   ```
   Caddy will request a cert via DNS-01 within ~30s of starting.

### Cross-host fallback

If `edge-net` doesn't actually span all three hosts, expose auth-svc on the
potato's LAN IP and point the pi4 at it. Add this to the `auth-svc` service
in `potato/docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:8081:8080"   # then proxy via the host's WireGuard/Tailscale IP
```
…and on the pi4, set `AUTH_UPSTREAM=<potato-LAN-IP>:8081` in `pi4/.env`.

## Issuing a token

```bash
curl -sS -X POST https://your-host.example.org/auth/admin/tokens \
  -H "Authorization: Bearer ${AUTH_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"note":"alice laptop","ttl_days":30}' | jq
```

```json
{ "id": "Yb2k...", "token": "FQ8w-...-Tvc", "expires_at": "..." }
```

Send the `token` to the visitor over a private channel. They paste it into
`https://your-host.example.org/auth/login`, get bounced to
`:8443/`, and stay there for 30 days (cookie default).

### Connecting a media client (Jellyfin, etc.)

Native media clients can't follow the browser-form gate flow, so they use
HTTP Basic Auth as the machine-readable mode. The same site token that
unlocks the web gate doubles as the Basic-Auth password; the username
component is ignored.

**URL form** (works in browsers, the official Jellyfin iOS app v1.7+, JMP
desktop, and most Android clients):

```
https://anyuser:<site_token>@your-host.example.org:8443/media
```

Use this string verbatim in the client's "Add Server" field. The `:8443`
matters — it sends bytes straight to the pi4's 1 Gbps NIC and skips the
potato. Any username works; pick something memorable like `media`.

**Custom-header form** (for clients that strip URL userinfo):

Some clients (Swiftfin on iOS/tvOS, Findroid on Android) expose a
"Custom HTTP Headers" field in their server-edit screen. Server URL stays
plain `https://your-host.example.org:8443/media`, and you add one header:

```
Authorization: Basic <base64(anyuser:site_token)>
```

Generate the value with `printf 'anyuser:%s' "$TOKEN" | base64`.

**What happens on first contact:** auth-svc validates the Basic Auth, mints
a session, and `Set-Cookie`s `site_session` on the response. URLSession
(iOS/macOS) and most modern HTTP libraries store that cookie automatically.
On subsequent requests the client sends both the cookie and the Basic Auth
header — and once the user logs into Jellyfin and the client starts sending
`Authorization: MediaBrowser Token="..."` instead of Basic, the cookie
keeps flowing independently and the gate stays open. This sidesteps the
"Jellyfin's auth header replaces ours" problem.

**Failure modes worth knowing:**
- Wrong token → 401 on every request → after 5 misses in 15 min the IP is
  rate-limited (429) by auth-svc, and fail2ban escalates to a UDR firewall
  block.
- Client URL on `:443` instead of `:8443` → the gate 302s to `:8443` with
  the cookie set. Browsers handle this fine; some native clients don't
  follow cross-port redirects with credentials, so always configure with
  `:8443` explicitly.
- Client wipes its cookie jar between sessions → harmless: every fresh
  start re-bootstraps via Basic Auth on the first request.

### Revoking

```bash
curl -X DELETE https://your-host.example.org/auth/admin/tokens/<id> \
  -H "Authorization: Bearer ${AUTH_ADMIN_TOKEN}"
curl -X DELETE https://your-host.example.org/auth/admin/sessions/<id> \
  -H "Authorization: Bearer ${AUTH_ADMIN_TOKEN}"
```

## Verifying the firewall pipeline

```bash
docker compose exec fail2ban fail2ban-client status web-auth
docker compose logs -f fail2ban
```
Brute-force the gate from a non-LAN IP. After `maxretry` (5) bad submissions
in 15 minutes you should see `[web-auth] Ban 1.2.3.4` and the IP appearing
in the `edge-deny` group on the UDR-7.

## Operations

- **Reload Caddy:** `docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`
- **Tail access logs:** `docker compose exec caddy tail -f /var/log/caddy/access.log`
- **Backup:** the `auth_data` volume is your token + session DB. Snapshot it.
- **Rotate `AUTH_SESSION_KEY`:** logs everyone out (HMACs no longer verify);
  tokens stay valid.
- **Rotate `AUTH_ADMIN_TOKEN`:** doesn't affect existing sessions or tokens.

## What's still TODO outside this stack

- `pi4-web` container: the React + Hero UI app on `pi4-net:3000` (separate
  compose stack on the pi4 — not part of this gate).
- `mediasrv`: Jellyfin reachable on `edge-net:8096` with `BaseUrl=/media`.
- See `pi4/README.md` for the high-bandwidth side.
