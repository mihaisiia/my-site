# pi4-web

Fastify API + React/HeroUI SPA, served from a single container behind the
pi4 Caddy. By the time a request hits this container it has already cleared
the auth-svc forward_auth gate, so the app trusts the `X-Auth-User` and
`X-Auth-Token-Id` headers Caddy sets — and verifies the request came from a
trusted proxy CIDR before it does.

```
[client] --> pi4 Caddy --(forward_auth)--> auth-svc (200/302)
                |
                +-(on 200)--> pi4-web:3000
                                  ├── GET /            -> SPA (React + HeroUI)
                                  ├── GET /api/me      -> identity
                                  ├── GET /api/posts   -> blog
                                  ├── POST /api/uploads (multipart)
                                  └── GET /api/admin/* -> owner-only
```

## Privacy model

Token IDs are the stable per-user identifier. The pi4-web app never reveals
*other* users to a normal viewer:

- `GET /api/posts` returns posts by the owner only. The displayed author is a
  generic name (`OWNER_DISPLAY_NAME`, defaults to `host`).
- `GET /api/uploads` returns only the caller's own uploads. There is no
  endpoint that lists user IDs or other users' uploads to non-owners.
- The owner gets `GET /api/admin/uploads` which returns every upload with
  uploader token IDs. This is the only path that crosses user boundaries.

A user reading the site cannot tell whether 1 or 100 other people have
accounts. They see only their own files and the owner's blog.

## Quota

Each user has `PER_USER_QUOTA_BYTES` of upload storage (default 5 GiB).
Enforced two ways:

1. **Pre-check** on upload: `Content-Length` plus the user's current usage
   must fit under the cap; otherwise the request is rejected with `413` before
   any bytes hit disk.
2. **Rolling check** during stream: every 4 MiB the rolling total is
   re-checked against the cap; if exceeded the in-progress upload is aborted
   and its temp file is deleted.

The DB is the source of truth for usage. A periodic reconcile sums actual
file sizes on disk and corrects the DB if it has drifted (e.g. after a crash
mid-upload).

## Bring it up

```bash
cd pi4/web
cp .env.example .env
chmod 600 .env

# Set OWNER_TOKEN_ID to the id from auth-svc when you minted your owner
# token. Example:
#   curl -X POST -H "Authorization: Bearer $AUTH_ADMIN_TOKEN" \
#        -H 'Content-Type: application/json' \
#        -d '{"note":"me","ttl_days":3650}' \
#        https://your-host.example.org/auth/admin/tokens
# The response has {"id":"...","token":"..."}. The id is OWNER_TOKEN_ID.

$EDITOR .env
mkdir -p uploads
docker compose up -d --build
docker compose logs -f pi4-web
```

## Verifying

```bash
# From the pi4 host (loopback CIDR is trusted):
docker exec pi4-web wget -qO- http://127.0.0.1:3000/api/healthz

# End-to-end from a browser: log in via the potato auth-svc, you'll be
# redirected to https://${HOSTNAME}:8443/ and see the SPA. The /files page
# shows your own uploads; the /admin page is only visible to the owner token.
```

## Backup

Two things to back up:

- `web_data` volume — `posts` and `uploads` metadata in `app.db`
- `./uploads/` bind mount — the actual file blobs

Both are owned by uid 10001 inside the container.
