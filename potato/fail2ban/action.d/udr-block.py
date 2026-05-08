#!/usr/bin/env python3
"""
udr-block: add/remove an IP from a UniFi firewall address group on the UDR-7.

Called by fail2ban's udr-block action. Uses Python stdlib only (urllib +
ssl), so it runs unmodified inside crazymax/fail2ban.

The UDR-7 runs UniFi OS, so the auth flow goes:
    POST /api/auth/login              -> session cookie + X-CSRF-Token header
    GET  /proxy/network/api/s/<site>/rest/firewallgroup/<id>
    PUT  /proxy/network/api/s/<site>/rest/firewallgroup/<id>  (with new members)

We don't verify the controller cert by default because UDR-7 ships a
self-signed one. Set UDR_VERIFY_TLS=true (and provide a CA bundle via
SSL_CERT_FILE) if you've installed a proper cert.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar


def env(name: str, default: str | None = None, *, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        print(f"udr-block: missing required env {name}", file=sys.stderr)
        sys.exit(2)
    return val or ""


def make_opener(verify_tls: bool) -> tuple[urllib.request.OpenerDirector, CookieJar]:
    cj = CookieJar()
    handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPCookieProcessor(cj)]
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    return opener, cj


def login(opener, host: str, user: str, password: str) -> str:
    body = json.dumps({"username": user, "password": password, "remember": True}).encode()
    req = urllib.request.Request(
        f"https://{host}/api/auth/login",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with opener.open(req, timeout=10) as resp:
        # UniFi OS hands back the CSRF token in a response header; we need it
        # for any state-changing call.
        csrf = resp.headers.get("X-CSRF-Token") or resp.headers.get("X-Updated-CSRF-Token") or ""
        resp.read()
    if not csrf:
        raise RuntimeError("UDR login succeeded but no X-CSRF-Token in response")
    return csrf


def get_group(opener, host: str, site: str, group_id: str, csrf: str) -> dict:
    req = urllib.request.Request(
        f"https://{host}/proxy/network/api/s/{site}/rest/firewallgroup/{group_id}",
        method="GET",
        headers={"Accept": "application/json", "X-CSRF-Token": csrf},
    )
    with opener.open(req, timeout=10) as resp:
        payload = json.loads(resp.read())
    data = payload.get("data") or []
    if not data:
        raise RuntimeError(f"firewall group {group_id} not found on site {site}")
    return data[0]


def put_group(opener, host: str, site: str, group: dict, csrf: str) -> None:
    body = json.dumps(group).encode()
    req = urllib.request.Request(
        f"https://{host}/proxy/network/api/s/{site}/rest/firewallgroup/{group['_id']}",
        data=body,
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": csrf,
        },
    )
    with opener.open(req, timeout=10) as resp:
        resp.read()


def normalize_member(ip: str) -> str:
    # UniFi accepts a bare IP; if you pass a subnet, leave it alone.
    return ip.strip()


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("ban", "unban"):
        print("usage: udr-block.py {ban|unban} <ip>", file=sys.stderr)
        return 2
    action, ip = sys.argv[1], normalize_member(sys.argv[2])

    host = env("UDR_HOST", required=True)
    user = env("UDR_USER", required=True)
    password = env("UDR_PASS", required=True)
    site = env("UDR_SITE", "default")
    group_id = env("UDR_GROUP_ID", required=True)
    verify_tls = env("UDR_VERIFY_TLS", "false").lower() == "true"

    opener, _ = make_opener(verify_tls=verify_tls)

    try:
        csrf = login(opener, host, user, password)
        group = get_group(opener, host, site, group_id, csrf)
        members = list(group.get("group_members") or [])
        changed = False
        if action == "ban" and ip not in members:
            members.append(ip)
            changed = True
        elif action == "unban" and ip in members:
            members = [m for m in members if m != ip]
            changed = True
        if not changed:
            print(f"udr-block: {action} {ip}: no-op (already in desired state)")
            return 0
        # UniFi refuses payloads with unknown fields; trim to the editable set.
        payload = {
            "_id": group["_id"],
            "name": group["name"],
            "group_type": group["group_type"],
            "group_members": members,
            "site_id": group.get("site_id"),
        }
        # Drop None values — site_id sometimes isn't in the response.
        payload = {k: v for k, v in payload.items() if v is not None}
        put_group(opener, host, site, payload, csrf)
        print(f"udr-block: {action} {ip} ok ({len(members)} members)")
        return 0
    except urllib.error.HTTPError as e:
        print(f"udr-block: {action} {ip} HTTP {e.code}: {e.read()!r}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"udr-block: {action} {ip} failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
