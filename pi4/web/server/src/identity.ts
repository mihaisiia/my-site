// Identity middleware. Two gates run before any handler sees the request:
//
//   1. The TCP peer (request.ip after fastify trustProxy) MUST be in
//      TRUSTED_PROXY_CIDRS. We assume the only thing on pi4-net that should
//      be talking to us is Caddy — anything else is rejected.
//   2. X-Auth-User and X-Auth-Token-Id MUST be present on /api/* calls.
//      Caddy sets these via forward_auth + copy_headers; missing means the
//      request didn't come through the gate.
//
// The token id is the *stable* per-user identifier (a token can mint many
// sessions). Cross-user state — uploads, posts — is keyed on token id.

import type { FastifyInstance, FastifyRequest } from "fastify";

import type { Config } from "./config.js";
import { isTrusted } from "./config.js";

declare module "fastify" {
  interface FastifyRequest {
    identity?: Identity;
  }
}

export interface Identity {
  // X-Auth-Token-Id from forward_auth. Stable per user; this is what we key
  // ownership on (uploads.owner_token_id, owner-only access).
  tokenId: string;
  // X-Auth-User from forward_auth. Rotates per session — useful only for
  // logout/audit. We never expose this to anyone.
  sessionId: string;
  // True if tokenId === OWNER_TOKEN_ID. Owner sees everything; everyone else
  // sees only their own data + the owner's published posts.
  isOwner: boolean;
}

export function registerIdentity(app: FastifyInstance, cfg: Config): void {
  app.addHook("onRequest", async (request, reply) => {
    // /api/healthz is the only path that should bypass auth — used by
    // the docker healthcheck which sits on loopback inside the container.
    if (request.url === "/api/healthz") return;

    const peer = request.ip;
    if (!isTrusted(peer, cfg.trustedCidrs)) {
      request.log.warn({ peer, url: request.url }, "rejecting untrusted peer");
      reply.code(403).send({ error: "forbidden" });
      return reply;
    }

    // The SPA shell (/, /index.html, /assets/*) can be served unauthenticated
    // because, in practice, the Caddy in front of us already did forward_auth
    // for any /-prefixed request — and the SPA does nothing on its own
    // without /api calls, which we *do* require auth headers on.
    if (request.url.startsWith("/api/")) {
      const tokenId = headerOne(request, "x-auth-token-id");
      const sessionId = headerOne(request, "x-auth-user");
      if (!tokenId || !sessionId) {
        request.log.warn(
          { peer, url: request.url },
          "missing auth headers on /api/ request",
        );
        reply.code(401).send({ error: "unauthenticated" });
        return reply;
      }
      request.identity = {
        tokenId,
        sessionId,
        isOwner: tokenId === cfg.ownerTokenId,
      };
    }
  });
}

function headerOne(req: FastifyRequest, name: string): string | null {
  const v = req.headers[name];
  if (Array.isArray(v)) return v[0] ?? null;
  if (typeof v === "string" && v.length > 0) return v;
  return null;
}

// Helper used by routes to bail when the caller isn't the owner.
export function requireOwner(request: FastifyRequest): boolean {
  return request.identity?.isOwner === true;
}
