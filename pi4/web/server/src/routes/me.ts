// /api/me returns just enough for the SPA to render correctly: are we owner
// or not, what's our quota look like, what's the owner's display name. We do
// NOT leak the user's stable token id back to the client — there's no
// reason the browser needs it.

import type { FastifyInstance } from "fastify";
import type { Config } from "../config.js";
import type { DB } from "../db.js";
import { snapshot } from "../quota.js";

export function registerMe(app: FastifyInstance, cfg: Config, db: DB): void {
  app.get("/api/me", async (request, reply) => {
    const id = request.identity;
    if (!id) {
      reply.code(401).send({ error: "unauthenticated" });
      return reply;
    }
    const q = snapshot(db, id.tokenId, cfg.perUserQuotaBytes);
    return {
      isOwner: id.isOwner,
      ownerDisplayName: cfg.ownerDisplayName,
      quota: {
        usedBytes: q.usedBytes,
        limitBytes: q.limitBytes,
        remainingBytes: q.remainingBytes,
        fileCount: q.fileCount,
      },
      limits: {
        maxUploadBytes: cfg.maxUploadBytes,
        allowedMimePrefixes: cfg.allowedMimePrefixes,
      },
    };
  });
}
