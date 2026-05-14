// Owner-only admin views. This is the one and only place where data crosses
// user boundaries: the owner can list every upload by every user, see who
// uploaded what, and delete on anyone's behalf.

import type { FastifyInstance } from "fastify";

import type { Config } from "../config.js";
import type { DB } from "../db.js";
import { requireOwner } from "../identity.js";

interface UploadRow {
  id: string;
  owner_token_id: string;
  filename: string;
  mime: string;
  size_bytes: number;
  sha256: string | null;
  stored_path: string;
  created_at: number;
}

interface UserUsageRow {
  owner_token_id: string;
  file_count: number;
  total_bytes: number;
  last_upload: number;
}

export function registerAdmin(app: FastifyInstance, cfg: Config, db: DB): void {
  // List every upload from every user, newest first. Includes uploader
  // token id so the owner can correlate to whoever they handed the token to.
  app.get("/api/admin/uploads", async (request, reply) => {
    if (!requireOwner(request)) {
      reply.code(403).send({ error: "forbidden" });
      return reply;
    }
    const rows = db
      .prepare<[], UploadRow>(
        `SELECT * FROM uploads ORDER BY created_at DESC LIMIT 500`,
      )
      .all();
    return {
      uploads: rows.map((u) => ({
        id: u.id,
        ownerTokenId: u.owner_token_id,
        filename: u.filename,
        mime: u.mime,
        sizeBytes: u.size_bytes,
        sha256: u.sha256,
        createdAt: u.created_at,
      })),
    };
  });

  // Per-user usage summary. Useful for the owner to see who's close to
  // their cap. Token ids only — the auth-svc store has the human notes.
  app.get("/api/admin/users", async (request, reply) => {
    if (!requireOwner(request)) {
      reply.code(403).send({ error: "forbidden" });
      return reply;
    }
    const rows = db
      .prepare<[], UserUsageRow>(
        `SELECT owner_token_id,
                COUNT(*)      AS file_count,
                SUM(size_bytes) AS total_bytes,
                MAX(created_at) AS last_upload
         FROM uploads
         GROUP BY owner_token_id
         ORDER BY total_bytes DESC`,
      )
      .all();
    return {
      limitBytes: cfg.perUserQuotaBytes,
      users: rows.map((r) => ({
        ownerTokenId: r.owner_token_id,
        fileCount: Number(r.file_count),
        totalBytes: Number(r.total_bytes),
        lastUploadAt: Number(r.last_upload),
        percent: cfg.perUserQuotaBytes === 0
          ? 0
          : Math.min(100, (Number(r.total_bytes) / cfg.perUserQuotaBytes) * 100),
      })),
    };
  });
}
