// File uploads. Each authenticated user has PER_USER_QUOTA_BYTES of storage.
//
// Privacy:
//   - GET /api/uploads lists only the caller's own files.
//   - GET /api/uploads/:id/download streams a file only if (a) it belongs to
//     the caller or (b) the caller is the owner.
//   - DELETE same rule as GET.
//
// Quota enforcement:
//   - Pre-check Content-Length vs remaining quota and reject with 413 before
//     we open a temp file.
//   - multipart `fileSize` limit set to `min(MAX_UPLOAD_BYTES, remaining)` so
//     the stream is aborted by the parser when it would push us over.
//   - We also tally bytesWritten manually so partial writes can't slip past
//     the parser limit. After stream end we verify size and truncated flag.
//
// Files on disk live at:
//   ${UPLOADS_DIR}/<bucket(token_id)>/<upload_id>__<safe_filename>
// `bucket` is sha256(token_id)[:16] — directory-key only, not used for auth.

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

import multipart from "@fastify/multipart";
import type { FastifyInstance } from "fastify";
import { nanoid } from "nanoid";

import type { Config } from "../config.js";
import type { DB } from "../db.js";
import { snapshot, usedBytes } from "../quota.js";

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

function publicShape(u: UploadRow) {
  return {
    id: u.id,
    filename: u.filename,
    mime: u.mime,
    sizeBytes: u.size_bytes,
    createdAt: u.created_at,
  };
}

// Strip path separators, control chars, and leading dots so the basename is
// safe for any filesystem and can't escape its parent dir.
function safeBasename(name: string): string {
  // eslint-disable-next-line no-control-regex
  const noControl = name.replace(/[\x00-\x1f\x7f]/g, "");
  const noSep = noControl.replace(/[/\\]/g, "_");
  const noLeadDot = noSep.replace(/^\.+/, "_");
  const trimmed = noLeadDot.trim().slice(0, 180);
  return trimmed || "file";
}

function mimeAllowed(mime: string, prefixes: string[]): boolean {
  if (prefixes.length === 0) return true;
  return prefixes.some((p) => mime.startsWith(p));
}

function bucketDir(tokenId: string): string {
  return crypto.createHash("sha256").update(tokenId).digest("hex").slice(0, 16);
}

export async function registerUploads(
  app: FastifyInstance,
  cfg: Config,
  db: DB,
): Promise<void> {
  await app.register(multipart, {
    limits: {
      fileSize: cfg.maxUploadBytes,
      files: 1,
      fields: 5,
      fieldSize: 1024 * 32,
    },
  });

  const listForOwner = db.prepare<[string], UploadRow>(
    `SELECT * FROM uploads WHERE owner_token_id = ? ORDER BY created_at DESC`,
  );
  const byIdForOwner = db.prepare<[string, string], UploadRow>(
    `SELECT * FROM uploads WHERE id = ? AND owner_token_id = ?`,
  );
  const byIdAny = db.prepare<[string], UploadRow>(
    `SELECT * FROM uploads WHERE id = ?`,
  );
  const insert = db.prepare(
    `INSERT INTO uploads (id, owner_token_id, filename, mime, size_bytes, sha256, stored_path, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const del = db.prepare(`DELETE FROM uploads WHERE id = ?`);

  // GET /api/uploads — only the caller's own.
  app.get("/api/uploads", async (request, reply) => {
    const id = request.identity;
    if (!id) {
      reply.code(401).send({ error: "unauthenticated" });
      return reply;
    }
    const rows = listForOwner.all(id.tokenId);
    const q = snapshot(db, id.tokenId, cfg.perUserQuotaBytes);
    return {
      uploads: rows.map(publicShape),
      quota: q,
    };
  });

  // GET /api/uploads/:id/download — stream a file. Uploader or owner.
  app.get<{ Params: { id: string } }>(
    "/api/uploads/:id/download",
    async (request, reply) => {
      const id = request.identity;
      if (!id) {
        reply.code(401).send({ error: "unauthenticated" });
        return reply;
      }
      const row = id.isOwner
        ? byIdAny.get(request.params.id)
        : byIdForOwner.get(request.params.id, id.tokenId);
      if (!row) {
        reply.code(404).send({ error: "not_found" });
        return reply;
      }
      const abs = path.join(cfg.uploadsDir, row.stored_path);
      try {
        await fsp.access(abs, fs.constants.R_OK);
      } catch {
        reply.code(410).send({ error: "gone" });
        return reply;
      }
      reply
        .header("Content-Type", row.mime || "application/octet-stream")
        .header("Content-Length", String(row.size_bytes))
        .header(
          "Content-Disposition",
          `attachment; filename*=UTF-8''${encodeURIComponent(row.filename)}`,
        );
      return reply.send(fs.createReadStream(abs));
    },
  );

  // DELETE /api/uploads/:id — uploader or owner.
  app.delete<{ Params: { id: string } }>(
    "/api/uploads/:id",
    async (request, reply) => {
      const id = request.identity;
      if (!id) {
        reply.code(401).send({ error: "unauthenticated" });
        return reply;
      }
      const row = id.isOwner
        ? byIdAny.get(request.params.id)
        : byIdForOwner.get(request.params.id, id.tokenId);
      if (!row) {
        reply.code(404).send({ error: "not_found" });
        return reply;
      }
      del.run(row.id);
      const abs = path.join(cfg.uploadsDir, row.stored_path);
      try {
        await fsp.unlink(abs);
      } catch (err) {
        request.log.warn({ err, abs }, "failed to unlink upload");
      }
      reply.code(204).send();
      return reply;
    },
  );

  // POST /api/uploads — multipart, single file.
  app.post("/api/uploads", async (request, reply) => {
    const id = request.identity;
    if (!id) {
      reply.code(401).send({ error: "unauthenticated" });
      return reply;
    }

    const used = usedBytes(db, id.tokenId);
    const remaining = Math.max(0, cfg.perUserQuotaBytes - used);

    // Pre-check: if the envelope itself already exceeds quota, bail.
    const claimedLen = Number(request.headers["content-length"] ?? 0);
    if (Number.isFinite(claimedLen) && claimedLen > 0 && claimedLen > remaining) {
      reply.code(413).send({
        error: "quota_exceeded",
        remainingBytes: remaining,
        limitBytes: cfg.perUserQuotaBytes,
      });
      return reply;
    }
    if (remaining <= 0) {
      reply.code(413).send({
        error: "quota_exceeded",
        remainingBytes: 0,
        limitBytes: cfg.perUserQuotaBytes,
      });
      return reply;
    }

    let part: Awaited<ReturnType<typeof request.file>>;
    try {
      part = await request.file({
        limits: {
          // Cap = min(global max, remaining). multipart aborts the stream
          // when this is exceeded and sets part.file.truncated = true.
          fileSize: Math.min(cfg.maxUploadBytes, remaining),
        },
      });
    } catch (err) {
      request.log.warn({ err }, "multipart parse error");
      reply.code(400).send({ error: "bad_multipart" });
      return reply;
    }
    if (!part) {
      reply.code(400).send({ error: "no_file" });
      return reply;
    }

    const mime = (part.mimetype || "application/octet-stream").toLowerCase();
    if (!mimeAllowed(mime, cfg.allowedMimePrefixes)) {
      part.file.resume(); // drain
      reply.code(415).send({ error: "mime_not_allowed", mime });
      return reply;
    }

    const uploadId = nanoid(16);
    const filename = safeBasename(part.filename || `upload-${uploadId}`);
    const bucket = bucketDir(id.tokenId);
    const dir = path.join(cfg.uploadsDir, bucket);
    await fsp.mkdir(dir, { recursive: true });
    const rel = path.join(bucket, `${uploadId}__${filename}`);
    const tmp = path.join(dir, `.${uploadId}.part`);
    const final = path.join(cfg.uploadsDir, rel);

    const hasher = crypto.createHash("sha256");
    let bytesWritten = 0;
    const write = fs.createWriteStream(tmp, { flags: "wx" });

    const finished: Promise<void> = new Promise((resolve, reject) => {
      part!.file.on("data", (chunk: Buffer) => {
        hasher.update(chunk);
        bytesWritten += chunk.length;
      });
      part!.file.on("error", (err) => reject(err));
      write.on("error", (err) => reject(err));
      write.on("close", () => resolve());
      part!.file.pipe(write);
    });

    try {
      await finished;
    } catch (err) {
      await fsp.unlink(tmp).catch(() => {});
      request.log.error({ err }, "upload stream failed");
      reply.code(500).send({ error: "upload_failed" });
      return reply;
    }

    // multipart sets `truncated = true` when fileSize is exceeded.
    if (part.file.truncated || bytesWritten > remaining) {
      await fsp.unlink(tmp).catch(() => {});
      reply.code(413).send({
        error: "quota_exceeded",
        remainingBytes: Math.max(0, remaining - bytesWritten),
        limitBytes: cfg.perUserQuotaBytes,
      });
      return reply;
    }

    if (bytesWritten === 0) {
      await fsp.unlink(tmp).catch(() => {});
      reply.code(400).send({ error: "empty_file" });
      return reply;
    }

    try {
      await fsp.rename(tmp, final);
    } catch (err) {
      await fsp.unlink(tmp).catch(() => {});
      request.log.error({ err }, "upload finalize failed");
      reply.code(500).send({ error: "upload_failed" });
      return reply;
    }

    const now = Date.now();
    insert.run(
      uploadId,
      id.tokenId,
      filename,
      mime,
      bytesWritten,
      hasher.digest("hex"),
      rel,
      now,
    );

    reply.code(201).send({
      upload: {
        id: uploadId,
        filename,
        mime,
        sizeBytes: bytesWritten,
        createdAt: now,
      },
      quota: snapshot(db, id.tokenId, cfg.perUserQuotaBytes),
    });
    return reply;
  });
}
