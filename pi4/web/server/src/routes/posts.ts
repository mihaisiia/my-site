// Blog posts. Read: anyone authenticated. Write: owner only.
//
// Privacy: the response intentionally has no `author` field. The displayed
// author on the SPA is `OWNER_DISPLAY_NAME` from /api/me. This keeps the
// API surface free of user identifiers a reader could correlate.

import type { FastifyInstance } from "fastify";
import { nanoid } from "nanoid";
import { z } from "zod";

import type { DB } from "../db.js";
import { requireOwner } from "../identity.js";
import { htmlToText, sanitizeHtml } from "../sanitize.js";

const slugRe = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const createSchema = z.object({
  slug: z.string().min(1).max(120).regex(slugRe, "slug must be kebab-case"),
  title: z.string().min(1).max(200),
  // TipTap output. Sanitized before storage.
  bodyHtml: z.string().max(2_000_000),
  published: z.boolean().optional().default(false),
});

const updateSchema = z.object({
  slug: z.string().min(1).max(120).regex(slugRe).optional(),
  title: z.string().min(1).max(200).optional(),
  bodyHtml: z.string().max(2_000_000).optional(),
  published: z.boolean().optional(),
});

interface PostRow {
  id: string;
  slug: string;
  title: string;
  body_html: string;
  body_text: string;
  published: number;
  created_at: number;
  updated_at: number;
}

function publicShape(p: PostRow) {
  return {
    id: p.id,
    slug: p.slug,
    title: p.title,
    bodyHtml: p.body_html,
    published: !!p.published,
    createdAt: p.created_at,
    updatedAt: p.updated_at,
    // Cheap excerpt for the list page.
    excerpt: p.body_text.slice(0, 240),
  };
}

export function registerPosts(app: FastifyInstance, db: DB): void {
  const listPublished = db.prepare<[], PostRow>(
    `SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC`,
  );
  const listAll = db.prepare<[], PostRow>(
    `SELECT * FROM posts ORDER BY created_at DESC`,
  );
  const bySlug = db.prepare<[string], PostRow>(
    `SELECT * FROM posts WHERE slug = ?`,
  );
  const byId = db.prepare<[string], PostRow>(
    `SELECT * FROM posts WHERE id = ?`,
  );
  const insertStmt = db.prepare(
    `INSERT INTO posts (id, slug, title, body_html, body_text, published, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const updateStmt = db.prepare(
    `UPDATE posts SET slug = ?, title = ?, body_html = ?, body_text = ?, published = ?, updated_at = ?
     WHERE id = ?`,
  );
  const deleteStmt = db.prepare(`DELETE FROM posts WHERE id = ?`);

  // List. Owner sees drafts too; everyone else only sees published.
  app.get("/api/posts", async (request) => {
    const rows = requireOwner(request) ? listAll.all() : listPublished.all();
    return { posts: rows.map(publicShape) };
  });

  // Single post by slug. Non-owners can read drafts only if they know the
  // slug? No — explicitly gate drafts to the owner.
  app.get<{ Params: { slug: string } }>(
    "/api/posts/:slug",
    async (request, reply) => {
      const row = bySlug.get(request.params.slug);
      if (!row) {
        reply.code(404).send({ error: "not_found" });
        return reply;
      }
      if (!row.published && !requireOwner(request)) {
        reply.code(404).send({ error: "not_found" });
        return reply;
      }
      return publicShape(row);
    },
  );

  // Create / Update / Delete — owner only.
  app.post("/api/posts", async (request, reply) => {
    if (!requireOwner(request)) {
      reply.code(403).send({ error: "forbidden" });
      return reply;
    }
    const parsed = createSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.code(400).send({ error: "bad_request", issues: parsed.error.issues });
      return reply;
    }
    if (bySlug.get(parsed.data.slug)) {
      reply.code(409).send({ error: "slug_taken" });
      return reply;
    }
    const now = Date.now();
    const id = nanoid(12);
    const html = sanitizeHtml(parsed.data.bodyHtml);
    const text = htmlToText(html);
    insertStmt.run(
      id,
      parsed.data.slug,
      parsed.data.title,
      html,
      text,
      parsed.data.published ? 1 : 0,
      now,
      now,
    );
    const row = byId.get(id);
    return publicShape(row!);
  });

  app.patch<{ Params: { id: string } }>(
    "/api/posts/:id",
    async (request, reply) => {
      if (!requireOwner(request)) {
        reply.code(403).send({ error: "forbidden" });
        return reply;
      }
      const existing = byId.get(request.params.id);
      if (!existing) {
        reply.code(404).send({ error: "not_found" });
        return reply;
      }
      const parsed = updateSchema.safeParse(request.body);
      if (!parsed.success) {
        reply.code(400).send({ error: "bad_request", issues: parsed.error.issues });
        return reply;
      }
      const next = {
        slug: parsed.data.slug ?? existing.slug,
        title: parsed.data.title ?? existing.title,
        bodyHtml:
          parsed.data.bodyHtml !== undefined
            ? sanitizeHtml(parsed.data.bodyHtml)
            : existing.body_html,
        published:
          parsed.data.published !== undefined
            ? parsed.data.published
            : !!existing.published,
      };
      // Slug uniqueness check if changed.
      if (next.slug !== existing.slug) {
        const conflict = bySlug.get(next.slug);
        if (conflict) {
          reply.code(409).send({ error: "slug_taken" });
          return reply;
        }
      }
      const text = htmlToText(next.bodyHtml);
      updateStmt.run(
        next.slug,
        next.title,
        next.bodyHtml,
        text,
        next.published ? 1 : 0,
        Date.now(),
        existing.id,
      );
      return publicShape(byId.get(existing.id)!);
    },
  );

  app.delete<{ Params: { id: string } }>(
    "/api/posts/:id",
    async (request, reply) => {
      if (!requireOwner(request)) {
        reply.code(403).send({ error: "forbidden" });
        return reply;
      }
      const row = byId.get(request.params.id);
      if (!row) {
        reply.code(404).send({ error: "not_found" });
        return reply;
      }
      deleteStmt.run(row.id);
      reply.code(204).send();
      return reply;
    },
  );
}
