// SQLite handle + migrations. We use better-sqlite3 (synchronous) because
// the Pi has plenty of CPU headroom and avoiding async hops keeps quota
// arithmetic transactional in a single WAL transaction.

import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";

export type DB = Database.Database;

const MIGRATIONS: { id: string; sql: string }[] = [
  {
    id: "001_init",
    sql: `
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      PRAGMA synchronous = NORMAL;

      CREATE TABLE IF NOT EXISTS posts (
        id           TEXT PRIMARY KEY,
        slug         TEXT NOT NULL UNIQUE,
        title        TEXT NOT NULL,
        -- Body is sanitized HTML produced by TipTap. We strip on input, so
        -- consumers read it as-is.
        body_html    TEXT NOT NULL,
        body_text    TEXT NOT NULL,
        published    INTEGER NOT NULL DEFAULT 0,
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS posts_published_created
        ON posts(published, created_at DESC);

      -- One row per uploaded file. owner_token_id is the stable per-user
      -- identifier from X-Auth-Token-Id. We never expose owner_token_id
      -- to anyone except the OWNER.
      CREATE TABLE IF NOT EXISTS uploads (
        id              TEXT PRIMARY KEY,
        owner_token_id  TEXT NOT NULL,
        filename        TEXT NOT NULL,
        mime            TEXT NOT NULL,
        size_bytes      INTEGER NOT NULL,
        sha256          TEXT,
        stored_path     TEXT NOT NULL,
        created_at      INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS uploads_owner_created
        ON uploads(owner_token_id, created_at DESC);
    `,
  },
];

export function openDatabase(dataDir: string): DB {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, "app.db");
  const db = new Database(file);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("synchronous = NORMAL");

  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    id TEXT PRIMARY KEY,
    applied_at INTEGER NOT NULL
  );`);

  const has = db.prepare("SELECT 1 FROM schema_migrations WHERE id = ?");
  const insert = db.prepare(
    "INSERT INTO schema_migrations(id, applied_at) VALUES (?, ?)",
  );

  for (const m of MIGRATIONS) {
    if (has.get(m.id)) continue;
    db.exec("BEGIN");
    try {
      db.exec(m.sql);
      insert.run(m.id, Date.now());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
