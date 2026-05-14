// Per-user upload quota arithmetic. Single source of truth is the `uploads`
// table; we trust the row-level size_bytes column.

import type { DB } from "./db.js";

export interface QuotaSnapshot {
  usedBytes: number;
  limitBytes: number;
  remainingBytes: number;
  fileCount: number;
}

export function usedBytes(db: DB, tokenId: string): number {
  const row = db
    .prepare<[string], { total: number | null }>(
      "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM uploads WHERE owner_token_id = ?",
    )
    .get(tokenId);
  // SQLite SUM() returns NULL for empty sets; coalesce + Number to be safe.
  return Number(row?.total ?? 0);
}

export function fileCount(db: DB, tokenId: string): number {
  const row = db
    .prepare<[string], { c: number }>(
      "SELECT COUNT(*) AS c FROM uploads WHERE owner_token_id = ?",
    )
    .get(tokenId);
  return Number(row?.c ?? 0);
}

export function snapshot(
  db: DB,
  tokenId: string,
  limitBytes: number,
): QuotaSnapshot {
  const used = usedBytes(db, tokenId);
  return {
    usedBytes: used,
    limitBytes,
    remainingBytes: Math.max(0, limitBytes - used),
    fileCount: fileCount(db, tokenId),
  };
}

// True iff adding `incomingBytes` for `tokenId` would stay within
// `limitBytes`. Caller is expected to hold the DB context that has just read
// existing usage (we accept used directly so we don't re-query when streaming
// rolling checks).
export function wouldExceed(
  usedSoFar: number,
  incomingBytes: number,
  limitBytes: number,
): boolean {
  return usedSoFar + incomingBytes > limitBytes;
}
