// Centralised env loading. We resolve once at boot and fail loudly if
// anything that affects security (trusted CIDRs, owner token, paths) is
// missing or malformed.

import { isIP } from "node:net";
import path from "node:path";

export interface Config {
  nodeEnv: string;
  port: number;
  bind: string;
  logLevel: string;

  dataDir: string;
  uploadsDir: string;
  webRoot: string;

  trustedCidrs: Cidr[];
  ownerTokenId: string;
  ownerDisplayName: string;

  perUserQuotaBytes: number;
  maxUploadBytes: number;
  allowedMimePrefixes: string[];
}

export interface Cidr {
  raw: string;
  family: 4 | 6;
  // For IPv4 we store as a 32-bit number + prefix length. For IPv6 as a
  // BigInt + prefix length. Membership is then a simple bitmask compare.
  v4Net?: number;
  v6Net?: bigint;
  prefix: number;
}

function envStr(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") {
    if (fallback !== undefined) return fallback;
    throw new Error(`missing required env var: ${name}`);
  }
  return v;
}

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
    throw new Error(`env ${name} must be a non-negative integer, got: ${v}`);
  }
  return n;
}

function parseCidrs(raw: string): Cidr[] {
  const out: Cidr[] = [];
  for (const piece of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const cidr = parseCidr(piece);
    if (!cidr) throw new Error(`bad CIDR in TRUSTED_PROXY_CIDRS: ${piece}`);
    out.push(cidr);
  }
  if (out.length === 0) {
    throw new Error("TRUSTED_PROXY_CIDRS must list at least one CIDR");
  }
  return out;
}

function parseCidr(s: string): Cidr | null {
  const m = s.match(/^([^/]+)\/(\d+)$/);
  if (!m) return null;
  const ip = m[1]!;
  const prefix = Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 0) return null;
  const family = isIP(ip);
  if (family === 4) {
    if (prefix > 32) return null;
    const n = ipv4ToInt(ip);
    if (n === null) return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { raw: s, family: 4, v4Net: n & mask, prefix };
  }
  if (family === 6) {
    if (prefix > 128) return null;
    const n = ipv6ToBigInt(ip);
    if (n === null) return null;
    const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
    return { raw: s, family: 6, v6Net: n & mask, prefix };
  }
  return null;
}

export function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

export function ipv6ToBigInt(ip: string): bigint | null {
  // Naive but correct full/compressed parse. node:net validated it already,
  // we just need a numeric form for bitmask compare.
  if (!ip.includes(":")) return null;
  // Handle :: shorthand.
  let groups: string[];
  if (ip.includes("::")) {
    const [lhs, rhs] = ip.split("::") as [string, string];
    const left = lhs ? lhs.split(":") : [];
    const right = rhs ? rhs.split(":") : [];
    const missing = 8 - (left.length + right.length);
    groups = [...left, ...new Array<string>(missing).fill("0"), ...right];
  } else {
    groups = ip.split(":");
  }
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (g.length === 0 || g.length > 4) return null;
    const v = parseInt(g, 16);
    if (Number.isNaN(v) || v < 0 || v > 0xffff) return null;
    n = (n << 16n) | BigInt(v);
  }
  return n;
}

export function isTrusted(ip: string, cidrs: Cidr[]): boolean {
  const fam = isIP(ip);
  if (fam === 4) {
    const n = ipv4ToInt(ip);
    if (n === null) return false;
    for (const c of cidrs) {
      if (c.family !== 4 || c.v4Net === undefined) continue;
      const mask = c.prefix === 0 ? 0 : (0xffffffff << (32 - c.prefix)) >>> 0;
      if ((n & mask) === c.v4Net) return true;
    }
    return false;
  }
  if (fam === 6) {
    const n = ipv6ToBigInt(ip);
    if (n === null) return false;
    for (const c of cidrs) {
      if (c.family !== 6 || c.v6Net === undefined) continue;
      const mask = c.prefix === 0 ? 0n : ((1n << BigInt(c.prefix)) - 1n) << BigInt(128 - c.prefix);
      if ((n & mask) === c.v6Net) return true;
    }
    return false;
  }
  return false;
}

export function loadConfig(): Config {
  const dataDir = path.resolve(envStr("DATA_DIR", "/data"));
  const uploadsDir = path.resolve(envStr("UPLOADS_DIR", "/uploads"));
  const webRoot = path.resolve(envStr("WEB_ROOT", "/app/web/dist"));

  const allowedMimePrefixes = envStr("ALLOWED_MIME_PREFIXES", "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    nodeEnv: envStr("NODE_ENV", "production"),
    port: envInt("PORT", 3000),
    bind: envStr("BIND", "0.0.0.0"),
    logLevel: envStr("LOG_LEVEL", "info"),

    dataDir,
    uploadsDir,
    webRoot,

    trustedCidrs: parseCidrs(envStr("TRUSTED_PROXY_CIDRS")),
    ownerTokenId: envStr("OWNER_TOKEN_ID"),
    ownerDisplayName: envStr("OWNER_DISPLAY_NAME", "host"),

    perUserQuotaBytes: envInt("PER_USER_QUOTA_BYTES", 5 * 1024 * 1024 * 1024),
    maxUploadBytes: envInt("MAX_UPLOAD_BYTES", 2 * 1024 * 1024 * 1024),
    allowedMimePrefixes,
  };
}
