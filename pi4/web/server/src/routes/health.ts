import type { FastifyInstance } from "fastify";

export function registerHealth(app: FastifyInstance): void {
  app.get("/api/healthz", async () => ({ ok: true }));
}
