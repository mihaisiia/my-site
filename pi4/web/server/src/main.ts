// Entry point. Loads config, builds the app, handles signals.

import fs from "node:fs";

import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";

async function main(): Promise<void> {
  const cfg = loadConfig();

  // Ensure uploads dir exists; we don't create it lazily on first upload so
  // permission problems surface at boot.
  fs.mkdirSync(cfg.uploadsDir, { recursive: true });

  const { app } = await buildApp(cfg);

  await app.listen({ port: cfg.port, host: cfg.bind });

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "shutting down");
    try {
      await app.close();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, "shutdown error");
      process.exit(1);
    }
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("fatal:", err);
  process.exit(1);
});
