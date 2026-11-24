// src/config.ts
import { join } from "node:path";

function intEnv(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function secretEnv(name: string): string {
  const val = process.env[name]?.trim();
  if (val && val.length >= 16) return val;
  return (
    crypto.randomUUID().replace(/-/g, "") +
    crypto.randomUUID().replace(/-/g, "")
  );
}

export const config = {
  port: intEnv("PORT", 3000),
  debug: process.env.DEBUG === "1",
  appSecret: secretEnv("APP_SECRET"),
  tokenTtlSeconds: intEnv("TOKEN_TTL_SECONDS", 60 * 60 * 24 * 7),
  roomInactiveSeconds: intEnv("ROOM_INACTIVE_SECONDS", 60 * 60 * 24),
  maxFileSize: intEnv("MAX_FILE_SIZE_MB", 100) * 1024 * 1024,
  maxChunkSize: intEnv("MAX_CHUNK_SIZE_MB", 10) * 1024 * 1024,
  maxMessageLength: intEnv("MAX_MESSAGE_LENGTH", 5000),
  maxUsernameLength: intEnv("MAX_USERNAME_LENGTH", 30),
  maxReactionsPerMsg: intEnv("MAX_REACTIONS_PER_MSG", 12),
  maxRoomLength: 8,
  maxFileIdLength: 100,
  maxFileNameLength: 255,
  dataDir: join(import.meta.dir, "..", "data"),
  uploadDir: join(import.meta.dir, "..", "data", "uploads"),
  publicDir: join(import.meta.dir, "..", "public"),
} as const;
