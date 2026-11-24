// src/db.ts
import { Database } from "bun:sqlite";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { config } from "./config";

mkdirSync(config.dataDir, { recursive: true });
mkdirSync(config.uploadDir, { recursive: true });

export const db = new Database(join(config.dataDir, "batelnagogram.sqlite"), {
  create: true,
});
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login INTEGER
  );

  CREATE TABLE IF NOT EXISTS user_pubkeys (
    user_id TEXT PRIMARY KEY,
    public_key_jwk TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sessions (
    session_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS rooms (
    room TEXT PRIMARY KEY,
    room_name TEXT,
    password_hash TEXT,
    created_by TEXT NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS room_epochs (
    room TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    key_material_b64 TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (room, epoch),
    FOREIGN KEY (room) REFERENCES rooms(room) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS room_activity (
    room TEXT PRIMARY KEY,
    last_active INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT NOT NULL,
    sender TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 1,
    message TEXT NOT NULL DEFAULT '',
    iv TEXT,
    reply_to INTEGER,
    file_name TEXT,
    file_size INTEGER,
    file_id TEXT,
    timestamp INTEGER NOT NULL,
    edited_at INTEGER,
    deleted_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room, id);

  CREATE TABLE IF NOT EXISTS message_reactions (
    room TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    user_id TEXT NOT NULL,
    emoji TEXT NOT NULL,
    PRIMARY KEY (room, message_id, user_id, emoji)
  );

  CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    message TEXT NOT NULL,
    iv TEXT NOT NULL,
    reply_to INTEGER,
    timestamp INTEGER NOT NULL,
    edited_at INTEGER,
    deleted_at INTEGER,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_pm_pair_id ON private_messages(sender_id, recipient_id, id);

  CREATE TABLE IF NOT EXISTS room_presence (
    room TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    username TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (room, sender_id)
  );

  CREATE TABLE IF NOT EXISTS file_transfers (
    file_id TEXT NOT NULL,
    room TEXT NOT NULL,
    sender TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    total_chunks INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (room, file_id)
  );
`);

export function hashSecret(val: string): string {
  return createHmac("sha256", config.appSecret).update(val).digest("hex");
}

export function newLoginToken(): string {
  return "bn_" + randomBytes(24).toString("base64url");
}

export function newSessionToken(): string {
  return "bns_" + randomBytes(24).toString("base64url");
}

export function safeCompare(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function sanitizeRoom(input: unknown): string {
  if (typeof input !== "string") return "";
  const hex = input
    .toLowerCase()
    .trim()
    .replace(/[^a-f0-9]/g, "");
  return hex.length === 8 ? hex : "";
}

export function sanitizeUsername(input: unknown): string {
  if (typeof input !== "string") return "";
  return Array.from(input.trim()).slice(0, config.maxUsernameLength).join("");
}

export function sanitizeText(input: unknown, maxLen: number): string {
  if (typeof input !== "string") return "";
  return Array.from(input.trim()).slice(0, maxLen).join("");
}

export function sanitizeFileId(input: unknown): string {
  if (typeof input !== "string") return "";
  return input
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, config.maxFileIdLength);
}

export function sanitizeEmoji(input: unknown): string {
  if (typeof input !== "string") return "";
  const trimmed = input.trim();
  if (!trimmed || Array.from(trimmed).length > 8) return "";
  return trimmed;
}

export function getAuthUser(
  authHeader: string | null,
  queryToken: string | null,
) {
  const raw =
    (authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : "") ||
    (queryToken ?? "").trim();
  if (!raw) return null;

  const now = Math.floor(Date.now() / 1000);
  db.query("DELETE FROM sessions WHERE expires_at < ?1").run(now);

  return (
    db
      .query<{ id: string; username: string }, [string, number]>(
        `
        SELECT u.id, u.username
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_hash = ?1 AND s.expires_at >= ?2
        LIMIT 1
      `,
      )
      .get(hashSecret(raw), now) ?? null
  );
}

export function touchRoom(room: string): void {
  const now = Math.floor(Date.now() / 1000);
  db.query(
    `
    INSERT INTO room_activity (room, last_active) VALUES (?1, ?2)
    ON CONFLICT(room) DO UPDATE SET last_active = excluded.last_active
  `,
  ).run(room, now);
}

export function touchPresence(
  room: string,
  userId: string,
  username?: string,
): void {
  const now = Math.floor(Date.now() / 1000);
  if (username) {
    db.query(
      `
      INSERT INTO room_presence (room, sender_id, username, last_seen) VALUES (?1, ?2, ?3, ?4)
      ON CONFLICT(room, sender_id) DO UPDATE SET username = excluded.username, last_seen = excluded.last_seen
    `,
    ).run(room, userId, username, now);
  } else {
    db.query(
      "UPDATE room_presence SET last_seen = ?1 WHERE room = ?2 AND sender_id = ?3",
    ).run(now, room, userId);
  }
}

export function advanceRoomEpoch(
  room: string,
  actorId: string,
): { epoch: number; keyMaterialB64: string } {
  const now = Math.floor(Date.now() / 1000);
  const keyMaterialB64 = randomBytes(32).toString("base64");

  return db.transaction(() => {
    const row = db
      .query<{ current_epoch: number }, [string]>(
        "SELECT current_epoch FROM rooms WHERE room = ?1",
      )
      .get(room);
    const nextEpoch = (row?.current_epoch ?? 0) + 1;

    db.query(
      "UPDATE rooms SET current_epoch = ?1, updated_at = ?2 WHERE room = ?3",
    ).run(nextEpoch, now, room);
    db.query(
      `
      INSERT INTO room_epochs (room, epoch, key_material_b64, created_by, created_at)
      VALUES (?1, ?2, ?3, ?4, ?5)
    `,
    ).run(room, nextEpoch, keyMaterialB64, actorId, now);

    return { epoch: nextEpoch, keyMaterialB64 };
  })();
}

export function getRoomEpochKey(
  room: string,
  epoch: number,
  actorId: string,
): { epoch: number; keyMaterialB64: string } | null {
  const roomRow = db
    .query<{ current_epoch: number }, [string]>(
      "SELECT current_epoch FROM rooms WHERE room = ?1",
    )
    .get(room);
  if (!roomRow) return null;

  const targetEpoch = epoch > 0 ? epoch : roomRow.current_epoch;
  const existing = db
    .query<{ epoch: number; key_material_b64: string }, [string, number]>(
      "SELECT epoch, key_material_b64 FROM room_epochs WHERE room = ?1 AND epoch = ?2",
    )
    .get(room, targetEpoch);

  if (existing) {
    return { epoch: existing.epoch, keyMaterialB64: existing.key_material_b64 };
  }

  if (targetEpoch === roomRow.current_epoch) {
    return advanceRoomEpoch(room, actorId);
  }
  return null;
}

export function getReactionsMap(room: string, messageIds: number[]) {
  const map: Record<
    number,
    Array<{ emoji: string; count: number; users: string[] }>
  > = {};
  if (!messageIds.length) return map;

  const placeholders = messageIds.map(() => "?").join(",");
  const rows = db
    .query<
      { message_id: number; emoji: string; user_id: string },
      [string, ...number[]]
    >(
      `SELECT message_id, emoji, user_id FROM message_reactions WHERE room = ?1 AND message_id IN (${placeholders})`,
    )
    .all(room, ...messageIds);

  const grouped = new Map<number, Map<string, string[]>>();
  for (const r of rows) {
    if (!grouped.has(r.message_id)) grouped.set(r.message_id, new Map());
    const emMap = grouped.get(r.message_id)!;
    if (!emMap.has(r.emoji)) emMap.set(r.emoji, []);
    emMap.get(r.emoji)!.push(r.user_id);
  }

  for (const [msgId, emMap] of grouped.entries()) {
    map[msgId] = Array.from(emMap.entries()).map(([emoji, users]) => ({
      emoji,
      count: users.length,
      users,
    }));
  }

  return map;
}

export function cleanInactiveRooms(): void {
  const now = Math.floor(Date.now() / 1000);
  const threshold = now - config.roomInactiveSeconds;
  db.query("DELETE FROM room_presence WHERE last_seen < ?1").run(now - 120);

  const expired = db
    .query<{ room: string }, [number]>(
      "SELECT room FROM room_activity WHERE last_active < ?1",
    )
    .all(threshold);
  if (!expired.length) return;

  db.transaction((rooms: string[]) => {
    for (const r of rooms) {
      db.query("DELETE FROM message_reactions WHERE room = ?1").run(r);
      db.query("DELETE FROM messages WHERE room = ?1").run(r);
      db.query("DELETE FROM file_transfers WHERE room = ?1").run(r);
      db.query("DELETE FROM room_activity WHERE room = ?1").run(r);
      db.query("DELETE FROM room_presence WHERE room = ?1").run(r);
      db.query("DELETE FROM room_epochs WHERE room = ?1").run(r);
      db.query("DELETE FROM rooms WHERE room = ?1").run(r);
      rmSync(join(config.uploadDir, r), { recursive: true, force: true });
    }
  })(expired.map((x) => x.room));
}

export function verifyRoomPassword(
  room: string,
  password: string | null,
): boolean {
  const row = db
    .query<{ password_hash: string | null }, [string]>(
      "SELECT password_hash FROM rooms WHERE room = ?1",
    )
    .get(room);
  if (!row || !row.password_hash) return true;
  if (!password) return false;
  return Bun.password.verifySync(password, row.password_hash);
}
