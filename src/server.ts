// src/server.ts
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "./config";
import {
  advanceRoomEpoch,
  cleanInactiveRooms,
  db,
  getAuthUser,
  getReactionsMap,
  getRoomEpochKey,
  hashSecret,
  newLoginToken,
  newSessionToken,
  safeCompare,
  sanitizeEmoji,
  sanitizeFileId,
  sanitizeRoom,
  sanitizeText,
  sanitizeUsername,
  touchPresence,
  touchRoom,
  verifyRoomPassword,
} from "./db";
import { apiMsg, resolveLang } from "./i18n";

interface WsSession {
  room: string;
  userId: string;
  username: string;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function publishRoom(
  srv: Bun.Server<WsSession>,
  room: string,
  event: unknown,
): void {
  srv.publish(`bn:room:${room}`, JSON.stringify(event));
}

function publishUser(
  srv: Bun.Server<WsSession>,
  userId: string,
  event: unknown,
): void {
  srv.publish(`bn:user:${userId}`, JSON.stringify(event));
}

const server = Bun.serve<WsSession>({
  port: config.port,

  websocket: {
    open(ws) {
      ws.subscribe(`bn:user:${ws.data.userId}`);
      if (ws.data.room) {
        ws.subscribe(`bn:room:${ws.data.room}`);
      }
    },
    message(ws, raw) {
      try {
        const msg = JSON.parse(String(raw));
        if (msg?.type === "ping") {
          if (ws.data.room) {
            touchPresence(ws.data.room, ws.data.userId, ws.data.username);
          }
          ws.send(JSON.stringify({ type: "pong" }));
        } else if (msg?.type === "typing") {
          if (msg.targetType === "dm" && typeof msg.recipientId === "string") {
            publishUser(server, msg.recipientId, {
              type: "typing",
              targetType: "dm",
              fromUserId: ws.data.userId,
              fromUsername: ws.data.username,
              isTyping: Boolean(msg.isTyping),
            });
          } else if (ws.data.room) {
            publishRoom(server, ws.data.room, {
              type: "typing",
              targetType: "room",
              room: ws.data.room,
              fromUserId: ws.data.userId,
              fromUsername: ws.data.username,
              isTyping: Boolean(msg.isTyping),
            });
          }
        }
      } catch {
        // ignore invalid frame
      }
    },
    close(ws) {
      ws.unsubscribe(`bn:user:${ws.data.userId}`);
      if (ws.data.room) {
        ws.unsubscribe(`bn:room:${ws.data.room}`);
      }
    },
  },

  async fetch(req, srv) {
    const url = new URL(req.url);

    if (url.pathname === "/ws") {
      const user = getAuthUser(
        req.headers.get("authorization"),
        url.searchParams.get("token"),
      );
      if (!user) return new Response("Unauthorized", { status: 401 });

      const rawRoom = url.searchParams.get("room") ?? "";
      const room = rawRoom ? sanitizeRoom(rawRoom) : "";
      if (rawRoom && !room)
        return new Response("Invalid room", { status: 400 });

      const pass = url.searchParams.get("room_password");
      if (room && !verifyRoomPassword(room, pass)) {
        return new Response("Forbidden", { status: 403 });
      }

      const upgraded = srv.upgrade(req, {
        data: { room, userId: user.id, username: user.username },
      });
      return upgraded
        ? undefined
        : new Response("Upgrade failed", { status: 400 });
    }

    if (req.method === "GET" && !url.pathname.startsWith("/api")) {
      const rel =
        url.pathname === "/" ? "index.html" : url.pathname.replace(/^\/+/, "");
      const full = join(config.publicDir, rel);
      if (!full.startsWith(config.publicDir))
        return new Response("Forbidden", { status: 403 });
      const file = Bun.file(full);
      if (await file.exists()) return new Response(file);
      return new Response(Bun.file(join(config.publicDir, "index.html")));
    }

    if (!url.pathname.startsWith("/api"))
      return new Response("Not Found", { status: 404 });

    cleanInactiveRooms();

    let body: Record<string, unknown> = {};
    let formData: FormData | null = null;
    const ct = req.headers.get("content-type") ?? "";

    if (req.method === "POST") {
      if (ct.includes("multipart/form-data")) {
        formData = await req.formData();
        for (const [k, v] of formData.entries()) {
          if (typeof v === "string") body[k] = v;
        }
      } else if (ct.includes("application/json")) {
        body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
      }
    }

    const lang = resolveLang(req, body.lang);
    const m = apiMsg(lang);
    const action = String(body.action ?? url.searchParams.get("action") ?? "");

    try {
      // --- Auth: Unique username -> one-time login token + session token ---
      if (action === "register") {
        const username = sanitizeUsername(body.username);
        if (!username) return json({ error: m.missingParams }, 400);

        const exists = db
          .query<{ id: string }, [string]>(
            "SELECT id FROM users WHERE username = ?1 LIMIT 1",
          )
          .get(username);
        if (exists) return json({ error: m.usernameTaken }, 409);

        const userId = "u_" + randomBytes(12).toString("hex");
        const loginToken = newLoginToken();
        const sessionToken = newSessionToken();
        const now = Math.floor(Date.now() / 1000);

        db.transaction(() => {
          db.query(
            "INSERT INTO users (id, username, token_hash, created_at, last_login) VALUES (?1, ?2, ?3, ?4, ?4)",
          ).run(userId, username, hashSecret(loginToken), now);
          db.query(
            "INSERT INTO sessions (session_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
          ).run(hashSecret(sessionToken), userId, now + config.tokenTtlSeconds);
        })();

        return json({
          status: "ok",
          user: { id: userId, username },
          loginToken,
          sessionToken,
        });
      }

      if (action === "login") {
        const username = sanitizeUsername(body.username);
        const loginToken = String(body.loginToken ?? "").trim();
        if (!username || !loginToken)
          return json({ error: m.missingParams }, 400);

        const user = db
          .query<
            { id: string; username: string; token_hash: string },
            [string]
          >(
            "SELECT id, username, token_hash FROM users WHERE username = ?1 LIMIT 1",
          )
          .get(username);

        if (!user || !safeCompare(hashSecret(loginToken), user.token_hash)) {
          return json({ error: m.invalidLogin }, 401);
        }

        const sessionToken = newSessionToken();
        const now = Math.floor(Date.now() / 1000);
        db.transaction(() => {
          db.query("UPDATE users SET last_login = ?1 WHERE id = ?2").run(
            now,
            user.id,
          );
          db.query(
            "INSERT INTO sessions (session_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
          ).run(
            hashSecret(sessionToken),
            user.id,
            now + config.tokenTtlSeconds,
          );
        })();

        return json({
          status: "ok",
          user: { id: user.id, username: user.username },
          sessionToken,
        });
      }

      const user = getAuthUser(
        req.headers.get("authorization"),
        url.searchParams.get("token"),
      );
      if (!user) return json({ error: m.unauthorized }, 401);

      // --- ECDH Public Keys & Directory for Private Messages ---
      if (action === "publish_pubkey") {
        const jwkStr =
          typeof body.publicKeyJwk === "string" ? body.publicKeyJwk : "";
        if (!jwkStr || jwkStr.length > 2000)
          return json({ error: m.missingParams }, 400);
        const now = Math.floor(Date.now() / 1000);
        db.query(
          `
          INSERT INTO user_pubkeys (user_id, public_key_jwk, updated_at) VALUES (?1, ?2, ?3)
          ON CONFLICT(user_id) DO UPDATE SET public_key_jwk = excluded.public_key_jwk, updated_at = excluded.updated_at
        `,
        ).run(user.id, jwkStr, now);
        return json({ status: "ok" });
      }

      if (action === "list_users") {
        const rows = db
          .query<
            { id: string; username: string; public_key_jwk: string | null },
            [string]
          >(
            `
            SELECT u.id, u.username, p.public_key_jwk
            FROM users u
            LEFT JOIN user_pubkeys p ON p.user_id = u.id
            WHERE u.id != ?1
            ORDER BY u.username ASC
          `,
          )
          .all(user.id);
        return json({ users: rows });
      }

      if (action === "get_pubkey") {
        const targetId = sanitizeText(
          body.userId ?? url.searchParams.get("userId"),
          64,
        );
        if (!targetId) return json({ error: m.missingParams }, 400);
        const row = db
          .query<
            {
              user_id: string;
              username: string;
              public_key_jwk: string | null;
            },
            [string]
          >(
            `
            SELECT u.id AS user_id, u.username, p.public_key_jwk
            FROM users u
            LEFT JOIN user_pubkeys p ON p.user_id = u.id
            WHERE u.id = ?1 LIMIT 1
          `,
          )
          .get(targetId);
        if (!row) return json({ error: m.recipientNotFound }, 404);
        return json(row);
      }

      // --- Private Messages (DMs) ---
      if (action === "send_dm") {
        const recipientId = sanitizeText(body.recipientId, 64);
        const ciphertext = sanitizeText(
          body.message,
          config.maxMessageLength * 2,
        );
        const iv = typeof body.iv === "string" ? body.iv.slice(0, 128) : "";
        const replyTo =
          typeof body.reply_to === "number" && body.reply_to > 0
            ? Math.floor(body.reply_to)
            : null;

        if (!recipientId || !ciphertext || !iv)
          return json({ error: m.missingParams }, 400);
        const recipient = db
          .query<{ id: string; username: string }, [string]>(
            "SELECT id, username FROM users WHERE id = ?1",
          )
          .get(recipientId);
        if (!recipient) return json({ error: m.recipientNotFound }, 404);

        const now = Math.floor(Date.now() / 1000);
        const ins = db
          .query(
            "INSERT INTO private_messages (sender_id, recipient_id, message, iv, reply_to, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
          )
          .run(user.id, recipientId, ciphertext, iv, replyTo, now);

        const dmObj = {
          id: Number(ins.lastInsertRowid),
          sender_id: user.id,
          senderName: user.username,
          recipient_id: recipientId,
          recipientName: recipient.username,
          message: ciphertext,
          iv,
          reply_to: replyTo,
          timestamp: now,
          edited_at: null,
          deleted_at: null,
        };

        publishUser(srv, user.id, { type: "dm", message: dmObj });
        publishUser(srv, recipientId, { type: "dm", message: dmObj });
        return json({ status: "ok", id: dmObj.id, message: dmObj });
      }

      if (action === "poll_dms") {
        const peerId = sanitizeText(url.searchParams.get("peerId"), 64);
        const sinceId = Number(url.searchParams.get("since_id") ?? 0);
        if (!peerId) return json({ messages: [] });

        const rows = db
          .query(
            `
            SELECT pm.id, pm.sender_id, su.username AS senderName, pm.recipient_id, ru.username AS recipientName,
                   pm.message, pm.iv, pm.reply_to, pm.timestamp, pm.edited_at, pm.deleted_at
            FROM private_messages pm
            JOIN users su ON su.id = pm.sender_id
            JOIN users ru ON ru.id = pm.recipient_id
            WHERE ((pm.sender_id = ?1 AND pm.recipient_id = ?2) OR (pm.sender_id = ?2 AND pm.recipient_id = ?1))
              AND pm.id > ?3
            ORDER BY pm.id ASC LIMIT 100
          `,
          )
          .all(user.id, peerId, sinceId);

        return json({ messages: rows });
      }

      if (action === "edit_dm") {
        const id = Number(body.id ?? 0);
        const ciphertext = sanitizeText(
          body.message,
          config.maxMessageLength * 2,
        );
        const iv = typeof body.iv === "string" ? body.iv.slice(0, 128) : "";
        if (!id || !ciphertext || !iv)
          return json({ error: m.missingParams }, 400);

        const row = db
          .query<
            { id: number; sender_id: string; recipient_id: string },
            [number]
          >(
            "SELECT id, sender_id, recipient_id FROM private_messages WHERE id = ?1",
          )
          .get(id);
        if (!row) return json({ error: m.messageNotFound }, 404);
        if (row.sender_id !== user.id)
          return json({ error: m.forbiddenEdit }, 403);

        const now = Math.floor(Date.now() / 1000);
        db.query(
          "UPDATE private_messages SET message = ?1, iv = ?2, edited_at = ?3 WHERE id = ?4",
        ).run(ciphertext, iv, now, id);

        const payload = {
          type: "dm_edited",
          id,
          message: ciphertext,
          iv,
          edited_at: now,
          sender_id: row.sender_id,
          recipient_id: row.recipient_id,
        };
        publishUser(srv, row.sender_id, payload);
        publishUser(srv, row.recipient_id, payload);
        return json({ status: "ok", edited_at: now });
      }

      if (action === "delete_dm") {
        const id = Number(body.id ?? 0);
        if (!id) return json({ error: m.missingParams }, 400);

        const row = db
          .query<
            { id: number; sender_id: string; recipient_id: string },
            [number]
          >(
            "SELECT id, sender_id, recipient_id FROM private_messages WHERE id = ?1",
          )
          .get(id);
        if (!row) return json({ error: m.messageNotFound }, 404);
        if (row.sender_id !== user.id)
          return json({ error: m.forbiddenEdit }, 403);

        const now = Math.floor(Date.now() / 1000);
        db.query(
          "UPDATE private_messages SET deleted_at = ?1, message = '' WHERE id = ?2",
        ).run(now, id);

        const payload = {
          type: "dm_deleted",
          id,
          deleted_at: now,
          sender_id: row.sender_id,
          recipient_id: row.recipient_id,
        };
        publishUser(srv, row.sender_id, payload);
        publishUser(srv, row.recipient_id, payload);
        return json({ status: "ok", deleted_at: now });
      }

      // --- Rooms, Forward-Secrecy Epochs & Room Messages ---
      if (action === "get_room_info") {
        const room = sanitizeRoom(url.searchParams.get("room"));
        if (!room) return json({ error: m.invalidRoom }, 400);

        const row = db
          .query<
            {
              room: string;
              room_name: string | null;
              created_by: string;
              password_hash: string | null;
              current_epoch: number;
            },
            [string]
          >(
            "SELECT room, room_name, created_by, password_hash, current_epoch FROM rooms WHERE room = ?1",
          )
          .get(room);

        if (!row)
          return json({
            exists: false,
            room,
            has_password: false,
            is_owner: false,
            current_epoch: 0,
          });
        return json({
          exists: true,
          room: row.room,
          room_name: row.room_name,
          has_password: Boolean(row.password_hash),
          is_owner: row.created_by === user.id,
          current_epoch: row.current_epoch,
        });
      }

      if (action === "create_or_update_room") {
        const rawCode = String(body.room ?? "").trim();
        const room = rawCode
          ? sanitizeRoom(rawCode)
          : randomBytes(4).toString("hex");
        if (!room) return json({ error: m.invalidRoom }, 400);

        const roomName = sanitizeText(body.room_name, 100) || null;
        const roomPassword =
          body.room_password == null ? "" : String(body.room_password);
        const now = Math.floor(Date.now() / 1000);

        const existing = db
          .query<{ created_by: string }, [string]>(
            "SELECT created_by FROM rooms WHERE room = ?1",
          )
          .get(room);

        if (!existing) {
          const hash =
            roomPassword !== "" ? Bun.password.hashSync(roomPassword) : null;
          db.query(
            `
            INSERT INTO rooms (room, room_name, password_hash, created_by, current_epoch, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
          `,
          ).run(room, roomName, hash, user.id, now);
          const ep = advanceRoomEpoch(room, user.id);
          touchRoom(room);
          publishRoom(srv, room, { type: "room_updated" });
          return json({
            status: "ok",
            created: true,
            room,
            room_name: roomName,
            has_password: Boolean(hash),
            epoch: ep.epoch,
            keyMaterialB64: ep.keyMaterialB64,
          });
        }

        if (existing.created_by !== user.id) {
          return json({ error: m.onlyCreator }, 403);
        }

        const hash =
          roomPassword !== "" ? Bun.password.hashSync(roomPassword) : null;
        db.query(
          "UPDATE rooms SET room_name = ?1, password_hash = ?2, updated_at = ?3 WHERE room = ?4",
        ).run(roomName, hash, now, room);
        const ep = advanceRoomEpoch(room, user.id);
        touchRoom(room);
        publishRoom(srv, room, {
          type: "room_updated",
          epoch: ep.epoch,
          keyMaterialB64: ep.keyMaterialB64,
        });
        return json({
          status: "ok",
          created: false,
          room,
          room_name: roomName,
          has_password: Boolean(hash),
          epoch: ep.epoch,
          keyMaterialB64: ep.keyMaterialB64,
        });
      }

      if (action === "join_room") {
        const room = sanitizeRoom(body.room);
        if (!room) return json({ error: m.invalidRoom }, 400);
        const pass =
          body.room_password != null ? String(body.room_password) : null;
        if (!verifyRoomPassword(room, pass))
          return json({ error: m.wrongPassword }, 403);

        const now = Math.floor(Date.now() / 1000);
        const existing = db
          .query<{ room: string }, [string]>(
            "SELECT room FROM rooms WHERE room = ?1",
          )
          .get(room);
        if (!existing) {
          db.query(
            `
            INSERT INTO rooms (room, room_name, password_hash, created_by, current_epoch, created_at, updated_at)
            VALUES (?1, NULL, NULL, ?2, 0, ?3, ?3)
          `,
          ).run(room, user.id, now);
        }

        // Rotate epoch on join so the new joiner only gets the new epoch and cannot decrypt past messages
        const ep = advanceRoomEpoch(room, user.id);
        touchPresence(room, user.id, user.username);
        touchRoom(room);

        const sysText = JSON.stringify({
          type: "system",
          text: `${m.joined(user.username)} — ${m.epochRotated(ep.epoch)}`,
          subtype: "join",
        });
        const ins = db
          .query(
            "INSERT INTO messages (room, sender, epoch, message, timestamp) VALUES (?1, 'system', ?2, ?3, ?4)",
          )
          .run(room, ep.epoch, sysText, now);

        const sysMsg = {
          id: Number(ins.lastInsertRowid),
          sender: "system",
          senderName: "system",
          epoch: ep.epoch,
          message: sysText,
          iv: null,
          reply_to: null,
          file_name: null,
          file_size: null,
          file_id: null,
          timestamp: now,
          edited_at: null,
          deleted_at: null,
          reactions: [],
        };

        publishRoom(srv, room, {
          type: "epoch_rotated",
          epoch: ep.epoch,
          keyMaterialB64: ep.keyMaterialB64,
        });
        publishRoom(srv, room, { type: "message", message: sysMsg });
        publishRoom(srv, room, { type: "presence_updated" });

        return json({
          status: "ok",
          room,
          joinedEpoch: ep.epoch,
          keyMaterialB64: ep.keyMaterialB64,
        });
      }

      if (action === "get_epoch_key") {
        const room = sanitizeRoom(url.searchParams.get("room"));
        const epoch = Number(url.searchParams.get("epoch") ?? 0);
        const minAllowedEpoch = Number(url.searchParams.get("minEpoch") ?? 0);
        const pass = url.searchParams.get("room_password");
        if (!room) return json({ error: m.invalidRoom }, 400);
        if (!verifyRoomPassword(room, pass))
          return json({ error: m.wrongPassword }, 403);

        const target = epoch > 0 ? epoch : minAllowedEpoch;
        if (minAllowedEpoch > 0 && target < minAllowedEpoch) {
          return json(
            { error: "Historical epoch access denied for forward secrecy" },
            403,
          );
        }

        const keyData = getRoomEpochKey(room, target, user.id);
        if (!keyData) return json({ error: "Epoch key unavailable" }, 404);
        return json(keyData);
      }

      if (action === "leave_room") {
        const room = sanitizeRoom(body.room);
        if (!room) return json({ error: m.invalidRoom }, 400);
        db.query(
          "DELETE FROM room_presence WHERE room = ?1 AND sender_id = ?2",
        ).run(room, user.id);
        const now = Math.floor(Date.now() / 1000);
        const roomRow = db
          .query<{ current_epoch: number }, [string]>(
            "SELECT current_epoch FROM rooms WHERE room = ?1",
          )
          .get(room);
        const epNum = roomRow?.current_epoch ?? 1;
        const sysText = JSON.stringify({
          type: "system",
          text: m.left(user.username),
          subtype: "leave",
        });
        const ins = db
          .query(
            "INSERT INTO messages (room, sender, epoch, message, timestamp) VALUES (?1, 'system', ?2, ?3, ?4)",
          )
          .run(room, epNum, sysText, now);

        publishRoom(srv, room, {
          type: "message",
          message: {
            id: Number(ins.lastInsertRowid),
            sender: "system",
            senderName: "system",
            epoch: epNum,
            message: sysText,
            iv: null,
            reply_to: null,
            file_name: null,
            file_size: null,
            file_id: null,
            timestamp: now,
            edited_at: null,
            deleted_at: null,
            reactions: [],
          },
        });
        publishRoom(srv, room, { type: "presence_updated" });
        return json({ status: "ok" });
      }

      if (action === "send_message") {
        const room = sanitizeRoom(body.room);
        const message = sanitizeText(body.message, config.maxMessageLength * 2);
        const iv = typeof body.iv === "string" ? body.iv.slice(0, 128) : null;
        const replyTo =
          typeof body.reply_to === "number" && body.reply_to > 0
            ? Math.floor(body.reply_to)
            : null;
        const pass =
          body.room_password != null ? String(body.room_password) : null;

        if (!room || !message) return json({ error: m.missingParams }, 400);
        if (!verifyRoomPassword(room, pass))
          return json({ error: m.wrongPassword }, 403);

        const roomRow = db
          .query<{ current_epoch: number }, [string]>(
            "SELECT current_epoch FROM rooms WHERE room = ?1",
          )
          .get(room);
        const epNum = roomRow?.current_epoch ?? 1;
        const now = Math.floor(Date.now() / 1000);

        const ins = db
          .query(
            "INSERT INTO messages (room, sender, epoch, message, iv, reply_to, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
          )
          .run(room, user.id, epNum, message, iv, replyTo, now);
        touchRoom(room);

        const msgObj = {
          id: Number(ins.lastInsertRowid),
          sender: user.id,
          senderName: user.username,
          epoch: epNum,
          message,
          iv,
          reply_to: replyTo,
          file_name: null,
          file_size: null,
          file_id: null,
          timestamp: now,
          edited_at: null,
          deleted_at: null,
          reactions: [],
        };
        publishRoom(srv, room, { type: "message", message: msgObj });
        return json({ status: "ok", id: msgObj.id });
      }

      if (action === "edit_message") {
        const room = sanitizeRoom(body.room);
        const id = Number(body.id ?? 0);
        const message = sanitizeText(body.message, config.maxMessageLength * 2);
        const iv = typeof body.iv === "string" ? body.iv.slice(0, 128) : null;
        if (!room || !id || !message)
          return json({ error: m.missingParams }, 400);

        const row = db
          .query<{ id: number; sender: string }, [string, number]>(
            "SELECT id, sender FROM messages WHERE room = ?1 AND id = ?2",
          )
          .get(room, id);
        if (!row) return json({ error: m.messageNotFound }, 404);
        if (row.sender !== user.id)
          return json({ error: m.forbiddenEdit }, 403);

        const now = Math.floor(Date.now() / 1000);
        db.query(
          "UPDATE messages SET message = ?1, iv = ?2, edited_at = ?3 WHERE room = ?4 AND id = ?5",
        ).run(message, iv, now, room, id);
        publishRoom(srv, room, {
          type: "message_edited",
          id,
          message,
          iv,
          edited_at: now,
        });
        return json({ status: "ok", edited_at: now });
      }

      if (action === "delete_message") {
        const room = sanitizeRoom(body.room);
        const id = Number(body.id ?? 0);
        if (!room || !id) return json({ error: m.missingParams }, 400);

        const row = db
          .query<{ id: number; sender: string }, [string, number]>(
            "SELECT id, sender FROM messages WHERE room = ?1 AND id = ?2",
          )
          .get(room, id);
        if (!row) return json({ error: m.messageNotFound }, 404);
        if (row.sender !== user.id)
          return json({ error: m.forbiddenEdit }, 403);

        const now = Math.floor(Date.now() / 1000);
        db.query(
          "UPDATE messages SET deleted_at = ?1, message = '' WHERE room = ?2 AND id = ?3",
        ).run(now, room, id);
        publishRoom(srv, room, {
          type: "message_deleted",
          id,
          deleted_at: now,
        });
        return json({ status: "ok", deleted_at: now });
      }

      if (action === "toggle_reaction") {
        const room = sanitizeRoom(body.room);
        const messageId = Number(body.messageId ?? 0);
        const emoji = sanitizeEmoji(body.emoji);
        if (!room || !messageId || !emoji)
          return json({ error: m.missingParams }, 400);

        const existing = db
          .query<{ emoji: string }, [string, number, string, string]>(
            "SELECT emoji FROM message_reactions WHERE room = ?1 AND message_id = ?2 AND user_id = ?3 AND emoji = ?4",
          )
          .get(room, messageId, user.id, emoji);

        if (existing) {
          db.query(
            "DELETE FROM message_reactions WHERE room = ?1 AND message_id = ?2 AND user_id = ?3 AND emoji = ?4",
          ).run(room, messageId, user.id, emoji);
        } else {
          db.query(
            "INSERT OR IGNORE INTO message_reactions (room, message_id, user_id, emoji) VALUES (?1, ?2, ?3, ?4)",
          ).run(room, messageId, user.id, emoji);
        }

        const reactions = getReactionsMap(room, [messageId])[messageId] ?? [];
        publishRoom(srv, room, {
          type: "reactions_updated",
          messageId,
          reactions,
        });
        return json({ status: "ok", reactions });
      }

      if (action === "poll_messages") {
        const room = sanitizeRoom(url.searchParams.get("room"));
        const sinceId = Number(url.searchParams.get("since_id") ?? 0);
        const pass = url.searchParams.get("room_password");
        if (!room) return json({ messages: [], activeUsers: [] });
        if (!verifyRoomPassword(room, pass))
          return json({ error: m.wrongPassword }, 403);

        touchPresence(room, user.id, user.username);
        touchRoom(room);

        const rows = db
          .query<
            {
              id: number;
              sender: string;
              senderName: string | null;
              epoch: number;
              message: string;
              iv: string | null;
              reply_to: number | null;
              file_name: string | null;
              file_size: number | null;
              file_id: string | null;
              timestamp: number;
              edited_at: number | null;
              deleted_at: number | null;
            },
            [string, number]
          >(
            `
            SELECT m.id, m.sender, u.username AS senderName, m.epoch, m.message, m.iv, m.reply_to,
                   m.file_name, m.file_size, m.file_id, m.timestamp, m.edited_at, m.deleted_at
            FROM messages m
            LEFT JOIN users u ON u.id = m.sender
            WHERE m.room = ?1 AND m.id > ?2
            ORDER BY m.id ASC LIMIT 100
          `,
          )
          .all(room, sinceId);

        const rxMap = getReactionsMap(
          room,
          rows.map((r) => r.id),
        );
        const messages = rows.map((r) => ({
          ...r,
          reactions: rxMap[r.id] ?? [],
        }));

        const activeUsers = db
          .query(
            "SELECT sender_id, username, last_seen FROM room_presence WHERE room = ?1 AND last_seen >= ?2 ORDER BY username ASC",
          )
          .all(room, Math.floor(Date.now() / 1000) - 120);

        return json({ messages, activeUsers });
      }

      if (action === "upload_chunk") {
        const room = sanitizeRoom(body.room);
        const fileId = sanitizeFileId(body.file_id);
        const chunkIndex = Number(body.chunk_index ?? 0);
        const totalChunks = Number(body.total_chunks ?? 0);
        const fileName =
          sanitizeText(body.file_name || "file", config.maxFileNameLength) ||
          "file";
        const fileSize = Number(body.file_size ?? 0);
        const mimeType =
          sanitizeText(body.mime_type || "application/octet-stream", 100) ||
          "application/octet-stream";
        const pass =
          body.room_password != null ? String(body.room_password) : null;
        const chunk = formData?.get("chunk_data");

        if (!room || !fileId || !(chunk instanceof Blob))
          return json({ error: m.missingParams }, 400);
        if (!verifyRoomPassword(room, pass))
          return json({ error: m.wrongPassword }, 403);
        if (fileSize > config.maxFileSize)
          return json({ error: m.fileTooLarge }, 400);
        if (chunk.size > config.maxChunkSize)
          return json({ error: m.chunkTooLarge }, 400);

        const dir = join(config.uploadDir, room, fileId);
        mkdirSync(dir, { recursive: true });
        writeFileSync(
          join(dir, `chunk_${chunkIndex}`),
          Buffer.from(await chunk.arrayBuffer()),
        );

        const now = Math.floor(Date.now() / 1000);
        const roomRow = db
          .query<{ current_epoch: number }, [string]>(
            "SELECT current_epoch FROM rooms WHERE room = ?1",
          )
          .get(room);
        const epNum = roomRow?.current_epoch ?? 1;
        let newMsg: Record<string, unknown> | null = null;

        db.transaction(() => {
          if (chunkIndex === 0) {
            db.query(
              `
              INSERT OR IGNORE INTO file_transfers (file_id, room, sender, file_name, file_size, mime_type, total_chunks, timestamp)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            `,
            ).run(
              fileId,
              room,
              user.id,
              fileName,
              fileSize,
              mimeType,
              totalChunks,
              now,
            );

            const ins = db
              .query(
                `
              INSERT INTO messages (room, sender, epoch, message, file_name, file_size, file_id, timestamp)
              VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, ?7)
            `,
              )
              .run(room, user.id, epNum, fileName, fileSize, fileId, now);

            newMsg = {
              id: Number(ins.lastInsertRowid),
              sender: user.id,
              senderName: user.username,
              epoch: epNum,
              message: "",
              iv: null,
              reply_to: null,
              file_name: fileName,
              file_size: fileSize,
              file_id: fileId,
              timestamp: now,
              edited_at: null,
              deleted_at: null,
              reactions: [],
            };
          }

          let complete = true;
          for (let i = 0; i < totalChunks; i++) {
            if (!existsSync(join(dir, `chunk_${i}`))) {
              complete = false;
              break;
            }
          }
          if (complete) {
            const parts: Buffer[] = [];
            for (let i = 0; i < totalChunks; i++) {
              parts.push(readFileSync(join(dir, `chunk_${i}`)));
            }
            writeFileSync(
              join(config.uploadDir, room, `${fileId}.bin`),
              Buffer.concat(parts),
            );
          }
          touchRoom(room);
        })();

        if (newMsg)
          publishRoom(srv, room, { type: "message", message: newMsg });
        return json({ status: "ok" });
      }

      if (action === "download_file") {
        const room = sanitizeRoom(url.searchParams.get("room"));
        const fileId = sanitizeFileId(url.searchParams.get("file_id"));
        const pass = url.searchParams.get("room_password");
        if (!room || !fileId) return json({ error: m.missingParams }, 400);
        if (!verifyRoomPassword(room, pass))
          return json({ error: m.wrongPassword }, 403);

        const meta = db
          .query<{ file_name: string; mime_type: string }, [string, string]>(
            "SELECT file_name, mime_type FROM file_transfers WHERE room = ?1 AND file_id = ?2",
          )
          .get(room, fileId);
        const binPath = join(config.uploadDir, room, `${fileId}.bin`);
        if (!meta || !existsSync(binPath))
          return json({ error: m.fileNotFound }, 404);

        const safeName = meta.file_name.replace(/["\r\n]/g, "_");
        return new Response(Bun.file(binPath), {
          headers: {
            "Content-Type": meta.mime_type,
            "Content-Disposition": `attachment; filename="${safeName}"`,
          },
        });
      }

      return json({ error: "Unknown action" }, 400);
    } catch (err) {
      return json({ error: config.debug ? String(err) : m.serverError }, 500);
    }
  },
});

console.log(
  `BatelNagogram server listening on http://localhost:${server.port}`,
);
