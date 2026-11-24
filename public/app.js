// public/app.js
import { applyLang, getLang, STRINGS } from "./i18n.js";
import {
  decryptAesGcm,
  deriveDmAesKey,
  deriveEpochAesKey,
  encryptAesGcm,
  getOrCreateEcdhKeyPair,
} from "./crypto.js";

const MAX_FILE_SIZE = 100 * 1024 * 1024;
const CHUNK_SIZE = 10 * 1024 * 1024;
const QUICK_REACTIONS = ["👍", "❤️", "😂", "🔥"];

let lang = getLang();
applyLang(lang);

let authSession = null; // { user: { id, username }, sessionToken }
let ecdhKeyPair = null; // { publicKeyJwk, privateKey }
let roomHex = null;
let roomMeta = null;
let roomPassword = "";
let joinedEpoch = 1;

const epochKeyCache = new Map(); // `${roomHex}:${epoch}` -> CryptoKey
const epochKeyMaterialCache = new Map(); // `${roomHex}:${epoch}` -> keyMaterialB64
const dmKeyCache = new Map(); // peerUserId -> CryptoKey
const dmPeerPubkeys = new Map(); // peerUserId -> publicKeyJwk

let lastMessageId = 0;
let lastDmId = 0;
let activeDmPeer = null; // { id, username, public_key_jwk }
let replyToMsg = null;
let ws = null;
let pollTimer = null;
let pingTimer = null;
let typingTimer = null;
const renderedMsgIds = new Set();
const renderedDmIds = new Set();
const messageCache = new Map(); // id -> plaintext string

const el = {
  roomTitle: document.getElementById("roomTitle"),
  roomIdDisplay: document.getElementById("roomIdDisplay"),
  roomEpochBadge: document.getElementById("roomEpochBadge"),
  roomLockState: document.getElementById("roomLockState"),
  langSwitchBtn: document.getElementById("langSwitchBtn"),
  dmDrawerBtn: document.getElementById("dmDrawerBtn"),
  switchRoomBtn: document.getElementById("switchRoomBtn"),
  copyLinkBtn: document.getElementById("copyLinkBtn"),
  roomSettingsBtn: document.getElementById("roomSettingsBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  activeUsersList: document.getElementById("activeUsersList"),
  typingIndicator: document.getElementById("typingIndicator"),
  chatContainer: document.getElementById("chatContainer"),
  emptyHint: document.getElementById("emptyHint"),
  replyPreview: document.getElementById("replyPreview"),
  replyText: document.getElementById("replyText"),
  cancelReply: document.getElementById("cancelReply"),
  fileInput: document.getElementById("fileInput"),
  fileBtn: document.getElementById("fileBtn"),
  msgInput: document.getElementById("msgInput"),
  sendBtn: document.getElementById("sendBtn"),
  toastWrap: document.getElementById("toastWrap"),

  authModal: document.getElementById("authModal"),
  modeLoginBtn: document.getElementById("modeLoginBtn"),
  modeRegisterBtn: document.getElementById("modeRegisterBtn"),
  authUsernameInput: document.getElementById("authUsernameInput"),
  authTokenField: document.getElementById("authTokenField"),
  authTokenInput: document.getElementById("authTokenInput"),
  authWarning: document.getElementById("authWarning"),
  tokenRevealBox: document.getElementById("tokenRevealBox"),
  newTokenDisplay: document.getElementById("newTokenDisplay"),
  authSubmitBtn: document.getElementById("authSubmitBtn"),
  tokenContinueBtn: document.getElementById("tokenContinueBtn"),

  joinModal: document.getElementById("joinModal"),
  joinRoomSummary: document.getElementById("joinRoomSummary"),
  joinRoomTargetInput: document.getElementById("joinRoomTargetInput"),
  roomNameField: document.getElementById("roomNameField"),
  joinRoomNameInput: document.getElementById("joinRoomNameInput"),
  roomPasswordField: document.getElementById("roomPasswordField"),
  joinPasswordInput: document.getElementById("joinPasswordInput"),
  joinHint: document.getElementById("joinHint"),
  joinWarning: document.getElementById("joinWarning"),
  generateRoomBtn: document.getElementById("generateRoomBtn"),
  joinSubmitBtn: document.getElementById("joinSubmitBtn"),

  settingsModal: document.getElementById("settingsModal"),
  settingsCloseBtn: document.getElementById("settingsCloseBtn"),
  settingsCancelBtn: document.getElementById("settingsCancelBtn"),
  settingsRoomId: document.getElementById("settingsRoomId"),
  roomNameInput: document.getElementById("roomNameInput"),
  roomPasswordInput: document.getElementById("roomPasswordInput"),
  settingsWarning: document.getElementById("settingsWarning"),
  saveSettingsBtn: document.getElementById("saveSettingsBtn"),

  dmModal: document.getElementById("dmModal"),
  dmModalTitle: document.getElementById("dmModalTitle"),
  dmCloseBtn: document.getElementById("dmCloseBtn"),
  dmPeersList: document.getElementById("dmPeersList"),
  dmMessagesLog: document.getElementById("dmMessagesLog"),
  dmTypingIndicator: document.getElementById("dmTypingIndicator"),
  dmInput: document.getElementById("dmInput"),
  dmSendBtn: document.getElementById("dmSendBtn"),
};

function t() {
  return STRINGS[lang];
}

function showToast(msg, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  el.toastWrap.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s ?? "";
  return d.innerHTML;
}

function formatSize(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatTime(ts) {
  const d = new Date((ts || 0) * 1000);
  return d.toLocaleTimeString(lang === "fa" ? "fa-IR" : "en-US", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function parseRoomInput(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  try {
    if (s.includes("://") || s.includes("?")) {
      const u = new URL(s.startsWith("http") ? s : `https://x/${s}`);
      const qRoom = u.searchParams.get("room") || "";
      const hex = qRoom.toLowerCase().replace(/[^a-f0-9]/g, "");
      if (hex.length === 8) return hex;
    }
  } catch {
    // ignore URL parse error
  }
  const hex = s.toLowerCase().replace(/[^a-f0-9]/g, "");
  return hex.length === 8 ? hex : "";
}

function randomRoomHex() {
  const arr = new Uint8Array(4);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

function getStoredJoinedEpoch(uid, rHex) {
  const raw = localStorage.getItem(`bn_joined_epoch_${uid}_${rHex}`);
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 1;
}

function setStoredJoinedEpoch(uid, rHex, ep) {
  joinedEpoch = ep;
  localStorage.setItem(`bn_joined_epoch_${uid}_${rHex}`, String(ep));
  if (el.roomEpochBadge) {
    el.roomEpochBadge.textContent = t().epochLabel(ep);
  }
}

async function apiPost(payload) {
  const headers = { "Content-Type": "application/json" };
  if (authSession?.sessionToken)
    headers.Authorization = `Bearer ${authSession.sessionToken}`;
  const res = await fetch(`/api?lang=${lang}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ ...payload, lang }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiGet(params) {
  const headers = {};
  if (authSession?.sessionToken)
    headers.Authorization = `Bearer ${authSession.sessionToken}`;
  const qs = new URLSearchParams({ ...params, lang });
  const res = await fetch(`/api?${qs.toString()}`, { headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function getEpochKey(epoch) {
  const epNum = Number(epoch) || 1;
  if (epNum < joinedEpoch) {
    return null; // Enforce forward secrecy: newcomer cannot unlock older epochs
  }
  const cacheKey = `${roomHex}:${epNum}`;
  if (epochKeyCache.has(cacheKey)) {
    return epochKeyCache.get(cacheKey);
  }
  let mat = epochKeyMaterialCache.get(cacheKey);
  if (!mat) {
    const data = await apiGet({
      action: "get_epoch_key",
      room: roomHex,
      epoch: String(epNum),
      minEpoch: String(joinedEpoch),
      room_password: roomPassword,
    });
    mat = data.keyMaterialB64;
    epochKeyMaterialCache.set(cacheKey, mat);
  }
  const key = await deriveEpochAesKey(roomHex, epNum, mat, roomPassword);
  epochKeyCache.set(cacheKey, key);
  return key;
}

async function getDmKey(peerId, peerPubkeyJwk = null) {
  if (dmKeyCache.has(peerId)) return dmKeyCache.get(peerId);
  let pub = peerPubkeyJwk || dmPeerPubkeys.get(peerId);
  if (!pub) {
    const info = await apiGet({ action: "get_pubkey", userId: peerId });
    if (!info.public_key_jwk) return null;
    pub = JSON.parse(info.public_key_jwk);
    dmPeerPubkeys.set(peerId, pub);
  }
  const key = await deriveDmAesKey(
    ecdhKeyPair.privateKey,
    pub,
    authSession.user.id,
    peerId,
  );
  dmKeyCache.set(peerId, key);
  return key;
}

function setComposerEnabled(enabled) {
  el.msgInput.disabled = !enabled;
  el.sendBtn.disabled = !enabled;
  el.fileBtn.disabled = !enabled;
  el.msgInput.placeholder = enabled ? t().msgPlaceholder : t().waitingSecure;
}

function showAuthModal(initialMode = "login") {
  let mode = initialMode;
  el.authWarning.style.display = "none";
  el.tokenRevealBox.style.display = "none";
  el.tokenContinueBtn.style.display = "none";
  el.authSubmitBtn.style.display = "inline-flex";

  function syncMode() {
    el.modeLoginBtn.classList.toggle("active-mode", mode === "login");
    el.modeRegisterBtn.classList.toggle("active-mode", mode === "register");
    el.authTokenField.style.display = mode === "login" ? "flex" : "none";
    el.authSubmitBtn.textContent =
      mode === "login" ? t().loginBtn : t().registerBtn;
  }

  el.modeLoginBtn.onclick = () => {
    mode = "login";
    syncMode();
  };
  el.modeRegisterBtn.onclick = () => {
    mode = "register";
    syncMode();
  };

  el.authSubmitBtn.onclick = async () => {
    el.authWarning.style.display = "none";
    const username = el.authUsernameInput.value.trim();
    if (!username) {
      el.authWarning.textContent = t().missingParams;
      el.authWarning.style.display = "block";
      return;
    }
    try {
      if (mode === "register") {
        const res = await apiPost({ action: "register", username });
        authSession = { user: res.user, sessionToken: res.sessionToken };
        sessionStorage.setItem("bn_session", JSON.stringify(authSession));
        el.newTokenDisplay.textContent = res.loginToken;
        el.tokenRevealBox.style.display = "flex";
        el.authSubmitBtn.style.display = "none";
        el.tokenContinueBtn.style.display = "inline-flex";
      } else {
        const loginToken = el.authTokenInput.value.trim();
        const res = await apiPost({ action: "login", username, loginToken });
        authSession = { user: res.user, sessionToken: res.sessionToken };
        sessionStorage.setItem("bn_session", JSON.stringify(authSession));
        el.authModal.classList.remove("show");
        await afterAuthenticated();
      }
    } catch (err) {
      el.authWarning.textContent = err.message;
      el.authWarning.style.display = "block";
    }
  };

  el.tokenContinueBtn.onclick = async () => {
    el.authModal.classList.remove("show");
    await afterAuthenticated();
  };

  syncMode();
  el.authModal.classList.add("show");
}

async function afterAuthenticated() {
  ecdhKeyPair = await getOrCreateEcdhKeyPair(authSession.user.id);
  await apiPost({
    action: "publish_pubkey",
    publicKeyJwk: JSON.stringify(ecdhKeyPair.publicKeyJwk),
  });

  el.switchRoomBtn.hidden = false;
  el.dmDrawerBtn.hidden = false;
  el.logoutBtn.hidden = false;

  const urlRoom = parseRoomInput(
    new URLSearchParams(location.search).get("room") || "",
  );
  if (urlRoom) {
    openJoinModal(urlRoom);
  } else {
    openJoinModal(randomRoomHex());
  }
}

async function openJoinModal(suggestedHex) {
  el.joinWarning.style.display = "none";
  el.joinRoomTargetInput.value = suggestedHex || "";
  el.joinPasswordInput.value = "";
  el.joinNameField.style.display = "flex";

  const candidate = parseRoomInput(suggestedHex);
  if (candidate) {
    try {
      const info = await apiGet({ action: "get_room_info", room: candidate });
      el.joinRoomSummary.textContent = info.exists
        ? `${info.room_name || info.room} (${t().epochLabel(info.current_epoch)})`
        : `${candidate} — ${t().joinCreateTitle}`;
      el.joinRoomNameInput.value = info.room_name || "";
      el.joinNameField.style.display =
        info.exists && !info.is_owner ? "none" : "flex";
    } catch {
      el.joinRoomSummary.textContent = t().checkingRoom;
    }
  } else {
    el.joinRoomSummary.textContent = t().joinCreateTitle;
  }

  el.joinModal.classList.add("show");
}

el.generateRoomBtn.onclick = () => {
  el.joinRoomTargetInput.value = randomRoomHex();
};

el.joinSubmitBtn.onclick = async () => {
  el.joinWarning.style.display = "none";
  const targetHex =
    parseRoomInput(el.joinRoomTargetInput.value) || randomRoomHex();
  const rName = el.joinRoomNameInput.value.trim();
  const rPass = el.joinPasswordInput.value;

  try {
    const info = await apiGet({ action: "get_room_info", room: targetHex });
    let ep = 1;
    let keyMat = null;

    if (!info.exists) {
      const created = await apiPost({
        action: "create_or_update_room",
        room: targetHex,
        room_name: rName,
        room_password: rPass,
      });
      ep = created.epoch;
      keyMat = created.keyMaterialB64;
    } else {
      const joined = await apiPost({
        action: "join_room",
        room: targetHex,
        room_password: rPass,
      });
      ep = joined.joinedEpoch;
      keyMat = joined.keyMaterialB64;
    }

    roomHex = targetHex;
    roomPassword = rPass;
    const nextUrl = new URL(location.href);
    nextUrl.searchParams.set("room", roomHex);
    history.replaceState({}, "", nextUrl.toString());

    epochKeyCache.clear();
    epochKeyMaterialCache.set(`${roomHex}:${ep}`, keyMat);
    setStoredJoinedEpoch(authSession.user.id, roomHex, ep);

    renderedMsgIds.clear();
    messageCache.clear();
    lastMessageId = 0;
    el.chatContainer.innerHTML = "";
    el.chatContainer.appendChild(el.emptyHint);
    el.emptyHint.style.display = "flex";

    el.joinModal.classList.remove("show");
    await refreshRoomMeta();
    setComposerEnabled(true);
    connectWs();
    await pollRoom();
    startPolling();
  } catch (err) {
    el.joinWarning.textContent = err.message;
    el.joinWarning.style.display = "block";
  }
};

async function refreshRoomMeta() {
  if (!roomHex) return;
  const info = await apiGet({ action: "get_room_info", room: roomHex });
  roomMeta = info;
  el.roomTitle.textContent = info.room_name || t().defaultRoomTitle;
  el.roomIdDisplay.textContent = roomHex;
  el.roomEpochBadge.textContent = t().epochLabel(joinedEpoch);
  el.roomLockState.innerHTML = info.has_password
    ? `<span class="locked-badge">🔒</span>`
    : "";
}

function connectWs() {
  if (ws) {
    try {
      ws.close();
    } catch {}
    ws = null;
  }
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const qs = new URLSearchParams({
    token: authSession.sessionToken,
    room: roomHex || "",
    room_password: roomPassword || "",
  });
  ws = new WebSocket(`${proto}//${location.host}/ws?${qs.toString()}`);

  ws.onmessage = async (ev) => {
    try {
      const data = JSON.parse(ev.data);
      if (data.type === "message") {
        await renderRoomMessage(data.message);
        if (data.message.id > lastMessageId) lastMessageId = data.message.id;
      } else if (data.type === "epoch_rotated") {
        if (data.keyMaterialB64) {
          epochKeyMaterialCache.set(
            `${roomHex}:${data.epoch}`,
            data.keyMaterialB64,
          );
        }
        if (el.roomEpochBadge) {
          el.roomEpochBadge.textContent = t().epochLabel(joinedEpoch);
        }
      } else if (data.type === "message_edited") {
        await handleRemoteEdit(data);
      } else if (data.type === "message_deleted") {
        handleRemoteDelete(data.id);
      } else if (data.type === "reactions_updated") {
        renderReactions(data.messageId, data.reactions || []);
      } else if (data.type === "presence_updated") {
        await pollRoom();
      } else if (data.type === "room_updated") {
        await refreshRoomMeta();
      } else if (data.type === "typing") {
        handleTypingEvent(data);
      } else if (data.type === "dm") {
        if (
          activeDmPeer &&
          (data.message.sender_id === activeDmPeer.id ||
            data.message.recipient_id === activeDmPeer.id)
        ) {
          await renderDmMessage(data.message);
          if (data.message.id > lastDmId) lastDmId = data.message.id;
        } else if (data.message.sender_id !== authSession.user.id) {
          showToast(`✉ ${data.message.senderName}`, "info");
        }
      } else if (data.type === "dm_edited") {
        await handleRemoteDmEdit(data);
      } else if (data.type === "dm_deleted") {
        handleRemoteDmDelete(data.id);
      }
    } catch {
      // ignore frame error
    }
  };

  clearInterval(pingTimer);
  pingTimer = setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "ping" }));
    }
  }, 25000);
}

function handleTypingEvent(data) {
  if (data.fromUserId === authSession.user.id) return;
  const txt = data.isTyping ? t().typingOne(data.fromUsername) : "";
  if (data.targetType === "dm") {
    el.dmTypingIndicator.textContent = txt;
  } else {
    el.typingIndicator.textContent = txt;
  }
}

function sendTypingSignal(isTyping, targetType = "room", recipientId = null) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(
    JSON.stringify({ type: "typing", isTyping, targetType, recipientId }),
  );
}

async function decodeRoomMessageText(msg) {
  if (msg.deleted_at) return t().deletedText;
  if (msg.sender === "system") {
    try {
      const parsed = JSON.parse(msg.message);
      return parsed.text || msg.message;
    } catch {
      return msg.message;
    }
  }
  if (!msg.iv) return msg.message;

  const ep = Number(msg.epoch) || 1;
  if (ep < joinedEpoch) {
    return t().pastEpochLocked;
  }

  try {
    const key = await getEpochKey(ep);
    if (!key) return t().pastEpochLocked;
    return await decryptAesGcm(key, msg.message, msg.iv);
  } catch {
    return t().decryptFailed;
  }
}

function renderReactions(messageId, reactions) {
  const card = el.chatContainer.querySelector(`[data-msg-id="${messageId}"]`);
  if (!card) return;
  let row = card.querySelector(".reactions-row");
  if (!row) {
    row = document.createElement("div");
    row.className = "reactions-row";
    card.insertBefore(row, card.querySelector(".meta"));
  }
  row.innerHTML = "";

  for (const rx of reactions) {
    const btn = document.createElement("button");
    btn.type = "button";
    const mine =
      Array.isArray(rx.users) && rx.users.includes(authSession.user.id);
    btn.className = `reaction-chip ${mine ? "active" : ""}`;
    btn.textContent = `${rx.emoji} ${rx.count}`;
    btn.onclick = () => toggleReaction(messageId, rx.emoji);
    row.appendChild(btn);
  }

  const picker = document.createElement("span");
  picker.className = "reaction-picker";
  for (const em of QUICK_REACTIONS) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = em;
    b.onclick = () => toggleReaction(messageId, em);
    picker.appendChild(b);
  }
  row.appendChild(picker);
}

async function toggleReaction(messageId, emoji) {
  try {
    await apiPost({
      action: "toggle_reaction",
      room: roomHex,
      messageId,
      emoji,
    });
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function handleRemoteEdit(data) {
  const card = el.chatContainer.querySelector(`[data-msg-id="${data.id}"]`);
  if (!card) return;
  const textEl = card.querySelector(".text");
  if (!textEl) return;
  const decoded = await decodeRoomMessageText({
    id: data.id,
    sender: authSession.user.id,
    epoch: joinedEpoch,
    message: data.message,
    iv: data.iv,
  });
  messageCache.set(data.id, decoded);
  textEl.textContent = decoded;
  if (!card.querySelector(".edited-tag")) {
    const tag = document.createElement("span");
    tag.className = "edited-tag";
    tag.textContent = t().editedLabel;
    textEl.appendChild(tag);
  }
}

function handleRemoteDelete(id) {
  const card = el.chatContainer.querySelector(`[data-msg-id="${id}"]`);
  if (!card) return;
  card.classList.add("deleted");
  const textEl = card.querySelector(".text");
  if (textEl) textEl.textContent = t().deletedText;
}

async function renderRoomMessage(msg) {
  if (renderedMsgIds.has(msg.id)) return;
  renderedMsgIds.add(msg.id);
  el.emptyHint.style.display = "none";

  const isSystem = msg.sender === "system";
  const isSelf = msg.sender === authSession.user.id;
  const div = document.createElement("div");
  div.className = `message ${isSystem ? "system" : isSelf ? "self" : "other"} ${msg.deleted_at ? "deleted" : ""}`;
  div.dataset.msgId = String(msg.id);

  if (isSystem) {
    div.textContent = await decodeRoomMessageText(msg);
    el.chatContainer.appendChild(div);
    el.chatContainer.scrollTop = el.chatContainer.scrollHeight;
    return;
  }

  if (msg.reply_to && messageCache.has(msg.reply_to)) {
    const q = document.createElement("div");
    q.className = "quoted-reply";
    q.textContent = `${t().replyPrefix}: ${messageCache.get(msg.reply_to)}`;
    div.appendChild(q);
  }

  if (msg.file_id && msg.file_name) {
    const link = document.createElement("a");
    link.className = "file-link";
    link.href = `/api?action=download_file&room=${encodeURIComponent(roomHex)}&file_id=${encodeURIComponent(msg.file_id)}&room_password=${encodeURIComponent(roomPassword)}&token=${encodeURIComponent(authSession.sessionToken)}`;
    link.download = msg.file_name;
    link.innerHTML = `<div class="file-name">${escapeHtml(msg.file_name)}</div><div class="file-size">${formatSize(msg.file_size)}</div>`;
    div.appendChild(link);
  } else {
    const textEl = document.createElement("div");
    textEl.className = "text";
    const decoded = await decodeRoomMessageText(msg);
    messageCache.set(msg.id, decoded);
    textEl.textContent = decoded;
    if (msg.edited_at && !msg.deleted_at) {
      const ed = document.createElement("span");
      ed.className = "edited-tag";
      ed.textContent = t().editedLabel;
      textEl.appendChild(ed);
    }
    div.appendChild(textEl);
  }

  const meta = document.createElement("div");
  meta.className = "meta";

  const left = document.createElement("span");
  left.className = "meta-left";
  left.innerHTML = `<span class="name-badge">${escapeHtml(msg.senderName || msg.sender)}</span> <span>${formatTime(msg.timestamp)}</span> <span class="mono">#E${msg.epoch || 1}</span>`;

  const actions = document.createElement("span");
  actions.className = "meta-actions";

  const replyBtn = document.createElement("button");
  replyBtn.type = "button";
  replyBtn.className = "mini-btn";
  replyBtn.textContent = "↩";
  replyBtn.title = t().replyBtnTitle;
  replyBtn.onclick = () => {
    replyToMsg = {
      id: msg.id,
      senderName: msg.senderName || msg.sender,
      preview: messageCache.get(msg.id) || "",
    };
    el.replyText.textContent = `${t().replyPrefix} ${replyToMsg.senderName}: ${replyToMsg.preview.slice(0, 60)}`;
    el.replyPreview.classList.add("show");
  };
  actions.appendChild(replyBtn);

  if (isSelf && !msg.file_id && !msg.deleted_at) {
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "mini-btn";
    editBtn.textContent = "✎";
    editBtn.title = t().editBtn;
    editBtn.onclick = async () => {
      const nextPlain = prompt(t().editPrompt, messageCache.get(msg.id) || "");
      if (!nextPlain || !nextPlain.trim()) return;
      const ep = Number(msg.epoch) || joinedEpoch;
      const key = await getEpochKey(ep);
      if (!key) return;
      const encData = await encryptAesGcm(key, nextPlain.trim());
      await apiPost({
        action: "edit_message",
        room: roomHex,
        id: msg.id,
        message: encData.ciphertext,
        iv: encData.iv,
      });
    };
    actions.appendChild(editBtn);

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "mini-btn";
    delBtn.textContent = "🗑";
    delBtn.title = t().deleteBtn;
    delBtn.onclick = async () => {
      await apiPost({ action: "delete_message", room: roomHex, id: msg.id });
    };
    actions.appendChild(delBtn);
  }

  meta.appendChild(left);
  meta.appendChild(actions);
  div.appendChild(meta);

  el.chatContainer.appendChild(div);
  renderReactions(msg.id, msg.reactions || []);
  el.chatContainer.scrollTop = el.chatContainer.scrollHeight;
}

function renderActiveUsers(users) {
  el.activeUsersList.innerHTML = "";
  if (!users || !users.length) {
    const s = document.createElement("span");
    s.className = "user-pill muted";
    s.textContent = t().noActiveUsers;
    el.activeUsersList.appendChild(s);
    return;
  }
  for (const u of users) {
    const isSelf = u.sender_id === authSession.user.id;
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = `user-pill ${isSelf ? "self" : ""}`;
    pill.textContent = isSelf ? `${u.username} ★` : `✉ ${u.username}`;
    if (!isSelf) {
      pill.onclick = () =>
        openDmModal({ id: u.sender_id, username: u.username });
    }
    el.activeUsersList.appendChild(pill);
  }
}

async function pollRoom() {
  if (!roomHex || !authSession) return;
  try {
    const data = await apiGet({
      action: "poll_messages",
      room: roomHex,
      since_id: String(lastMessageId),
      room_password: roomPassword,
    });
    renderActiveUsers(data.activeUsers || []);
    for (const m of data.messages || []) {
      await renderRoomMessage(m);
      if (m.id > lastMessageId) lastMessageId = m.id;
    }
  } catch {
    // ignore transient poll failure
  }
}

function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(pollRoom, 2500);
}

async function sendRoomMessage() {
  const plain = el.msgInput.value.trim();
  if (!plain || !roomHex) return;
  const key = await getEpochKey(joinedEpoch);
  if (!key) {
    showToast(t().decryptFailed, "error");
    return;
  }
  const encData = await encryptAesGcm(key, plain);
  const replyId = replyToMsg?.id ?? null;

  el.msgInput.value = "";
  el.msgInput.style.height = "auto";
  replyToMsg = null;
  el.replyPreview.classList.remove("show");
  sendTypingSignal(false, "room");

  try {
    await apiPost({
      action: "send_message",
      room: roomHex,
      message: encData.ciphertext,
      iv: encData.iv,
      reply_to: replyId,
      room_password: roomPassword,
    });
  } catch (err) {
    showToast(err.message, "error");
  }
}

// --- Private Messages (DMs) ---
async function openDmModal(preselectPeer = null) {
  el.dmModal.classList.add("show");
  const { users } = await apiGet({ action: "list_users" });
  el.dmPeersList.innerHTML = "";

  if (!users || !users.length) {
    el.dmPeersList.innerHTML = `<div class="hint">${escapeHtml(t().noDmPeers)}</div>`;
    return;
  }

  for (const u of users) {
    if (u.public_key_jwk) {
      dmPeerPubkeys.set(u.id, JSON.parse(u.public_key_jwk));
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "dm-peer-btn";
    btn.textContent = u.username;
    btn.dataset.peerId = u.id;
    btn.onclick = () => selectDmPeer(u);
    el.dmPeersList.appendChild(btn);
  }

  const target = preselectPeer
    ? users.find((x) => x.id === preselectPeer.id) || preselectPeer
    : users[0];
  await selectDmPeer(target);
}

async function selectDmPeer(peer) {
  activeDmPeer = peer;
  lastDmId = 0;
  renderedDmIds.clear();
  el.dmMessagesLog.innerHTML = "";
  el.dmModalTitle.textContent = `${t().privateMessages} — ${peer.username}`;
  el.dmInput.disabled = false;
  el.dmSendBtn.disabled = false;

  el.dmPeersList.querySelectorAll(".dm-peer-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.peerId === peer.id);
  });

  await pollDms();
}

async function renderDmMessage(dm) {
  if (renderedDmIds.has(dm.id)) return;
  renderedDmIds.add(dm.id);

  const isSelf = dm.sender_id === authSession.user.id;
  const peerId = isSelf ? dm.recipient_id : dm.sender_id;
  const div = document.createElement("div");
  div.className = `message ${isSelf ? "self" : "other"} ${dm.deleted_at ? "deleted" : ""}`;
  div.dataset.dmId = String(dm.id);

  const textEl = document.createElement("div");
  textEl.className = "text";

  if (dm.deleted_at) {
    textEl.textContent = t().deletedText;
  } else {
    try {
      const key = await getDmKey(peerId, dm.public_key_jwk || null);
      textEl.textContent = key
        ? await decryptAesGcm(key, dm.message, dm.iv)
        : t().decryptFailed;
    } catch {
      textEl.textContent = t().decryptFailed;
    }
    if (dm.edited_at) {
      const ed = document.createElement("span");
      ed.className = "edited-tag";
      ed.textContent = t().editedLabel;
      textEl.appendChild(ed);
    }
  }
  div.appendChild(textEl);

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.innerHTML = `<span class="meta-left"><span class="name-badge">${escapeHtml(dm.senderName)}</span> <span>${formatTime(dm.timestamp)}</span></span>`;

  if (isSelf && !dm.deleted_at) {
    const act = document.createElement("span");
    act.className = "meta-actions";

    const eb = document.createElement("button");
    eb.type = "button";
    eb.className = "mini-btn";
    eb.textContent = "✎";
    eb.onclick = async () => {
      const nextPlain = prompt(
        t().editPrompt,
        textEl.firstChild?.textContent || "",
      );
      if (!nextPlain || !nextPlain.trim()) return;
      const key = await getDmKey(peerId);
      if (!key) return;
      const encData = await encryptAesGcm(key, nextPlain.trim());
      await apiPost({
        action: "edit_dm",
        id: dm.id,
        message: encData.ciphertext,
        iv: encData.iv,
      });
    };

    const db = document.createElement("button");
    db.type = "button";
    db.className = "mini-btn";
    db.textContent = "🗑";
    db.onclick = async () => {
      await apiPost({ action: "delete_dm", id: dm.id });
    };

    act.appendChild(eb);
    act.appendChild(db);
    meta.appendChild(act);
  }

  div.appendChild(meta);
  el.dmMessagesLog.appendChild(div);
  el.dmMessagesLog.scrollTop = el.dmMessagesLog.scrollHeight;
}

async function handleRemoteDmEdit(data) {
  const card = el.dmMessagesLog.querySelector(`[data-dm-id="${data.id}"]`);
  if (!card) return;
  const textEl = card.querySelector(".text");
  if (!textEl) return;
  const peerId =
    data.sender_id === authSession.user.id ? data.recipient_id : data.sender_id;
  const key = await getDmKey(peerId);
  textEl.textContent = key
    ? await decryptAesGcm(key, data.message, data.iv)
    : t().decryptFailed;
}

function handleRemoteDmDelete(id) {
  const card = el.dmMessagesLog.querySelector(`[data-dm-id="${id}"]`);
  if (!card) return;
  card.classList.add("deleted");
  const textEl = card.querySelector(".text");
  if (textEl) textEl.textContent = t().deletedText;
}

async function pollDms() {
  if (!activeDmPeer || !authSession) return;
  const data = await apiGet({
    action: "poll_dms",
    peerId: activeDmPeer.id,
    since_id: String(lastDmId),
  });
  for (const dm of data.messages || []) {
    await renderDmMessage(dm);
    if (dm.id > lastDmId) lastDmId = dm.id;
  }
}

async function sendDm() {
  if (!activeDmPeer) return;
  const plain = el.dmInput.value.trim();
  if (!plain) return;
  const key = await getDmKey(activeDmPeer.id);
  if (!key) {
    showToast(t().decryptFailed, "error");
    return;
  }
  const encData = await encryptAesGcm(key, plain);
  el.dmInput.value = "";
  sendTypingSignal(false, "dm", activeDmPeer.id);
  await apiPost({
    action: "send_dm",
    recipientId: activeDmPeer.id,
    message: encData.ciphertext,
    iv: encData.iv,
  });
}

// --- Chunked File Upload ---
el.fileBtn.onclick = () => el.fileInput.click();
el.fileInput.onchange = async () => {
  const files = Array.from(el.fileInput.files || []);
  el.fileInput.value = "";
  for (const f of files) {
    if (f.size > MAX_FILE_SIZE) {
      showToast(t().fileTooLarge, "error");
      continue;
    }
    const fileId = `f_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const totalChunks = Math.max(1, Math.ceil(f.size / CHUNK_SIZE));
    for (let idx = 0; idx < totalChunks; idx++) {
      const blob = f.slice(idx * CHUNK_SIZE, (idx + 1) * CHUNK_SIZE);
      const fd = new FormData();
      fd.append("action", "upload_chunk");
      fd.append("room", roomHex);
      fd.append("file_id", fileId);
      fd.append("chunk_index", String(idx));
      fd.append("total_chunks", String(totalChunks));
      fd.append("file_name", f.name);
      fd.append("file_size", String(f.size));
      fd.append("mime_type", f.type || "application/octet-stream");
      fd.append("room_password", roomPassword);
      fd.append("chunk_data", blob);

      const res = await fetch(`/api?lang=${lang}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${authSession.sessionToken}` },
        body: fd,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showToast(err.error || "Upload failed", "error");
        break;
      }
    }
    showToast(t().fileUploaded(f.name), "success");
  }
};

// --- Event Listeners ---
el.langSwitchBtn.onclick = () => {
  lang = lang === "fa" ? "en" : "fa";
  applyLang(lang);
  if (roomHex) refreshRoomMeta();
};

el.dmDrawerBtn.onclick = () => openDmModal(null);
el.dmCloseBtn.onclick = () => el.dmModal.classList.remove("show");
el.dmSendBtn.onclick = sendDm;
el.dmInput.onkeydown = (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendDm();
  } else if (activeDmPeer) {
    sendTypingSignal(true, "dm", activeDmPeer.id);
    clearTimeout(typingTimer);
    typingTimer = setTimeout(
      () => sendTypingSignal(false, "dm", activeDmPeer.id),
      1500,
    );
  }
};

el.switchRoomBtn.onclick = () => openJoinModal(randomRoomHex());
el.copyLinkBtn.onclick = () => {
  if (!roomHex) return;
  const u = new URL(location.href);
  u.searchParams.set("room", roomHex);
  navigator.clipboard?.writeText(u.toString());
  showToast(t().linkCopied, "success");
};
el.roomIdDisplay.onclick = () => el.copyLinkBtn.click();

el.roomSettingsBtn.onclick = () => {
  if (!roomHex) return;
  el.settingsWarning.style.display = "none";
  el.settingsRoomId.textContent = roomHex;
  el.roomNameInput.value = roomMeta?.room_name || "";
  el.roomPasswordInput.value = "";
  el.settingsModal.classList.add("show");
};
el.settingsCloseBtn.onclick = () => el.settingsModal.classList.remove("show");
el.settingsCancelBtn.onclick = () => el.settingsModal.classList.remove("show");

el.saveSettingsBtn.onclick = async () => {
  el.settingsWarning.style.display = "none";
  try {
    const newName = el.roomNameInput.value.trim();
    const newPass = el.roomPasswordInput.value;
    const res = await apiPost({
      action: "create_or_update_room",
      room: roomHex,
      room_name: newName,
      room_password: newPass,
    });
    roomPassword = newPass;
    if (res.epoch && res.keyMaterialB64) {
      epochKeyMaterialCache.set(`${roomHex}:${res.epoch}`, res.keyMaterialB64);
      setStoredJoinedEpoch(authSession.user.id, roomHex, res.epoch);
    }
    el.settingsModal.classList.remove("show");
    await refreshRoomMeta();
    showToast(t().settingsSaved, "success");
  } catch (err) {
    el.settingsWarning.textContent = err.message;
    el.settingsWarning.style.display = "block";
  }
};

el.logoutBtn.onclick = async () => {
  if (roomHex) {
    try {
      await apiPost({ action: "leave_room", room: roomHex });
    } catch {}
  }
  sessionStorage.removeItem("bn_session");
  authSession = null;
  location.reload();
};

el.cancelReply.onclick = () => {
  replyToMsg = null;
  el.replyPreview.classList.remove("show");
};

el.sendBtn.onclick = sendRoomMessage;
el.msgInput.onkeydown = (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendRoomMessage();
  } else if (roomHex) {
    sendTypingSignal(true, "room");
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => sendTypingSignal(false, "room"), 1500);
  }
};

el.msgInput.oninput = () => {
  el.msgInput.style.height = "auto";
  el.msgInput.style.height = `${Math.min(el.msgInput.scrollHeight, 120)}px`;
};

// Boot
(async function init() {
  const saved = sessionStorage.getItem("bn_session");
  if (saved) {
    try {
      authSession = JSON.parse(saved);
      if (authSession?.user?.id && authSession?.sessionToken) {
        await afterAuthenticated();
        return;
      }
    } catch {
      sessionStorage.removeItem("bn_session");
    }
  }
  showAuthModal("login");
})();
