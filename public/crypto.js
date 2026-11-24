// public/crypto.js
const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function deriveEpochAesKey(
  roomHex,
  epoch,
  keyMaterialB64,
  roomPassword = "",
) {
  const passPart =
    roomPassword && roomPassword.length > 0 ? `pw:${roomPassword}` : "nopw";
  const ikm = enc.encode(
    `${roomHex}:epoch:${epoch}:${keyMaterialB64}:${passPart}`,
  );
  const baseKey = await crypto.subtle.importKey("raw", ikm, "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(`batelnagogram-epoch:${roomHex}:${epoch}`),
      iterations: 150_000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptAesGcm(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext),
  );
  return { ciphertext: bytesToB64(new Uint8Array(buf)), iv: bytesToB64(iv) };
}

export async function decryptAesGcm(key, ciphertextB64, ivB64) {
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(ivB64) },
    key,
    b64ToBytes(ciphertextB64),
  );
  return dec.decode(buf);
}

// --- ECDH P-256 keypair & shared key derivation for Private Messages ---
export async function getOrCreateEcdhKeyPair(userId) {
  const storageKey = `bn_ecdh_${userId}`;
  const saved = sessionStorage.getItem(storageKey);
  if (saved) {
    const parsed = JSON.parse(saved);
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      parsed.privateKeyJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    return { publicKeyJwk: parsed.publicKeyJwk, privateKey };
  }

  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  sessionStorage.setItem(
    storageKey,
    JSON.stringify({ publicKeyJwk, privateKeyJwk }),
  );
  return { publicKeyJwk, privateKey: kp.privateKey };
}

export async function deriveDmAesKey(
  myPrivateKey,
  peerPublicKeyJwk,
  myUserId,
  peerUserId,
) {
  const peerPub = await crypto.subtle.importKey(
    "jwk",
    peerPublicKeyJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPub },
    myPrivateKey,
    256,
  );
  const pairSalt = [myUserId, peerUserId].sort().join(":");
  const hkdfKey = await crypto.subtle.importKey("raw", bits, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(`bn-dm:${pairSalt}`),
      info: enc.encode("batelnagogram-dm-aes256gcm"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
