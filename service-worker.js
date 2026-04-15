/**
 * Service Worker (Background Script) - Manifest V3
 *
 * Responsibilities:
 *  - PBKDF2 key derivation from master password (600 000 iterations, SHA-256)
 *  - AES-256-GCM encryption / decryption of the vault
 *  - Holding the session key in chrome.storage.session (cleared on browser close)
 *  - Responding to messages from popup.js and content.js
 *  - Progressive lock-out after repeated failed unlock attempts
 */

"use strict";

// ─── Constants ────────────────────────────────────────────────────────────────
const PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES        = 16;
const IV_BYTES          = 12;
const MAX_ATTEMPTS      = 5;
const LOCKOUT_MS        = 60_000; // 1 minute

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Convert an ArrayBuffer to a base-64 string */
function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/** Convert a base-64 string back to a Uint8Array */
function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/** Encode a plain string as UTF-8 bytes */
const enc = new TextEncoder();
const dec = new TextDecoder();

// ─── Crypto primitives ────────────────────────────────────────────────────────

/**
 * Derive an AES-256-GCM CryptoKey from `masterPassword` + `salt`.
 * The key is marked non-extractable so it can never leave the worker.
 */
async function deriveKey(masterPassword, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name:       "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash:       "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,       // non-extractable
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt `plaintext` (string) with `key`.
 * Returns { iv: <b64>, ciphertext: <b64> }.
 */
async function encryptData(key, plaintext) {
  const iv         = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  return { iv: bufToB64(iv), ciphertext: bufToB64(ciphertext) };
}

/**
 * Decrypt `{ iv, ciphertext }` (both base-64) with `key`.
 * Returns the original plaintext string, or throws on tamper detection.
 */
async function decryptData(key, iv, ciphertext) {
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(iv) },
    key,
    b64ToBuf(ciphertext)
  );
  return dec.decode(plainBuf);
}

// ─── Vault helpers ────────────────────────────────────────────────────────────

/** Load the raw encrypted-vault object from chrome.storage.local */
async function loadEncryptedVault() {
  return new Promise(resolve => {
    chrome.storage.local.get(["vault", "salt"], items => {
      resolve({ vault: items.vault || null, salt: items.salt || null });
    });
  });
}

/** Persist the encrypted vault blob */
async function saveEncryptedVault(blob, saltB64) {
  return new Promise(resolve => {
    chrome.storage.local.set({ vault: blob, salt: saltB64 }, resolve);
  });
}

/** Retrieve the live session key (CryptoKey object) from session storage. */
async function getSessionKey() {
  return new Promise(resolve => {
    chrome.storage.session.get(["sessionKey"], items => {
      resolve(items.sessionKey || null);
    });
  });
}

/** Store a CryptoKey reference in session storage.
 *  NOTE: Chrome serialises CryptoKey objects natively in session storage.
 */
async function setSessionKey(key) {
  return new Promise(resolve => {
    chrome.storage.session.set({ sessionKey: key }, resolve);
  });
}

/** Remove the session key (lock the vault). */
async function clearSessionKey() {
  return new Promise(resolve => {
    chrome.storage.session.remove(["sessionKey"], resolve);
  });
}

/** Decrypt and return the in-memory vault array, or [] on first use. */
async function readVault(key, vaultBlob) {
  if (!vaultBlob) return [];
  const json = await decryptData(key, vaultBlob.iv, vaultBlob.ciphertext);
  return JSON.parse(json);
}

/** Encrypt the vault array and write it back to storage. */
async function writeVault(key, entries, saltB64) {
  const blob = await encryptData(key, JSON.stringify(entries));
  await saveEncryptedVault(blob, saltB64);
}

// ─── Attempt tracking ─────────────────────────────────────────────────────────

async function getAttemptData() {
  return new Promise(resolve => {
    chrome.storage.local.get(["failedAttempts", "lockedUntil"], items => {
      resolve({
        failedAttempts: items.failedAttempts || 0,
        lockedUntil:    items.lockedUntil    || 0,
      });
    });
  });
}

async function setAttemptData(data) {
  return new Promise(resolve => {
    chrome.storage.local.set(data, resolve);
  });
}

async function resetAttempts() {
  return new Promise(resolve => {
    chrome.storage.local.remove(["failedAttempts", "lockedUntil"], resolve);
  });
}

// ─── Password generator ───────────────────────────────────────────────────────

function generatePassword(length = 16) {
  const upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower   = "abcdefghijklmnopqrstuvwxyz";
  const digits  = "0123456789";
  const special = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  const all     = upper + lower + digits + special;

  // Guarantee at least one character of each category
  const required = [
    upper  [crypto.getRandomValues(new Uint32Array(1))[0] % upper.length],
    lower  [crypto.getRandomValues(new Uint32Array(1))[0] % lower.length],
    digits [crypto.getRandomValues(new Uint32Array(1))[0] % digits.length],
    special[crypto.getRandomValues(new Uint32Array(1))[0] % special.length],
  ];

  const remaining = Array.from(
    crypto.getRandomValues(new Uint32Array(length - 4)),
    v => all[v % all.length]
  );

  // Shuffle result using Fisher-Yates
  const result = [...required, ...remaining];
  for (let i = result.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result.join("");
}

// ─── Have I Been Pwned (k-anonymity) ─────────────────────────────────────────

/**
 * Checks a password against the HIBP Pwned Passwords API using k-anonymity.
 * Only the first 5 hex chars of the SHA-1 hash are sent to the server.
 * Returns the number of times the password appeared in breaches (0 = safe).
 */
async function checkBreached(password) {
  const hashBuf  = await crypto.subtle.digest("SHA-1", enc.encode(password));
  const hashHex  = Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" },
  });
  if (!resp.ok) throw new Error("HIBP API error");

  const text = await resp.text();
  for (const line of text.split("\n")) {
    const [hash, count] = line.trim().split(":");
    if (hash === suffix) return parseInt(count, 10);
  }
  return 0;
}

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message).then(sendResponse).catch(err => {
    sendResponse({ success: false, error: err.message });
  });
  return true; // keep message channel open for async response
});

async function handleMessage(message) {
  const { action } = message;

  // ── UNLOCK ──────────────────────────────────────────────────────────────────
  if (action === "unlock") {
    const { masterPassword } = message;

    // Progressive lockout check
    const { failedAttempts, lockedUntil } = await getAttemptData();
    if (Date.now() < lockedUntil) {
      const remaining = Math.ceil((lockedUntil - Date.now()) / 1000);
      return { success: false, error: `Locked. Retry in ${remaining}s.` };
    }

    const { vault, salt } = await loadEncryptedVault();

    let saltBytes;
    if (!salt) {
      // First-time setup: generate and persist a salt
      saltBytes = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
      await saveEncryptedVault(null, bufToB64(saltBytes));
    } else {
      saltBytes = b64ToBuf(salt);
    }

    const key = await deriveKey(masterPassword, saltBytes);

    // If there is an existing vault, verify the key by decrypting it
    if (vault) {
      try {
        await readVault(key, vault);
      } catch {
        const newAttempts = failedAttempts + 1;
        if (newAttempts >= MAX_ATTEMPTS) {
          await setAttemptData({
            failedAttempts: newAttempts,
            lockedUntil:    Date.now() + LOCKOUT_MS,
          });
          return { success: false, error: `Too many attempts. Locked for 60 seconds.` };
        }
        await setAttemptData({ failedAttempts: newAttempts, lockedUntil: 0 });
        return { success: false, error: `Incorrect master password. ${MAX_ATTEMPTS - newAttempts} attempt(s) remaining.` };
      }
    }

    await setSessionKey(key);
    await resetAttempts();
    return { success: true };
  }

  // ── LOCK ─────────────────────────────────────────────────────────────────────
  if (action === "lock") {
    await clearSessionKey();
    return { success: true };
  }

  // ── CHECK LOCKED ─────────────────────────────────────────────────────────────
  if (action === "isLocked") {
    const key = await getSessionKey();
    return { locked: !key };
  }

  // ── ADD CREDENTIAL ────────────────────────────────────────────────────────────
  if (action === "addCredential") {
    const key = await getSessionKey();
    if (!key) return { success: false, error: "Vault is locked." };

    const { vault, salt } = await loadEncryptedVault();
    const entries = await readVault(key, vault);

    entries.push({
      id:       crypto.randomUUID(),
      url:      message.url,
      username: message.username,
      password: message.password,
      createdAt: new Date().toISOString(),
    });

    await writeVault(key, entries, salt);
    return { success: true };
  }

  // ── GET CREDENTIALS ───────────────────────────────────────────────────────────
  if (action === "getCredentials") {
    const key = await getSessionKey();
    if (!key) return { success: false, error: "Vault is locked." };

    const { vault, salt } = await loadEncryptedVault();
    const entries = await readVault(key, vault);
    return { success: true, entries };
  }

  // ── GET CREDENTIALS FOR URL ───────────────────────────────────────────────────
  if (action === "getCredentialsForUrl") {
    const key = await getSessionKey();
    if (!key) return { success: false, entries: [] };

    const { vault } = await loadEncryptedVault();
    const entries   = await readVault(key, vault);
    const url       = message.url || "";
    let domain;
    try { domain = new URL(url).hostname; } catch { domain = url; }

    const matches = entries.filter(e => {
      try { return new URL(e.url).hostname === domain; } catch { return false; }
    });
    return { success: true, entries: matches };
  }

  // ── DELETE CREDENTIAL ─────────────────────────────────────────────────────────
  if (action === "deleteCredential") {
    const key = await getSessionKey();
    if (!key) return { success: false, error: "Vault is locked." };

    const { vault, salt } = await loadEncryptedVault();
    const entries  = await readVault(key, vault);
    const filtered = entries.filter(e => e.id !== message.id);
    await writeVault(key, filtered, salt);
    return { success: true };
  }

  // ── GENERATE PASSWORD ─────────────────────────────────────────────────────────
  if (action === "generatePassword") {
    const password = generatePassword(message.length || 16);
    return { success: true, password };
  }

  // ── CHECK BREACH ──────────────────────────────────────────────────────────────
  if (action === "checkBreach") {
    try {
      const count = await checkBreached(message.password);
      return { success: true, count };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  return { success: false, error: `Unknown action: ${action}` };
}
