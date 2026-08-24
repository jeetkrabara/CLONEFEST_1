import { generateIv, exportKeyRaw, importKeyRaw, bufToBase64, base64ToBuf } from './keys.js';
import { encryptData, decryptData } from './encrypt.js';

export async function deriveKeyFromPassword(password, saltBytes) {
  const encoder = new TextEncoder();
  const passwordKeyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 600000, hash: "SHA-256" },
    passwordKeyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function wrapMasterKey(masterKey, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapIv = generateIv();
  const wrapKey = await deriveKeyFromPassword(password, salt);
  const masterKeyRaw = await exportKeyRaw(masterKey);
  const masterKeyRawB64 = bufToBase64(masterKeyRaw);
  const wrappedKeyB64 = await encryptData(masterKeyRawB64, wrapKey, wrapIv);

  return {
    wrappedKey: wrappedKeyB64,
    kdfSalt: bufToBase64(salt),
    wrapIv: bufToBase64(wrapIv),
    kdfParams: { iterations: 600000, algorithm: "PBKDF2-SHA256" }
  };
}

export async function unwrapMasterKey(password, wrapData) {
  const salt = new Uint8Array(base64ToBuf(wrapData.kdfSalt));
  const wrapIv = new Uint8Array(base64ToBuf(wrapData.wrapIv));
  const wrapKey = await deriveKeyFromPassword(password, salt);
  const masterKeyRawB64 = await decryptData(wrapData.wrappedKey, wrapKey, wrapIv);
  const masterKeyRaw = base64ToBuf(masterKeyRawB64);
  return importKeyRaw(masterKeyRaw);
}