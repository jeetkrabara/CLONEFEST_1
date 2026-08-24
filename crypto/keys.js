export async function generateMasterKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export function generateIv() {
  return crypto.getRandomValues(new Uint8Array(12));
}

export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function exportKeyRaw(key) {
  return crypto.subtle.exportKey("raw", key);
}

export async function importKeyRaw(rawBytes) {
  return crypto.subtle.importKey(
    "raw", rawBytes, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
  );
}

export function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function base64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}