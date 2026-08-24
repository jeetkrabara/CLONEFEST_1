import { bufToBase64, base64ToBuf } from './keys.js';

export async function encryptData(plaintext, key, iv) {
  const encoder = new TextEncoder();
  const encodedPlaintext = encoder.encode(plaintext);
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, encodedPlaintext
  );
  return bufToBase64(ciphertextBuf);
}

export async function decryptData(ciphertextB64, key, iv) {
  const ciphertextBuf = base64ToBuf(ciphertextB64);
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, key, ciphertextBuf
  );
  const decoder = new TextDecoder();
  return decoder.decode(plaintextBuf);
}