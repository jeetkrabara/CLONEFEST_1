// src/crypto/envelope.js
import { generateMasterKey, generateIv } from './keys.js';
import { encryptData, decryptData } from './encrypt.js';
import { wrapMasterKey, unwrapMasterKey } from './passwordWrap.js';
import { encryptFile, decryptFile } from './fileEncrypt.js';
import { analyzeContent } from './detect.js';

/**
 * Custom error so the UI layer (Person 3) can distinguish
 * "view limit hit" from "wrong password" from "network error"
 * and show the right message for each.
 */
export class SecretAccessError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "SecretAccessError";
    this.code = code; // e.g. "VIEW_LIMIT_EXCEEDED", "NOT_FOUND", "EXPIRED"
  }
}

// --- small local helpers for IV base64 handling, used throughout this file ---
function bufToBase64Iv(iv) {
  return btoa(String.fromCharCode(...iv));
}
function base64ToBufIv(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/**
 * CREATE flow (text): encrypts a secret, analyzes it client-side for
 * sensitivity (type/score/recommendations), encrypts that analysis too
 * (so the server stores it but can never read it — keeps zero-knowledge
 * consistent), and wraps the master key for each viewer.
 */
export async function buildEnvelope(plaintext, viewerPasswords) {
  // viewerPasswords: array of { label, password }, e.g.
  // [{ label: "Alice", password: "..." }, { label: "Bob", password: "..." }]

  const masterKey = await generateMasterKey();
  const dataIv = generateIv();
  const ciphertext = await encryptData(plaintext, masterKey, dataIv);

  // Analyze the plaintext (client-side, pre-encryption), then encrypt the
  // result with the SAME master key — the server stores it but can't read it.
  const analysisIv = generateIv();
  const analysis = analyzeContent(plaintext);
  const encryptedAnalysis = await encryptData(JSON.stringify(analysis), masterKey, analysisIv);

  const viewers = [];
  for (const { label, password } of viewerPasswords) {
    const wrapData = await wrapMasterKey(masterKey, password);
    viewers.push({ viewerLabel: label, ...wrapData });
  }

  return {
    ciphertext,
    iv: bufToBase64Iv(dataIv),
    encryptedAnalysis,
    analysisIv: bufToBase64Iv(analysisIv),
    viewers
  };
}

/**
 * ACCESS flow (text): called when a viewer opens a shared link and enters
 * their password. Returns { plaintext, analysis } — NOT just a string.
 *
 * fetchSecretFn: a function you pass in that calls Person 2's API,
 * e.g. (secretId, viewerLabel) => fetch(`/api/secrets/${secretId}?viewer=${viewerLabel}`)
 * Kept as a parameter so this module has zero direct dependency on API
 * routes — Person 4 wires the real fetch call at integration time.
 */
export async function openEnvelope(secretId, viewerLabel, password, fetchSecretFn) {
  let response;
  try {
    response = await fetchSecretFn(secretId, viewerLabel);
  } catch (networkErr) {
    throw new SecretAccessError("Could not reach the server.", "NETWORK_ERROR");
  }

  // The server is responsible for checking view limits, expiry, and
  // revocation BEFORE returning any ciphertext. We just interpret its response.
  if (response.status === 410) {
    throw new SecretAccessError("This secret has reached its view limit or expired.", "VIEW_LIMIT_EXCEEDED");
  }
  if (response.status === 404) {
    throw new SecretAccessError("This secret does not exist or was deleted.", "NOT_FOUND");
  }
  if (!response.ok) {
    throw new SecretAccessError("Unexpected server error.", "SERVER_ERROR");
  }

  const { ciphertext, iv, encryptedAnalysis, analysisIv, wrapData } = await response.json();

  let masterKey;
  try {
    masterKey = await unwrapMasterKey(password, wrapData);
  } catch (cryptoErr) {
    throw new SecretAccessError("Incorrect password, or this data has been tampered with.", "AUTH_FAILED");
  }

  try {
    const plaintext = await decryptData(ciphertext, masterKey, base64ToBufIv(iv));

    let analysis = null;
    if (encryptedAnalysis && analysisIv) {
      const analysisJson = await decryptData(encryptedAnalysis, masterKey, base64ToBufIv(analysisIv));
      analysis = JSON.parse(analysisJson);
    }

    return { plaintext, analysis };
  } catch (decryptErr) {
    throw new SecretAccessError("Decryption failed — content may be corrupted.", "DECRYPT_FAILED");
  }
}

/**
 * CREATE flow (file): same multi-viewer wrapping as buildEnvelope(),
 * but encrypts file bytes + metadata instead of text.
 * NOTE: content analysis is NOT run on files — analyzeContent() is
 * regex-based and designed for text plaintext, not arbitrary binary.
 */
export async function buildFileEnvelope(file, viewerPasswords) {
  const masterKey = await generateMasterKey();
  const fileIv = generateIv();
  const metaIv = generateIv();

  const { encryptedBytes, encryptedMetadata } = await encryptFile(file, masterKey, fileIv, metaIv);

  const viewers = [];
  for (const { label, password } of viewerPasswords) {
    const wrapData = await wrapMasterKey(masterKey, password);
    viewers.push({ viewerLabel: label, ...wrapData });
  }

  return {
    encryptedBytes,       // raw binary — upload as multipart/binary, not JSON
    encryptedMetadata,    // base64 string — small, fits fine in JSON alongside other fields
    fileIv: bufToBase64Iv(fileIv),
    metaIv: bufToBase64Iv(metaIv),
    viewers               // SAME shape as text secrets — no special-casing
  };
}

/**
 * ACCESS flow (file): identical error handling to openEnvelope(),
 * but returns a decrypted File object instead of a plaintext string.
 */
export async function openFileEnvelope(secretId, viewerLabel, password, fetchSecretFn) {
  let response;
  try {
    response = await fetchSecretFn(secretId, viewerLabel);
  } catch (networkErr) {
    throw new SecretAccessError("Could not reach the server.", "NETWORK_ERROR");
  }

  if (response.status === 410) {
    throw new SecretAccessError("This secret has reached its view limit or expired.", "VIEW_LIMIT_EXCEEDED");
  }
  if (response.status === 404) {
    throw new SecretAccessError("This secret does not exist or was deleted.", "NOT_FOUND");
  }
  if (!response.ok) {
    throw new SecretAccessError("Unexpected server error.", "SERVER_ERROR");
  }

  const { encryptedBytes, encryptedMetadata, fileIv, metaIv, wrapData } = await response.json();

  let masterKey;
  try {
    masterKey = await unwrapMasterKey(password, wrapData);
  } catch (cryptoErr) {
    throw new SecretAccessError("Incorrect password, or this data has been tampered with.", "AUTH_FAILED");
  }

  try {
    return await decryptFile(
      encryptedBytes,
      encryptedMetadata,
      masterKey,
      base64ToBufIv(fileIv),
      base64ToBufIv(metaIv)
    );
  } catch (decryptErr) {
    throw new SecretAccessError("Decryption failed — content may be corrupted.", "DECRYPT_FAILED");
  }
}