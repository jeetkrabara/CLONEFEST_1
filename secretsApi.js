/**
 * SecureBin — Integration Layer (Person 4)
 * -----------------------------------------
 * Sits between Person 3's UI, Person 1's crypto/index.js, and Person 2's REST API.
 * Person 3 should only ever call functions from THIS file, never touch crypto or
 * fetch() directly — same "stable public interface" principle Person 1 used.
 *
 * Backend base URL matches Person 2's docs (adjust for prod).
 */

import {
  buildEnvelope,
  openEnvelope,
  buildFileEnvelope,
  openFileEnvelope,
  isZeroKnowledge,
  SecretAccessError,
} from "./crypto/index.js";

const BASE_URL = "http://localhost:3000";

// ---------------------------------------------------------------------------
// Shared error mapping — one source of truth for UI copy, used by every flow.
// Covers both SecretAccessError.code (from crypto/openEnvelope) and raw HTTP
// status codes (from creation/revoke/status/stats, which don't go through
// crypto so don't produce SecretAccessError).
// ---------------------------------------------------------------------------
export function toUserMessage(err) {
  if (err instanceof SecretAccessError) {
    switch (err.code) {
      case "VIEW_LIMIT_EXCEEDED":
        return "This secret is no longer available.";
      case "NOT_FOUND":
        return "This link is invalid or has expired.";
      case "AUTH_FAILED":
        return "Incorrect password. Try again.";
      case "DECRYPT_FAILED":
        return "This secret's data appears corrupted.";
      case "NETWORK_ERROR":
        return "Couldn't reach the server. Check your connection.";
      case "SERVER_ERROR":
      default:
        return "Something went wrong. Please try again.";
    }
  }
  if (err && err.httpStatus) {
    switch (err.httpStatus) {
      case 400:
        return err.message || "That request was malformed.";
      case 403:
        return "You don't have permission to do that.";
      case 404:
        return "That secret doesn't exist.";
      case 410:
        return "That secret is no longer available (expired, revoked, or already used).";
      default:
        return "Something went wrong on our end. Please try again.";
    }
  }
  return "Something went wrong. Please try again.";
}

class ApiError extends Error {
  constructor(message, httpStatus) {
    super(message);
    this.name = "ApiError";
    this.httpStatus = httpStatus;
  }
}

async function parseJsonOrThrow(res) {
  let body = null;
  try {
    body = await res.json();
  } catch (_) {
    /* no body / not JSON */
  }
  if (!res.ok) {
    throw new ApiError(body?.error || `Request failed (${res.status})`, res.status);
  }
  return body;
}

// ---------------------------------------------------------------------------
// 1. CREATE — text secret
// ---------------------------------------------------------------------------
export async function createTextSecret({ secretText, viewerPasswords, maxViews, expiresAt }) {
  const envelope = await buildEnvelope(secretText, viewerPasswords);
  // envelope: { ciphertext, iv, encryptedAnalysis?, analysisIv?, viewers }

  const payload = {
    ...envelope,
    ...(maxViews != null ? { maxViews } : {}),
    ...(expiresAt ? { expiresAt } : {}),
  };

  const res = await fetch(`${BASE_URL}/api/secrets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await parseJsonOrThrow(res);
  return data; // { secretId, ownerToken }  <-- caller MUST persist ownerToken now, it's shown once
}

// ---------------------------------------------------------------------------
// 2. CREATE — file secret (multipart, per Person 2's contract)
// ---------------------------------------------------------------------------
export async function createFileSecret({ file, viewerPasswords, maxViews, expiresAt }) {
  const fileEnvelope = await buildFileEnvelope(file, viewerPasswords);
  // { encryptedBytes, encryptedMetadata, fileIv, metaIv, viewers }

  const form = new FormData();
  form.append(
    "encryptedBytes",
    new Blob([fileEnvelope.encryptedBytes]),
    "encrypted" // filename is irrelevant/opaque — real name lives inside encryptedMetadata
  );
  form.append("fileIv", fileEnvelope.fileIv);
  form.append("metaIv", fileEnvelope.metaIv);
  form.append("encryptedMetadata", fileEnvelope.encryptedMetadata);
  form.append("viewers", JSON.stringify(fileEnvelope.viewers)); // must be a JSON *string* field
  if (maxViews != null) form.append("maxViews", String(maxViews));
  if (expiresAt) form.append("expiresAt", expiresAt);

  const res = await fetch(`${BASE_URL}/api/secrets`, {
    method: "POST",
    body: form, // do NOT set Content-Type manually — browser sets multipart boundary
  });

  const data = await parseJsonOrThrow(res);
  return data; // { secretId, ownerToken }
}

// ---------------------------------------------------------------------------
// 3. VIEW — the fetchSecretFn crypto needs, shared by text + file
// ---------------------------------------------------------------------------
function fetchSecretFn(secretId, viewerLabel) {
  return fetch(`${BASE_URL}/api/secrets/${secretId}?viewer=${encodeURIComponent(viewerLabel)}`);
}

export async function viewTextSecret(secretId, viewerLabel, password) {
  // Throws SecretAccessError on failure — let the UI layer catch + call toUserMessage()
  const { plaintext, analysis } = await openEnvelope(secretId, viewerLabel, password, fetchSecretFn);
  return { plaintext, analysis }; // analysis may be null
}

export async function viewFileSecret(secretId, viewerLabel, password) {
  const file = await openFileEnvelope(secretId, viewerLabel, password, fetchSecretFn);
  return file; // real File object
}

// ---------------------------------------------------------------------------
// 4. REVOKE
// ---------------------------------------------------------------------------
export async function revokeSecret(secretId, ownerToken) {
  const res = await fetch(`${BASE_URL}/api/secrets/${secretId}/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ownerToken }),
  });
  return parseJsonOrThrow(res); // { status: "ok", message }
}

// ---------------------------------------------------------------------------
// 5. STATUS — safe to poll, doesn't consume a view (for countdowns/dashboard)
// ---------------------------------------------------------------------------
export async function getSecretStatus(secretId) {
  const res = await fetch(`${BASE_URL}/api/secrets/${secretId}/status`);
  return parseJsonOrThrow(res);
  // { state, type, timeRemainingSeconds, maxViews, viewsUsed, viewerLabels, configSecurityScore }
}

// ---------------------------------------------------------------------------
// 6. STATS — Person 3's Privacy Transparency Dashboard
// ---------------------------------------------------------------------------
export async function getSecretStats(secretId) {
  const res = await fetch(`${BASE_URL}/api/secrets/${secretId}/stats`);
  return parseJsonOrThrow(res);
}

// ---------------------------------------------------------------------------
// 7. INTEGRITY — self-healing storage health check
// ---------------------------------------------------------------------------
export async function checkIntegrity(secretId) {
  const res = await fetch(`${BASE_URL}/api/secrets/${secretId}/integrity`);
  return parseJsonOrThrow(res); // { intact, healEvents }
}

// ---------------------------------------------------------------------------
// 8. Zero-knowledge badge passthrough
// ---------------------------------------------------------------------------
export { isZeroKnowledge };

// ---------------------------------------------------------------------------
// 9. Health check — useful at app boot / demo start to fail fast if backend is down
// ---------------------------------------------------------------------------
export async function healthCheck() {
  try {
    const res = await fetch(`${BASE_URL}/health`);
    const data = await res.json();
    return res.ok && data.status === "ok";
  } catch {
    return false;
  }
}