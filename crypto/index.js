// Single public entry point for the crypto module.
// Person 3 (frontend) and Person 4 (integration) should ONLY import from
// this file — never reach into individual files like encrypt.js directly.

export { buildEnvelope, openEnvelope, buildFileEnvelope, openFileEnvelope, SecretAccessError } from './envelope.js';
export { encryptFile, decryptFile } from './fileEncrypt.js';
export { analyzeContent } from './detect.js';

export function isZeroKnowledge() {
  return true;
}