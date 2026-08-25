// crypto-loader.js
// Loaded via <script type="module" src="crypto-loader.js"> in the HTML.
// Being an EXTERNAL module file (not inline) means Babel Standalone's
// script-tag scanner never sees or transforms this — it's handled entirely
// natively by the browser's module loader.

import {
  buildEnvelope,
  openEnvelope,
  buildFileEnvelope,
  openFileEnvelope,
  analyzeContent,
  isZeroKnowledge,
  SecretAccessError,
} from "./crypto/index.js";

window.SecureCrypto = {
  buildEnvelope,
  openEnvelope,
  buildFileEnvelope,
  openFileEnvelope,
  analyzeContent,
  isZeroKnowledge,
  SecretAccessError,
};

window.dispatchEvent(new Event("securecrypto-ready"));