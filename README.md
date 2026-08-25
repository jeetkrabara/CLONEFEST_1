# SecureBin

## Zero-Knowledge Secure Secret Sharing

SecureBin is a secure platform for sharing sensitive text and files without exposing the actual secret or raw decryption key to the backend.

The main idea is simple: **encrypt the data on the client side, keep the raw decryption secret separate from the shareable URL, and give the creator control over the complete lifecycle of the secret.**

PrivateBin was the starting inspiration for the project, but SecureBin extends the secure-sharing concept with additional access control, lifecycle policies, security analysis, privacy features and self-healing encrypted storage.

---

## Key Features

### 1. Client-Side AES-256-GCM Encryption

- Secrets are encrypted in the browser before being sent to the backend.
- Uses **AES-256-GCM** for encryption.
- Fresh random IVs are generated for encryption operations.
- AES-GCM provides authentication and tamper detection.

### 2. Zero-Knowledge Architecture

- Plaintext secrets are not sent to the backend.
- Raw decryption keys are not sent to the server.
- Raw user passwords are not stored by the server.
- The backend mainly handles encrypted data, wrapped keys and lifecycle metadata.
- SecureBin includes an `isZeroKnowledge()` security indicator.

### 3. Decryption Secret Separated from the URL

- The shareable URL contains only a randomly generated `secretId`.
- The raw decryption secret is kept separate from the URL.
- The raw master key does not reach the server.
- For multi-viewer sharing, the master key is individually wrapped for each viewer.

### 4. Per-Viewer Password Protection

Each viewer can have an individual password.

SecureBin uses:

- PBKDF2
- SHA-256
- 600,000 iterations
- A separate random salt for each viewer

This allows different viewers to access the same encrypted secret using their own credentials.

### 5. Multi-Viewer Secure Sharing

A single encrypted secret can be shared with multiple authorized viewers.

- Each viewer has their own password.
- Each viewer receives an independently wrapped copy of the master encryption key.
- The actual secret only needs to be encrypted once.

SecureBin uses envelope encryption for this process.

### 6. Security Policy Engine

SecureBin has a backend-enforced Security Policy Engine that combines:

- Time-based expiration
- Maximum view limits
- Burn-after-reading

These policies are checked before access is allowed rather than being treated as frontend-only settings.

### 7. Complete Secret Lifecycle

Secrets can move through controlled lifecycle states:

- `ACTIVE`
- `VIEWED`
- `EXPIRED`
- `REVOKED`
- `BURNED`
- `DELETED`

The system supports:

- Time-based expiration
- View-limit expiration
- Burn-after-reading
- Instant revocation
- Automatic deletion

### 8. Instant Revocation

The owner can immediately revoke a secret using a separate `ownerToken`.

This allows the creator to invalidate access before the normal expiration condition is reached.

### 9. Automatic Deletion

Secrets that reach their terminal lifecycle state are permanently removed through a background deletion process.

This prevents expired or revoked secrets from remaining stored indefinitely.

### 10. Expiration and Status Tracking

The `/status` endpoint provides lifecycle and expiration information for an active secret.

This allows the application to keep track of the remaining lifetime and current state of the secret.

### 11. Intelligent Security Analysis

SecureBin performs security analysis on the client side before the secret is stored.

It can detect recognizable patterns such as:

- API keys
- AWS access keys
- JWTs
- Private keys
- Credit-card-like numbers
- Password-related content
- Email addresses

The system also performs automatic secret-type detection and provides security recommendations.

### 12. Security Score

The security score combines two areas:

- Content-sensitivity analysis
- Configuration-based security settings

The content analysis is encrypted before being stored, so the backend does not need access to the original plaintext.

### 13. Client-Side File Encryption

SecureBin supports files as well as text secrets.

Files are encrypted on the client side before being sent to the backend.

The system also protects file metadata such as:

- Filename
- MIME type
- File size

### 14. Privacy-Minimized Statistics

SecureBin provides useful access information without unnecessarily tracking users.

The system can provide:

- Successful and failed access attempts
- Viewer-wise access counts
- Access timestamps
- Current secret status

The backend deliberately does not log:

- IP addresses
- User agents

Privacy-preserving statistics are available through the `/stats` endpoint.

### 15. Self-Healing Encrypted Storage

SecureBin includes a recovery mechanism for row-level corruption of encrypted data.

- A checksum is used to verify the integrity of stored encrypted data.
- A redundant encrypted backup is maintained.
- If corruption is detected, the system can restore the encrypted record from the backup.
- The recovered data is verified before being used.

This is designed for storage-level corruption and bad writes, not complete database failure.

---

## Cryptographic Design

### AES-256-GCM

The actual secret content is encrypted using AES-256-GCM through the browser's Web Crypto API.

AES-GCM provides:

- Confidentiality
- Authentication
- Tamper detection

### Password-Based Key Derivation

Viewer passwords are processed using:

- PBKDF2
- SHA-256
- 600,000 iterations
- Individual random salts

### Envelope Encryption

A random master encryption key is used to encrypt the actual secret.

The master key is then individually wrapped for each authorized viewer.

This allows multiple viewers to access the same encrypted secret while using separate passwords.

---

## How SecureBin Handles a Secret

The general process is:

1. The creator enters a secret or uploads a file.
2. The client generates the required cryptographic keys.
3. The content is encrypted locally.
4. Viewer-specific key material is created where required.
5. Only encrypted information is sent to the backend.
6. The Security Policy Engine applies the configured access rules.
7. Access information is recorded using privacy-minimized statistics.
8. The encrypted data is checked for integrity when accessed.
9. The secret eventually expires, is revoked, burns after reading or is permanently deleted according to its lifecycle.

---

## Technology Stack

### Frontend

- JavaScript
- React
- HTML/CSS
- Web Crypto API

### Backend

- Node.js
- Express.js
- PostgreSQL
- Prisma ORM

### Cryptography

- AES-256-GCM
- PBKDF2-SHA256
- SHA-256
- Web Crypto API
- bcrypt

---

## Project Structure

The project is divided into three main areas.

### Frontend

Handles:

- User interface
- Secret creation
- Secret sharing
- Secret viewing
- User interaction
- Lifecycle information

### Cryptographic Layer

Handles:

- Encryption and decryption
- Key generation
- Password-based key derivation
- Key wrapping
- File encryption
- Sensitive-data detection
- Secret-type detection
- Security scoring
- Security recommendations

### Backend

Handles:

- API requests
- Encrypted secret storage
- Security policies
- Lifecycle management
- Revocation
- Access statistics
- Integrity verification
- Self-healing recovery
- Automatic deletion

---

## SecureBin vs PrivateBin

PrivateBin was the starting inspiration for our secure-sharing concept.

Instead of stopping at encrypted paste sharing, SecureBin focuses on managing the **entire lifecycle of a secret**.

Some of the major additions in SecureBin are:

- Decryption material separated from the URL
- Multi-viewer access with individual passwords
- Individually wrapped encryption keys
- Security Policy Engine
- Time-based expiration
- View-limit expiration
- Burn-after-reading
- Instant revocation
- Automatic deletion
- Intelligent security analysis
- Automatic secret-type detection
- Security scoring and recommendations
- Encrypted file metadata
- Privacy-minimized access statistics
- Self-healing encrypted storage

The goal was not simply to recreate PrivateBin with a different interface. We wanted to explore how secure sharing could be extended into a more complete system where the creator has control over **who can access a secret, how it can be accessed, how long it exists, and what happens when its stored encrypted data becomes corrupted.**

---

## Security Approach

The main principle behind SecureBin is:

> **The server should be able to manage an encrypted secret without being trusted with the secret itself.**

Security is therefore considered at multiple stages:

- Protecting the content
- Protecting the encryption keys
- Controlling viewer access
- Enforcing lifecycle policies
- Detecting tampering or corruption
- Recovering from storage corruption
- Minimizing unnecessary user data collection
- Permanently deleting secrets after their lifecycle ends

---

## Project

SecureBin was developed as a team project to explore practical applications of:

- Client-side cryptography
- Secure key management
- Access control
- Secret lifecycle management
- Privacy-preserving statistics
- Data integrity
- Secure storage recovery

### Live Demo

[SecureBin Live Demo](https://clonefest-1-git-main-srscd.vercel.app/securebin-frontend.html)
