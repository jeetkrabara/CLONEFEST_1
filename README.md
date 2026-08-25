# SecureBin

## Zero-Knowledge Secure Secret Sharing

SecureBin is a secure platform for sharing sensitive text and files over the internet.

The main idea is simple: **encrypt the data on the client side before it reaches the server, keep the decryption material separate from the shareable URL, and give the creator control over the entire lifecycle of the secret.**

SecureBin was inspired by the secure-sharing concept behind PrivateBin, but extends it with additional access control, lifecycle management, security analysis, integrity recovery and privacy features.

---

## Key Features

### 1. Client-Side Encryption

- Secrets are encrypted in the browser before being sent to the backend.
- Uses **AES-256-GCM** for encryption.
- Fresh random IVs are generated for encryption operations.
- AES-GCM also provides tamper detection.

### 2. Zero-Knowledge Architecture

- The backend does not receive the plaintext secret.
- Raw decryption keys are not sent to the server.
- Raw user passwords are not stored by the server.
- The backend mainly handles encrypted data, wrapped keys and the metadata required for lifecycle management.

### 3. Decryption Key Not Stored in the URL

- The shareable URL contains only a randomly generated `secretId`.
- The decryption secret is kept separate from the URL.
- Having the link alone does not provide the decryption material.

This was one of the main security changes we made compared with the traditional PrivateBin-style approach.

### 4. Multi-Viewer Sharing

- A single secret can be shared with multiple viewers.
- Each viewer can have their own password.
- Each viewer gets an independently wrapped copy of the master encryption key.
- The actual secret only needs to be encrypted once.

SecureBin uses envelope encryption to achieve this.

### 5. Secret Lifecycle Management

Creators can control how long and how often their secrets can be accessed.

Available controls include:

- Time-based expiration
- Maximum view limits
- Burn after reading
- Manual revocation
- Automatic deletion

Secrets can move through states such as:

- Active
- Viewed
- Expired
- Revoked
- Burned
- Deleted

The backend checks these policies before allowing access.

### 6. Self-Healing Storage

SecureBin includes a recovery mechanism for row-level corruption of encrypted data.

- SHA-256 is used to verify the integrity of stored encrypted data.
- A redundant encrypted backup is maintained.
- If corruption is detected, the system can recover the encrypted record from the backup.
- The recovered data is verified before being used.

This feature is designed for storage-level corruption and bad writes, not complete database failure.

### 7. Security Analysis and Recommendations

SecureBin can identify recognizable sensitive patterns in content before encryption.

Examples include:

- API keys
- AWS access keys
- JWTs
- Private keys
- Credit-card-like numbers
- Password-related content
- Email addresses

Based on the detected patterns, SecureBin provides a heuristic security score and recommendations such as using a shorter expiry or burn-after-reading.

The analysis result is encrypted before storage, so the backend does not need access to the original plaintext.

### 8. Secure File Sharing

SecureBin supports both text and files.

For files, the system protects:

- File contents
- Filename
- MIME type
- File size

Encrypting metadata is important because information such as a filename can itself reveal sensitive details.

### 9. Privacy-Minimized Statistics

Creators can monitor their secrets through information such as:

- Successful and failed access attempts
- Viewer-wise access counts
- First and last access times
- Current secret status

SecureBin deliberately avoids unnecessary logging of:

- IP addresses
- User agents
- Complete request headers

### 10. Integrity and Access Control

Security in SecureBin is not limited to encryption.

The system combines:

- Encryption
- Password-based key protection
- Viewer-specific access
- Lifecycle policies
- Revocation
- Integrity verification
- Storage recovery
- Privacy-minimized monitoring

---

## Cryptographic Design

### AES-256-GCM

The actual secret content is encrypted using AES-256-GCM through the browser's Web Crypto API.

GCM provides both:

- Confidentiality
- Authentication/tamper detection

### Password-Based Key Derivation

SecureBin uses:

- PBKDF2
- SHA-256
- 600,000 iterations
- A separate random salt for each viewer

### Envelope Encryption

The secret is encrypted using a random AES-256 master key.

The master key is then individually wrapped for each authorized viewer.

This allows different viewers to use different passwords while accessing the same encrypted secret.

---

## How SecureBin Handles a Secret

A secret goes through the following general process:

1. The creator enters a secret or uploads a file.
2. The client generates the required encryption keys.
3. The content is encrypted locally.
4. Viewer-specific key material is created where required.
5. Only encrypted information is sent to the backend.
6. The backend applies the configured access policies.
7. Access attempts are recorded using privacy-minimized statistics.
8. The encrypted data is integrity-checked when accessed.
9. The secret can eventually expire, be revoked, burn after reading, or be permanently deleted.

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

The project is divided into three main parts.

### Frontend

Handles:

- User interface
- Secret creation
- Sharing
- Secret viewing
- User interaction

### Cryptographic Layer

Handles:

- Encryption and decryption
- Key generation
- Password-based key derivation
- Key wrapping
- File encryption
- Security analysis

### Backend

Handles:

- API requests
- Encrypted secret storage
- Access policies
- Lifecycle management
- Revocation
- Access statistics
- Integrity verification
- Storage recovery
- Deletion

---

## SecureBin vs PrivateBin

PrivateBin was the starting inspiration for our project.

Instead of stopping at encrypted paste sharing, SecureBin focuses on managing the **entire lifecycle of a secret**.

Some of the major additions in SecureBin are:

- Decryption material separated from the URL
- Multi-viewer access with individual passwords
- Individually wrapped encryption keys
- Time-based expiration
- View-based limits
- Burn-after-reading
- Manual revocation
- Security scoring and recommendations
- Encrypted file metadata
- Privacy-minimized access statistics
- Self-healing encrypted storage

The goal was not simply to recreate PrivateBin with a different interface. We wanted to explore how secure sharing could be extended into a more complete system where the creator has control over **who can access a secret, how it can be accessed, how long it exists, and what happens when something goes wrong with its stored encrypted data.**

---

## Security Approach

The main principle behind SecureBin is:

> **The server should be able to manage an encrypted secret without being trusted with the secret itself.**

Because of this, security is considered at multiple stages:

- Protecting the content
- Protecting the encryption keys
- Controlling access
- Controlling the secret's lifetime
- Detecting tampering or corruption
- Recovering from storage corruption
- Minimizing unnecessary user data collection

---

## Project

**Live Demo:**

[SecureBin Live Demo](https://clonefest-1-git-main-srscd.vercel.app/securebin-frontend.html)

SecureBin was developed as a team project to explore practical applications of client-side cryptography, secure key management, access control, privacy and secure data lifecycle management.
