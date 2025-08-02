# 🔐 Security Policy

[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](https://github.com/himalabs/himacrypt/security/policy)
[![Responsible Disclosure](https://img.shields.io/badge/Responsible-Disclosure-yellow.svg)](https://github.com/himalabs/himacrypt/security/advisories/new)

Thank you for helping make `himacrypt` secure! This document outlines how to report security issues and best practices around using this tool safely.

## 📣 Reporting a Vulnerability

If you discover a security vulnerability or concern:

- **Do not open a public GitHub issue.**
- Instead, please report it **privately and responsibly** by emailing:

  ```
  maharanasarkars3@gmail.com
  ```

We aim to respond within **48 hours** and will work with you to address the issue promptly and transparently.

---

## 📌 Supported Versions

Only the **latest stable release** is actively maintained and receives security updates.

| Version | Supported          |
|---------|--------------------|
| `>=1.0` | ✅ Yes              |
| `<1.0`  | 🚫 No (pre-release) |

---

## 🛠 Security Best Practices

While `himacrypt` provides strong cryptographic tools, **misconfiguration can still lead to leaks or weak setups**. We strongly recommend the following practices:

### 🔑 Key Management
- **Do not commit** `private.pem` or decrypted `.env` files to version control.
- Use **password protection** on private keys wherever possible.
- Store private keys in **secure locations** (e.g., AWS Secrets Manager, Vault).

### 🔐 File Permissions
- Restrict access to encrypted and decrypted files using `chmod`:
  ```bash
  chmod 600 .env .env.enc keys/private.pem
### 🐳 Docker/CI/CD
- Mount private keys at runtime only; do not bake them into images
- Auto-decrypt in entrypoint only if key is present
- Never expose decrypted `.env` in logs

### 🧪 Regular Rotation
- Periodically rotate RSA key pairs and re-encrypt `.env` files
- Avoid long-lived encryption keys across many environments

### 🛡 Cryptographic Standards Used

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Public-key crypto | RSA 2048/4096 | OAEP padding (SHA-256) |
| Symmetric crypto | AES-256 | GCM or CBC mode (with random IVs) |
| Key protection | Optional AES | When password-encrypted private keys are used |

All cryptographic operations are backed by the cryptography package with secure defaults.

## ❌ Known Limitations

- The tool does not currently integrate with remote key vaults (e.g., KMS, Vault) — this is planned for future releases
- It assumes the user is responsible for managing private key secrecy and file permissions

## 🔄 Disclosure Timeline

Once a vulnerability is reported:

1. We acknowledge the report within 48 hours
2. We investigate and validate the issue
3. We create a fix and prepare a release
4. We coordinate disclosure if needed (CVE, blog post)
5. We credit the reporter (if allowed) in the changelog

## 🙏 Thank You

Security is a shared responsibility — thank you for helping improve himacrypt.

If in doubt, please reach out privately via the contact listed above.