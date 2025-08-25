# FAQ

This page answers common questions about himacrypt.

Q: What file formats does himacrypt support?

A: `.env`, `.json`, `.yaml`/`.yml`, and `.toml` are supported for encryption/decryption and validation. Field-level encryption may only be available for structured formats.

Q: How does himacrypt protect my secrets?

A: himacrypt uses hybrid encryption: an ephemeral AES key encrypts file contents and the AES key is encrypted with an RSA public key. This gives both fast encryption for large payloads and secure key distribution using public-key cryptography.

Q: Where do I store the private key?

A: Private keys should never be checked into source control. Use secure secret stores (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) or environment-specific secure volumes (Kubernetes secrets, mounted files accessible only to the runtime).

Q: How do I rotate keys?

A: Rotate RSA key pairs periodically. To rotate:
- Generate a new key pair
- Decrypt existing encrypted artifacts using the old key
- Re-encrypt with the new public key
Automation is recommended for production environments.

Q: Can I use hardware-backed keys (HSM)?

A: Yes — implement a Key Provider that interfaces with your HSM or KMS and use that provider to decrypt/encrypt the AES key. This requires adding a pluggable backend.

Q: I see issues with line endings on Windows. What should I do?

A: Ensure files use consistent line endings (LF preferred). Use `.gitattributes` to normalize line endings and configure your editor to use LF for repository files.

Q: How do I contribute?

A: See `docs/contributing.md` for guidelines. In short: fork, branch, make tests and docs changes, open a PR.

If your question isn't answered here, open an issue or reach out via the project's communication channels.
