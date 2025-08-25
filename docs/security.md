# Security Overview

This page summarizes the project's security practices and links to the main `SECURITY.md` in the repository root.

## Responsible Disclosure

Please report security issues privately to the contact listed in `SECURITY.md`. The project aims to respond within 48 hours and will coordinate fixes and disclosure as necessary.

## Best practices for users

- Never commit private keys or decrypted files.
- Use restricted file permissions for key files and secrets.
- Use remote KMS/HSM when possible and mount secrets at runtime.

## Auditing and third-party libraries

- The project relies on the `cryptography` package; keep dependencies pinned and up to date.
- Regularly run `pip/poetry audit` or use automated dependency scanning in CI.

For the full policy and contact information, see `SECURITY.md` at the project root.
