# Security Policy

## Supported Versions

Only the latest release of Hierarkey Community Edition receives security fixes.
If you are running an older version, please upgrade before reporting.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@hierarkey.com**. Include:

- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (even a rough one helps)
- The Hierarkey version (`hierarkey --version` / `hkey --version`)
- Any relevant configuration details (redact real secrets and credentials)

We will acknowledge your report within **3 business days** and aim to provide
an initial assessment within **7 business days**.

## Disclosure Policy

We follow a coordinated disclosure model:

1. You report the vulnerability privately to security@hierarkey.com.
2. We confirm the issue and agree on a timeline for a fix (typically ≤ 90 days
   for critical issues, sooner where possible).
3. We publish a fix and a security advisory simultaneously.
4. Credit is given to the reporter in the advisory unless you prefer to remain
   anonymous.

If we are unable to reproduce the issue or disagree that it is a vulnerability,
we will explain our reasoning. You are welcome to request a second review.

## Scope

Issues in scope include (but are not limited to):

- Authentication bypasses or token forgery
- Authorisation bypasses (RBAC evaluation errors)
- Encryption weaknesses or key material exposure
- Injection vulnerabilities (SQL, command, etc.)
- Denial-of-service vulnerabilities with a low attack complexity
- Sensitive data exposure in logs, error responses, or API responses

Out of scope:

- Vulnerabilities requiring physical access to the server
- Issues in dependencies not directly exploitable through Hierarkey
- Theoretical weaknesses without a practical attack path
- Issues affecting only the `insecure` master key provider (it is documented as
  development-only and must never be used in production)

## PGP Key

If you would like to encrypt your report, please request our PGP public key at
security@hierarkey.com before sending.
