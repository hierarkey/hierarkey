# Community vs Commercial Edition

Hierarkey is available in two editions:

- **Community Edition** - open source under AGPL-3.0, free to use, self-hosted.
- **Commercial Edition** - adds additional features and requires a license from [hierarkey.com](https://hierarkey.com).

Both editions share the same core codebase. Commercial features are enabled by
installing a signed license file.


## Community Edition

The community edition includes the full core feature set:

- Multi-layer encryption at rest: Master Key -> KEK -> DEK -> AES-256-GCM
- Hierarchical namespaces to organize secrets by environment, team, or app
- Secret revisions with rollback to any previous version
- Key rotation at every layer: master key rewrap, KEK rotation, DEK rewrap
- Fine-grained RBAC with roles, rules, bindings, and wildcard path matching
- Labels on namespaces, secrets, accounts, and master keys
- Personal Access Tokens (PAT) for authentication
- HTTP API and `hkey` CLI
- Passphrase-protected master key


## Commercial Edition

The commercial edition adds the following on top of the community feature set:

**Authentication**
- Multi-factor authentication (TOTP with authenticator apps, backup codes)
- mTLS client certificate authentication for service accounts
- Federated authentication: OIDC (OpenID Connect) and Kubernetes TokenReview workload identity

**Infrastructure**
- HSM support via PKCS#11 (YubiHSM, SoftHSM, AWS CloudHSM, and compatible devices)
- Prometheus metrics endpoint (`/metrics`)

**Compliance**
- Full audit trail: tamper-evident chain, query API, and export


## Licensing

When no license is installed, the server runs in community mode. All community
features are available without a license file.

A commercial license is a signed JSON file. Install it via:

```
hkey license set --file license.json
```

After installation, the server activates the licensed features immediately
without a restart. If a license expires, a 7-day grace period keeps audit
writes running to avoid gaps during renewal. All other commercial features
revert to community mode when the grace period ends.

For licensing inquiries contact [info@hierarkey.com](mailto:info@hierarkey.com).
