# Hierarkey — Secret Management Platform

[![CI](https://github.com/hierarkey/hierarkey/actions/workflows/ci.yaml/badge.svg)](https://github.com/hierarkey/hierarkey/actions/workflows/ci.yaml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![CLA](https://github.com/hierarkey/hierarkey/actions/workflows/cla.yaml/badge.svg)](https://github.com/hierarkey/hierarkey/actions/workflows/cla.yaml)

```
 _   _ _____ ___________  ___  ______ _   __ _______   __
| | | |_   _|  ___| ___ \/ _ \ | ___ \ | / /|  ___\ \ / /
| |_| | | | | |__ | |_/ / /_\ \| |_/ / |/ / | |__  \ V /
|  _  | | | |  __||    /|  _  ||    /|    \ |  __|  \ /
| | | |_| |_| |___| |\ \| | | || |\ \| |\  \| |___  | |
\_| |_/\___/\____/\_| \_\_| |_/\_| \_\_| \_/\____/  \_/
```

Hierarkey is a secure, hierarchical secret management system with fine-grained
RBAC, encryption at rest, and a full audit trail.

- Multi-layer encryption (Master Key -> KEK -> DEK -> Secret) using AES-256-GCM
- Hierarchical namespaces to organize secrets by environment, team, or app
- Fine-grained RBAC with a role/rule system and wildcard pattern matching
- HSM support via PKCS#11 (YubiHSM, SoftHSM, AWS CloudHSM)
- Every operation is recorded with actor, timestamp, and outcome

## Quick Start

**Prerequisites:** Rust stable, PostgreSQL 14+, `jq`

```bash
git clone https://github.com/hierarkey/hierarkey.git
cd hierarkey
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

Generate a config file, apply migrations, and bootstrap:

```bash
hierarkey generate-config --output hierarkey-config.toml
# Edit hierarkey-config.toml — set your database URL at minimum.
# For local dev, also set:
#   [server]  mode = "http", allow_insecure_http = true
#   [masterkey]  default_file_type = "insecure", allow_insecure_masterkey = true

hierarkey update-migrations --config hierarkey-config.toml --yes
hierarkey bootstrap-master-key --config hierarkey-config.toml \
    --usage wrap_kek --provider passphrase --generate-passphrase
hierarkey bootstrap-admin-account --config hierarkey-config.toml \
    --name admin
# A random password is printed — copy it, you'll need it below.

hierarkey serve --config hierarkey-config.toml
```

Log in with the CLI client:

```bash
export HKEY_SERVER_URL=https://127.0.0.1:8443

# First login returns a change-password token (hkcp_...) — change your password first:
hkey auth login --name admin
export HKEY_ACCESS_TOKEN=hkcp_...
hkey account change-password --name admin --insecure-new-password 'MyNewPassword!'

# Then log in again to get a full-access token:
hkey auth login --name admin
export HKEY_ACCESS_TOKEN=hkat_...
```

For a full walkthrough see [docs/tutorial/](docs/tutorial/).

## Documentation

- [Architecture overview](docs/architecture/)
- [Encryption model](docs/architecture/encryption.md)
- [RBAC and permissions](docs/rbac.md)
- [Secret types](docs/guides/secret-types.md)
- [Production deployment](docs/guides/production-deployment.md)
- [Master key management](docs/guides/master-key-management.md)
- [TLS configuration](docs/tls.md)
- [Kubernetes sidecar](docs/guides/kubernetes-sidecar.md)
- [GitHub Actions](docs/guides/github-actions.md)
- [Monitoring](docs/guides/monitoring.md)
- [Community vs commercial edition](docs/editions.md)
- [Full tutorial](docs/tutorial/)

Full documentation: <https://docs.hierarkey.com>

## Commercial Edition

A [Hierarkey Commercial Edition](https://hierarkey.com) is available with additional
enterprise features on top of the community core:

- **Multi-factor authentication** — TOTP with authenticator apps and backup codes
- **Federated identity** — OIDC and Kubernetes TokenReview workload authentication
- **mTLS client certificates** — for service account authentication
- **HSM support** — PKCS#11 backend (YubiHSM, SoftHSM, AWS CloudHSM, and compatible devices)
- **Audit trail** — tamper-evident chain with query API and export
- **Prometheus metrics** — `/metrics` endpoint for monitoring integration

See [docs/editions.md](docs/editions.md) for a full feature comparison, or contact
[info@hierarkey.com](mailto:info@hierarkey.com) for licensing inquiries.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and
the pull request process. All contributors must sign the [CLA](CLA.md).

## License

This project is dual-licensed. The community edition is released under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). A separate
proprietary license applies to the
[Hierarkey Commercial Edition](https://hierarkey.com).

Third-party dependency licenses: [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)

## Support

- Issues: <https://github.com/hierarkey/hierarkey/issues>
- Security vulnerabilities: see [SECURITY.md](SECURITY.md)
- Commercial support: <info@hierarkey.com>
