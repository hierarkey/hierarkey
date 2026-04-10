# Guides

Practical how-to guides for common Hierarkey use cases.

## Getting started

| Guide | Description |
|-------|-------------|
| [Quick Start with Docker](quick-start-docker.md) | Get a local Hierarkey instance running in 5 minutes with Docker Compose |
| [App Integration](app-integration.md) | Fetch secrets from Python or Go applications |
| [Migrating from .env Files](migrating-from-dotenv.md) | Move an existing .env-based project to Hierarkey with minimal code changes |

## Production operations

| Guide | Description |
|-------|-------------|
| [Production Deployment](production-deployment.md) | TLS, passphrase master key, PostgreSQL TLS, systemd, hardening checklist |
| [Master Key Management](master-key-management.md) | Passphrase change, rotation, rekey, and disaster recovery |
| [Backup and Restore](backup-and-restore.md) | PostgreSQL backup strategy and full restore procedure |
| [Monitoring](monitoring.md) | Health endpoints, log-based alerting, and what to put on your dashboard |

## Organising secrets

| Guide | Description |
|-------|-------------|
| [Namespace Strategy](namespace-strategy.md) | Design guide for organising namespaces across teams and environments |
| [Multi-Environment Patterns](multi-environment.md) | Dev/staging/prod namespace patterns and secret promotion workflows |
| [Secret Types](secret-types.md) | Typed secrets: Password, URI, ConnectionString, CertificateKeyPair, and more |

## CI/CD and tooling

| Guide | Description |
|-------|-------------|
| [Kubernetes Sidecar](kubernetes-sidecar.md) | Keep secrets fresh in Kubernetes pods without restarting them |
| [GitHub Actions](github-actions.md) | Authenticate with Ed25519 and fetch secrets in GitHub CI workflows |
| [GitLab CI](gitlab-ci.md) | Authenticate with Ed25519 and fetch secrets in GitLab CI/CD pipelines |
| [Template Rendering](template-rendering.md) | Generate .env or config files from templates using `hkey template render` |

---

For a deeper walkthrough of concepts, see the [Tutorial series](../tutorial/).
For architecture details, see the [Architecture docs](../architecture/).
