# Docker images

This directory contains Dockerfiles for the two images used by Hierarkey.

## `postgres/` — PostgreSQL image

A thin wrapper around `postgres:16` that ships a custom `pg_hba.conf` for
optional TLS support. Used by `docker-compose.yaml` for local development.

```bash
docker compose up -d
```

The database, user, and password (`hierarkey`/`hierarkey`/`hierarkey`) are
created automatically. To enable TLS between the server and Postgres, set
`HIERARKEY_POSTGRES_TLS=1` before starting the stack.

## `hierarkey/` — Hierarkey server image

The production/demo image for the Hierarkey server. Built and published by
the release workflow; the image is also what you use if you want to run
Hierarkey without building from source.

### First boot

On first start the entrypoint runs migrations, creates a master key, and
bootstraps an admin account. If `HIERARKEY_ADMIN_PASSWORD` is not set, a
random password is generated and printed to the log once.

```
  ╔══════════════════════════════════════════════════╗
  ║           HIERARKEY DEMO CREDENTIALS            ║
  ║  Username : admin                               ║
  ║  Password : <generated>                         ║
  ╚══════════════════════════════════════════════════╝
```

Subsequent starts skip initialisation (guarded by a `.initialized` flag in
the data volume).

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_URL` | `postgres://hierarkey:hierarkey@postgres:5432/hierarkey` | Database connection URL |
| `HIERARKEY_BIND_ADDRESS` | `0.0.0.0:8080` | Address the server listens on |
| `HIERARKEY_ADMIN_USER` | `admin` | Admin account name created on first boot |
| `HIERARKEY_ADMIN_PASSWORD` | _(generated)_ | Admin password; printed once if not set |

### Data volume

The container stores master keys and the initialisation flag under `/data`.
Mount a persistent volume there to survive container restarts:

```bash
docker run -v hierarkey-data:/data \
  -e POSTGRES_URL=postgres://... \
  -p 8080:8080 \
  ghcr.io/hierarkey/hierarkey:latest
```

> **Note:** This image uses an `insecure` (plaintext) master key and plain
> HTTP — it is intended for development and evaluation, not production.
> See [docs/guides/production-deployment.md](../docs/guides/production-deployment.md)
> for a production setup.
