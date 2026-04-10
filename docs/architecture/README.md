# Hierarkey Architecture

This directory contains architectural documentation for the Hierarkey secret management system.

## Documents

| File | Description |
|------|-------------|
| [overview.md](overview.md) | System purpose, crate structure, and high-level design |
| [domain-model.md](domain-model.md) | Core entities: Account, Namespace, Secret, MasterKey, KEK, DEK, PAT |
| [encryption.md](encryption.md) | Key hierarchy, AES-256-GCM encryption, master key providers |
| [services-and-managers.md](services-and-managers.md) | Service and manager layers, responsibilities |
| [http-api.md](http-api.md) | HTTP routes, AppState, middleware, error handling |
| [authentication.md](authentication.md) | Login, PATs, service account tokens, token refresh |
| [rbac.md](rbac.md) | Rules, roles, bindings, permission model, rule spec grammar |
| [startup.md](startup.md) | Startup sequence and initialization checks |
| [cli.md](cli.md) | hkey CLI binary structure and commands |
| [database.md](database.md) | Database schema, key tables, migration strategy |
