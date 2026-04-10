# Database

Hierarkey uses PostgreSQL as its only persistent store. All schema management is handled by sqlx migrations in `hierarkey-server/migrations/`.

## Migrations

Migration files are numbered sequentially: `0000_setup.sql` through `0078_platform_license.sql`. They are applied in order at startup. The server refuses to start if unapplied migrations exist.

---

## Key Tables

### accounts

```sql
CREATE TABLE accounts (
    id                      UUID        PRIMARY KEY,
    short_id                VARCHAR     UNIQUE NOT NULL,
    name                    VARCHAR     UNIQUE NOT NULL,
    account_type            account_type NOT NULL,       -- user | service | system
    status                  account_status NOT NULL,     -- active | locked | disabled | deleted
    status_reason           VARCHAR,
    status_changed_at       TIMESTAMPTZ,
    status_changed_by       UUID REFERENCES accounts(id) ON DELETE SET NULL,
    password_hash           VARCHAR,
    mfa_enabled             BOOLEAN     NOT NULL DEFAULT false,
    mfa_secret              VARCHAR,
    last_login_at           TIMESTAMPTZ,
    failed_login_attempts   INTEGER     NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    must_change_password    BOOLEAN     NOT NULL DEFAULT false,
    password_changed_at     TIMESTAMPTZ,
    full_name               VARCHAR,
    email                   VARCHAR,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ,
    deleted_at              TIMESTAMPTZ
);
```

### namespaces

```sql
CREATE TABLE namespaces (
    id                  UUID        PRIMARY KEY,
    short_id            VARCHAR     UNIQUE NOT NULL,
    namespace           VARCHAR     UNIQUE NOT NULL,
    status              resource_status NOT NULL,  -- active | disabled | deleted
    metadata            JSONB,
    status_reason       VARCHAR,
    status_changed_at   TIMESTAMPTZ,
    status_changed_by   UUID REFERENCES accounts(id) ON DELETE SET NULL,
    created_by          UUID REFERENCES accounts(id) ON DELETE SET NULL,
    updated_by          UUID REFERENCES accounts(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ
);
```

### masterkeys

```sql
CREATE TABLE masterkeys (
    id          UUID        PRIMARY KEY,
    short_id    VARCHAR     UNIQUE NOT NULL,
    usage       masterkey_usage   NOT NULL,   -- wrap_kek
    backend     masterkey_backend NOT NULL,   -- file | pkcs11
    file_type   masterkey_file_type,          -- insecure | passphrase (file backend only)
    status      masterkey_status  NOT NULL,   -- pending | active | draining | retired | unavailable
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES accounts(id) ON DELETE SET NULL
);
```

### keks

```sql
CREATE TABLE keks (
    id              UUID        PRIMARY KEY,
    short_id        VARCHAR     UNIQUE NOT NULL,
    algo            VARCHAR     NOT NULL,          -- aes256gcm
    ciphertext      BYTEA       NOT NULL,
    masterkey_id    UUID        REFERENCES masterkeys(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_rotated_at TIMESTAMPTZ,
    rotate_by       TIMESTAMPTZ,
    rotation_count  INTEGER     NOT NULL DEFAULT 0
);
```

### kek_assignments

Links a namespace to a KEK. Each rotation creates a new revision.

```sql
CREATE TABLE kek_assignments (
    namespace_id    UUID        NOT NULL REFERENCES namespaces(id),
    revision        INTEGER     NOT NULL,
    is_active       BOOLEAN     NOT NULL,
    kek_id          UUID        NOT NULL REFERENCES keks(id),
    masterkey_id    UUID        NOT NULL REFERENCES masterkeys(id),
    metadata        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace_id, revision)
);
```

### secrets

```sql
CREATE TABLE secrets (
    id               UUID        PRIMARY KEY,
    short_id         VARCHAR     UNIQUE NOT NULL,
    namespace_id     UUID        NOT NULL REFERENCES namespaces(id),
    ref_ns           VARCHAR     NOT NULL,
    ref_key          VARCHAR     NOT NULL,
    status           resource_status NOT NULL,
    active_revision  INTEGER     NOT NULL DEFAULT 1,
    latest_revision  INTEGER     NOT NULL DEFAULT 1,
    metadata         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ,
    deleted_at       TIMESTAMPTZ,
    UNIQUE (namespace_id, ref_ns, ref_key)
);
```

### secret_revisions

```sql
CREATE TABLE secret_revisions (
    id               UUID        PRIMARY KEY,
    short_id         VARCHAR     UNIQUE NOT NULL,
    secret_id        UUID        NOT NULL REFERENCES secrets(id),
    revision         INTEGER     NOT NULL,
    encrypted_secret BYTEA       NOT NULL,   -- AES-256-GCM ciphertext
    encrypted_dek    BYTEA       NOT NULL,   -- 60 bytes: nonce || dek_ciphertext || tag
    kek_id           UUID        NOT NULL REFERENCES keks(id),
    secret_alg       VARCHAR     NOT NULL,
    dek_alg          VARCHAR     NOT NULL,
    metadata         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ,
    UNIQUE (secret_id, revision)
);
```

### tokens (PATs)

```sql
CREATE TABLE tokens (
    id              UUID        PRIMARY KEY,
    short_id        VARCHAR     UNIQUE NOT NULL,
    account_id      UUID        NOT NULL REFERENCES accounts(id),
    description     VARCHAR     NOT NULL,
    token_hash      BYTEA       NOT NULL UNIQUE,
    token_suffix    VARCHAR     NOT NULL,
    purpose         token_purpose NOT NULL,   -- auth | refresh | change_pwd
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);
```

### RBAC tables

```sql
CREATE TABLE rbac_rules (
    id          UUID    PRIMARY KEY,
    short_id    VARCHAR UNIQUE NOT NULL,
    raw_spec    VARCHAR NOT NULL,
    spec_version INTEGER NOT NULL,
    effect      policy_effect NOT NULL,   -- allow | deny
    permission  VARCHAR NOT NULL,
    target_kind VARCHAR NOT NULL,
    pattern_raw VARCHAR NOT NULL,
    condition   VARCHAR,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES accounts(id),
    deleted_at  TIMESTAMPTZ
);

CREATE TABLE rbac_roles (
    id          UUID    PRIMARY KEY,
    short_id    VARCHAR UNIQUE NOT NULL,
    name        VARCHAR UNIQUE NOT NULL,
    is_system   BOOLEAN NOT NULL DEFAULT false,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES accounts(id),
    deleted_at  TIMESTAMPTZ
);

CREATE TABLE rbac_role_rules (
    role_id     UUID REFERENCES rbac_roles(id),
    rule_id     UUID REFERENCES rbac_rules(id),
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at  TIMESTAMPTZ,
    PRIMARY KEY (role_id, rule_id)
);

CREATE TABLE rbac_account_rules (
    account_id  UUID REFERENCES accounts(id),
    rule_id     UUID REFERENCES rbac_rules(id),
    valid_from  TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES accounts(id),
    PRIMARY KEY (account_id, rule_id)
);

CREATE TABLE rbac_account_roles (
    account_id  UUID REFERENCES accounts(id),
    role_id     UUID REFERENCES rbac_roles(id),
    valid_from  TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES accounts(id),
    PRIMARY KEY (account_id, role_id)
);
```

### platform_license

Single-row table; the `CHECK (id = 1)` constraint and `ON CONFLICT DO UPDATE` upsert pattern enforce the one-row limit.

```sql
CREATE TABLE platform_license (
    id           SMALLINT    PRIMARY KEY DEFAULT 1,
    license_json TEXT        NOT NULL,
    set_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT platform_license_single_row CHECK (id = 1)
);
```

---

## Custom Types (PostgreSQL Enums)

```sql
CREATE TYPE account_type     AS ENUM ('user', 'service', 'system');
CREATE TYPE account_status   AS ENUM ('active', 'locked', 'disabled', 'deleted');
CREATE TYPE resource_status  AS ENUM ('active', 'disabled', 'deleted');
CREATE TYPE masterkey_status AS ENUM ('pending', 'active', 'draining', 'retired', 'unavailable');
CREATE TYPE masterkey_backend AS ENUM ('file', 'pkcs11');
CREATE TYPE masterkey_file_type AS ENUM ('insecure', 'passphrase');
CREATE TYPE token_purpose    AS ENUM ('auth', 'refresh', 'change_pwd');
CREATE TYPE policy_effect    AS ENUM ('allow', 'deny');
```

---

## Soft Deletes

Most entities use soft deletes: `deleted_at` is set rather than removing the row. This preserves audit history and allows references from other tables (e.g., `created_by` on namespaces) to remain valid. Hard deletes are used only where cascading is appropriate.
