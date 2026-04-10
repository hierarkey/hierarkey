# RBAC

## Concepts

Access control in Hierarkey is built on three primitives:

- **Rule**: A single allow/deny statement with a permission and a target pattern.
- **Role**: A named, reusable collection of rules.
- **Binding**: Links an account to a rule (directly) or to a role (indirectly).

---

## Rule Spec Language

Rules are written in a human-readable spec language:

```
<effect> <permission> to <target> [where <condition>]
```

Examples:

```
allow secret:reveal to namespace /org/prod
allow secret:* to namespace /org/prod/**
deny  secret:delete to all
allow platform:admin to all
allow namespace:describe to namespace /public/*
```

### Effect

`allow` or `deny`

### Permissions

Permissions form a hierarchy — granting a broad permission also grants narrower ones:

```
platform:admin / all    (grants everything)
│
├── secret:*
│    ├── secret:reveal          reveal a secret value
│    ├── secret:list            list secrets in a namespace (names only, no values)
│    ├── secret:describe        read secret metadata
│    ├── secret:create          create a new secret
│    ├── secret:revise          write a new revision (update value)
│    ├── secret:delete          delete/tombstone a secret
│    ├── secret:restore         restore a deleted secret
│    ├── secret:update:meta     update metadata (description, labels) without changing value
│    ├── secret:lifecycle       manage lifecycle controls (enable/disable)
│    ├── secret:history:read    read revision history and metadata
│    └── secret:rollback        promote an older revision to current
│
├── namespace:*
│    ├── namespace:create       create a namespace
│    ├── namespace:list         list namespaces
│    ├── namespace:describe     read namespace metadata
│    ├── namespace:update:meta  update namespace metadata
│    ├── namespace:delete       delete a namespace
│    ├── namespace:policy:read  read RBAC policy attached to the namespace
│    ├── namespace:policy:write modify RBAC policy on the namespace
│    └── namespace:kek_rotate   rotate the namespace KEK
│
├── rbac:admin                  administer RBAC objects platform-wide
└── audit:read                  read audit events
```

`platform:admin` (or its alias `all`) subsumes all permissions. A rule granting `secret:*` grants all `secret:X` permissions. There are no `account:*` permissions — account management is a platform-admin operation.

### Target

Specifies which resources the rule applies to:

| Target syntax | Matches |
|---------------|---------|
| `to all` | Any resource (platform-level) |
| `to namespace /prod` | Exactly the namespace `/prod` |
| `to namespace /prod/**` | The namespace `/prod` and all descendants |
| `to namespace /prod/*` | Direct children of `/prod` only |
| `to secret /prod:app/db/*` | Secrets under path `app/db/` in `/prod` |

Pattern matching uses `**` for recursive descent and `*` for single-level wildcard.

### Condition (optional)

A WHERE clause that further restricts the rule to resources with matching metadata labels:

```
allow secret:reveal to namespace /prod where env=production
```

---

## Roles

A role groups multiple rules under a name. Roles can be system-defined (immutable, `is_system = true`) or user-created.

```
Role: "dev-read-only"
  ├── allow secret:reveal    to namespace /org/dev/**
  ├── allow secret:describe  to namespace /org/dev/**
  └── allow namespace:describe to namespace /org/dev/**
```

---

## Bindings

A binding attaches a rule or role to an account. All bindings support optional time windows:

| Binding type | Table |
|---|---|
| Account → Rule (direct) | `rbac_account_rules` |
| Account → Role (indirect) | `rbac_account_roles` |
| Label selector → Rule/Role | `rbac_label_bindings` |

Time windows: `valid_from` and `valid_until` allow temporary access grants.

---

## Permission Check

**Flow** for `is_allowed(account, permission, resource)`:

1. Fetch all rules bound to the account (direct rules + rules via roles).
2. Filter to rules with a matching permission (exact or via subsumption).
3. Filter to rules with a target pattern that matches the resource path.
4. Evaluate conditions against the resource's metadata labels.
5. Return `Allow` if any matching `allow` rule exists and no overriding `deny` rule exists.

`Deny` rules take precedence over `Allow` rules of equal specificity.

---

## Explain

**Endpoint**: `POST /v1/rbac/explain`

Returns the full reasoning for a permission decision:

```json
{
  "allowed": true,
  "matched_rule": { "id": "rul_abc123", "spec": "allow secret:reveal to namespace /org/prod" },
  "near_misses": [
    {
      "rule": { "id": "rul_def456", "spec": "allow secret:* to namespace /org/staging" },
      "reason": "TargetMismatch"
    }
  ]
}
```

Near-miss reasons: `PermissionMismatch`, `TargetMismatch`, `ConditionMismatch`, `LostToHigherSpecificity`.

---

## PlatformAdmin

An account bound to a rule granting `platform:admin to all` has unrestricted access to all resources. The RBAC engine short-circuits the full rule evaluation for PlatformAdmin accounts.

System accounts (`AccountType::System`) are also treated as platform admins.
