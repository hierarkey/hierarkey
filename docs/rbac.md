# Role-Based Access Control (RBAC)

Hierarkey uses a role/rule/binding system to control access to resources.

---

## Core concepts

### Roles, rules, and bindings

- A **rule** is a single policy statement: `allow secret:reveal to namespace /prod/**`
- A **role** groups one or more rules under a name: `prod-reader`
- A **binding** attaches a subject (an account or label selector) to a role

Access is granted by binding an account to a role that contains matching rules.

### Evaluation principles

- **Default deny** — if no rule matches, access is denied
- **Most-specific-wins** — when multiple rules match, only the most specific ones are considered
- **Deny overrides allow** — if any of the most-specific matching rules is `deny`, access is denied

---

## Rule syntax

```
<allow|deny> <permission> to <target-kind> <pattern> [where <k>=<v> [and <k>=<v> ...]]
```

Keywords (`allow`, `deny`, `to`, target kinds) are case-insensitive.

### Examples

```
allow secret:reveal       to namespace /prod/**
allow secret:*            to namespace /prod/**
deny  secret:delete       to secret    /prod:db/*
allow namespace:describe  to namespace /prod
allow rbac:admin          to platform
allow platform:admin      to all
allow secret:reveal       to secret    /prod:db/* where env=prod
allow namespace:*         to account   svc-*      where team=backend and env=prod
```

---

## Permissions

Permissions are namespaced tokens of the form `resource:action`.

**Secret permissions:**

| Permission | Description |
|---|---|
| `secret:reveal` | Decrypt and return a secret value |
| `secret:list` | List secret paths within a namespace |
| `secret:describe` | Read secret metadata |
| `secret:create` | Create a new secret |
| `secret:revise` | Add a new revision to an existing secret |
| `secret:delete` | Delete a secret |
| `secret:restore` | Restore a previously deleted secret |
| `secret:update:meta` | Update secret metadata without changing the value |
| `secret:history:read` | Read the full revision history |
| `secret:rollback` | Activate an older revision as the current one |
| `secret:lifecycle` | Manage secret lifecycle controls |
| `secret:*` | All secret permissions |

**Namespace permissions:**

| Permission | Description |
|---|---|
| `namespace:create` | Create a namespace |
| `namespace:list` | List visible namespaces |
| `namespace:describe` | Read namespace metadata |
| `namespace:update:meta` | Update namespace metadata |
| `namespace:delete` | Delete a namespace |
| `namespace:policy:read` | Read RBAC bindings/roles attached to the namespace |
| `namespace:policy:write` | Modify RBAC policy for the namespace |
| `namespace:kek_rotate` | Rotate the namespace KEK linkage |
| `namespace:*` | All namespace permissions |

**Platform-level permissions:**

| Permission | Description |
|---|---|
| `audit:read` | Read audit events |
| `rbac:admin` | Administer roles, rules, and bindings platform-wide |
| `platform:admin` | Full platform administration (superuser) |
| `all` | Wildcard — equivalent to `platform:admin` |

---

## Target kinds

| Target kind | Pattern format | Example |
|---|---|---|
| `namespace` | namespace path pattern | `namespace /prod/**` |
| `secret` | `<namespace-pattern>:<secret-path-pattern>` | `secret /prod:db/*` |
| `account` | account name pattern | `account svc-*` |
| `platform` | no pattern (singleton) | `platform` |
| `all` | no pattern (singleton) | `all` |

### Namespace patterns

| Pattern | Type | Matches | Does NOT match |
|---|---|---|---|
| `/prod` | exact | `/prod` | `/production`, `/prod/foo` |
| `/prod*` | prefix (same segment) | `/prod`, `/production`, `/prod1` | `/prod/foo`, `/production/foo` |
| `/prod/*` | direct children | `/prod/foo`, `/prod/bar` | `/prod`, `/prod/foo/bar` |
| `/prod/**` | full subtree | `/prod/foo`, `/prod/foo/bar` | `/prod`, `/production/foo` |

> **Note:** `/prod/*` matches only one level below `/prod` — it does **not** include `/prod` itself and does **not** descend further. Use `/prod/**` for a full subtree.

See [rbac-matches.md](rbac-matches.md) for detailed matching rules and examples.

### Secret patterns

Secret patterns combine a namespace pattern and a secret path pattern separated by `:`:

```
<namespace-pattern>:<secret-path-pattern>
```

The secret path pattern follows the same wildcard rules as namespace patterns, but without the leading `/`.

| Pattern | Matches |
|---|---|
| `/prod:db/password` | exactly that one secret |
| `/prod:db/*` | any direct child of `db/` in exactly `/prod` |
| `/prod:db/**` | any secret under `db/` at any depth in exactly `/prod` |
| `/prod/**:db/*` | any direct child of `db/` in any child namespace of `/prod` |
| `/prod:*` | any direct-child path in exactly `/prod` (no sub-paths) |
| `all` | any secret in any namespace |

### Account patterns

| Pattern | Matches |
|---|---|
| `alice` | exactly `alice` |
| `svc-*` | any account starting with `svc-` |
| `all` | any account |

Account patterns do not support `/` or `:`.

---

## The `where` clause

Rules can optionally carry a condition that restricts when the rule fires, matching against labels on the resource or subject:

```
allow secret:reveal to namespace /prod/** where env=prod
allow secret:reveal to namespace /prod/** where env=prod and tier=internal
```

Multiple clauses are ANDed together. If the condition does not match, the rule is skipped.

> **Note**: The `where` clause syntax is accepted by the parser and stored in the database, but condition evaluation is not yet implemented. Rules with a `where` clause currently fire unconditionally (the condition is ignored at evaluation time).

---

## CLI usage

```bash
# Create a role
hkey rbac role create --name prod-reader --description "Read secrets in prod"

# Add a rule to the role
hkey rbac role add --name prod-reader --rule "allow secret:reveal to namespace /prod/**"

# Bind an account to the role
hkey rbac bind --name alice --role prod-reader

# Show bindings for an account
hkey rbac bindings --account alice

# Explain a permission decision
hkey rbac explain --account alice --permission secret:reveal --secret /prod:db/password

# List roles
hkey rbac role list
```

---

## Policy cheat sheet

### 1. Prod / test separation

Developers can read everywhere, but cannot delete in prod:

```
allow secret:reveal  to namespace /test/**
allow secret:*       to namespace /test/**
allow secret:reveal  to namespace /prod/**
deny  secret:delete  to namespace /prod/**
```

### 2. Service account scoped to one namespace

`svc-api` may reveal secrets only in `/prod/api`:

```
allow secret:reveal to namespace /prod/api
```

Everything else is denied by default.

### 3. Database admin carve-out

Admins can do anything except delete prod DB credentials:

```
allow secret:*      to all
deny  secret:delete to secret /prod:db/**
```

### 4. Platform administrator

A break-glass account with full access:

```
allow platform:admin to all
```

Use sparingly; audit heavily.

### 5. Read-only auditors

Auditors can read secrets and namespaces, but nothing else:

```
allow secret:reveal    to all
allow namespace:list   to all
allow namespace:describe to all
```

### 6. Namespace policy delegate

An account that can manage RBAC within a specific namespace only:

```
allow namespace:policy:read  to namespace /prod
allow namespace:policy:write to namespace /prod
```

---

## Recommended conventions

- Use `/prod/**` (subtree) for broad namespace scoping, not `/prod/*` (direct children only)
- Use `:*` for "any direct-child secret path", `:**` for full secret path subtrees
- Keep `deny` rules specific (targeted carve-outs), not broad
- Prefer `platform:admin` over `all` for clarity
- Treat RBAC rules as security-critical code; review them like you would ACLs
