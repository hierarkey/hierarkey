# Hierarkey RBAC Path Matching

This document explains how **namespace path matching** works in Hierarkey RBAC rules.

Patterns are predictable, readable, and do not use regex.

---

## General rules

All paths are normalized before matching:

- They start with `/`
- They have no trailing `/`

Wildcards (`*`, `**`) have specific, limited semantics — they do **not** behave like shell globs or regex.

---

## Match kinds

### 1) Exact

**Pattern:** `/prod`

Match exactly this path and nothing else.

**Matches:** `/prod`

**Does NOT match:** `/production`, `/prod/foo`, `/prod/x/y`

Use when you want to target **one specific namespace** with no children.

---

### 2) Same-segment prefix

**Pattern:** `/prod*`

Match anything that starts with `/prod` **within the same path segment**. The `*` never crosses a `/`.

**Matches:** `/prod`, `/production`, `/prod1`, `/prodlef`

**Does NOT match:** `/prod/foo`, `/production/foo`, `/prod/x/y`

Use when multiple top-level namespaces share a name prefix but you **do not** want to include their subtrees.

---

### 3) Direct children only

**Pattern:** `/prod/*`

Match paths that are **exactly one level below** `/prod`. Does not match `/prod` itself, and does not descend further.

**Matches:** `/prod/foo`, `/prod/bar`

**Does NOT match:** `/prod`, `/prod/foo/bar`, `/production/foo`

Use when you want to grant access to the immediate children of a namespace but not deeper descendants.

---

### 4) Full subtree (descendants only)

**Pattern:** `/prod/**`

Match any path **anywhere under** `/prod`, at any depth. Does **not** match `/prod` itself.

**Matches:** `/prod/foo`, `/prod/foo/bar`, `/prod/a/b/c`

**Does NOT match:** `/prod`, `/production/foo`, `/prod1/foo`

Use when you want access to everything inside a namespace tree.

---

## Comparison table

| Pattern | Matches | Does NOT match |
|---|---|---|
| `/prod` | `/prod` | `/production`, `/prod/foo` |
| `/prod*` | `/prod`, `/production`, `/prod1` | `/prod/foo`, `/production/foo` |
| `/prod/*` | `/prod/foo`, `/prod/bar` | `/prod`, `/prod/foo/bar`, `/production/foo` |
| `/prod/**` | `/prod/foo`, `/prod/foo/bar` | `/prod`, `/production/foo` |

---

## Key distinctions

### `/prod/*` vs `/prod/**`

These are the two most commonly confused patterns:

| | `/prod/*` | `/prod/**` |
|---|---|---|
| Matches `/prod` itself | No | No |
| Matches `/prod/foo` | Yes | Yes |
| Matches `/prod/foo/bar` | **No** | Yes |
| Depth | Direct children only | Any depth |

If you want broad namespace access, use `/prod/**`. Use `/prod/*` only when you want exactly one level of children.

### `/prod` vs `/prod/**`

Neither pattern matches the other's targets:

- `/prod` matches only `/prod` — not any children
- `/prod/**` matches only children of `/prod` — not `/prod` itself

To match both `/prod` and all its descendants, you need two rules:

```
allow namespace:describe to namespace /prod
allow namespace:*        to namespace /prod/**
```

---

## RBAC examples

Allow reading secrets in the direct children of `/prod`:

```
allow secret:reveal to namespace /prod/*
```

Allow reading secrets anywhere under `/prod` (full subtree):

```
allow secret:reveal to namespace /prod/**
```

Allow access to namespaces matching a name prefix (no subtrees):

```
allow namespace:list to namespace /prod*
```

Allow access to exactly one namespace:

```
allow secret:reveal to namespace /prod/api
```

---

## Mental model

- `/prod` -> *this exact namespace only*
- `/prod*` -> *this name and similarly-named siblings (no children)*
- `/prod/*` -> *direct children of this namespace (one level)*
- `/prod/**` -> *everything inside this namespace tree (any depth)*
