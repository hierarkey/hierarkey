# Hierarkey Tutorial – Part 5: Auditing & Compliance Workflows

In the previous parts you:

- Set up the **Hierarkey server** (Part 1)
- Used the **`hkey` CLI** to manage secrets (Part 2)
- Configured **RBAC & permissions** (Part 3)
- Integrated Hierarkey with **apps, CI/CD, and Kubernetes** (Part 4)

This part explains what Hierarkey records for auditing, how to access it, and how to apply it to compliance and incident response workflows.

> **Commercial Edition feature**: Audit event storage, the audit query HTTP API, and chain integrity verification require a Hierarkey Commercial Edition license. In the community edition, audit events are not persisted — operations are not recorded to the database.
>
> The concepts and workflows in this chapter apply to the commercial edition. A dedicated `hkey audit` CLI subcommand is not yet available; audit data is accessible via the HTTP API directly (with `audit:read` permission).

---

## 1. What does Hierarkey audit?

Every important action generates an audit event. Categories include:

**Authentication & identity**
- User login / token issuance
- Token revocation / expiry

**Secret operations**
- `secret:reveal` — secret was decrypted and returned
- `secret:create` — new secret created
- `secret:revise` — new revision added
- `secret:delete` — secret deleted

**Namespace operations**
- Namespace create / update / disable / delete

**RBAC changes**
- Role create / update / delete
- Rule create / delete
- Binding add / remove

**Key management**
- Master key events (lock, unlock, rewrap)
- KEK rotation

Each event includes:
- **Timestamp** (UTC)
- **Principal** — who did it (account name + short ID)
- **Action** — what they did
- **Resource** — what was affected (e.g. `/prod/payments:db/password`)
- **Outcome** — success or denied
- **Client IP** — plain, hashed, or omitted depending on config

---

## 2. Audit log output

Hierarkey emits structured logs to **stdout**. In production you pipe these into your existing log infrastructure (Filebeat, Fluent Bit, Vector, Loki, Elasticsearch, Splunk, etc.).

This means storage, retention, and search are handled by your log platform — Hierarkey just produces the events.

---

## 3. Accessing audit events via the HTTP API

Until the CLI subcommand is available, query the audit API directly. You need the `audit:read` permission.

```bash
# List recent audit events (requires audit:read permission)
curl -s -H "Authorization: Bearer $HKEY_ACCESS_TOKEN" \
  "https://hierarkey.example.com/api/v1/audit?limit=20" | jq .

# Filter by resource
curl -s -H "Authorization: Bearer $HKEY_ACCESS_TOKEN" \
  "https://hierarkey.example.com/api/v1/audit?resource=/prod/payments:db/password" | jq .
```

Grant `audit:read` to an account:

```bash
hkey rbac role create --name auditor
hkey rbac role add --name auditor --rule "allow audit:read to platform"
hkey rbac bind --account security-team --role auditor
```

---

## 4. Common auditing workflows

### 4.1 Incident: "Who accessed this secret?"

Someone suspects a secret was accessed by an unauthorized party.

Steps:

1. Check all reveals for the secret in your log system, filtering for `action = secret:reveal` and `resource = /prod/payments:db/password`.
2. Identify which principals accessed it and at what times.
3. Compare against expected access patterns (only `ci-payments-deploy` and `k8s-payments-pod` should normally read it).
4. If you see an unexpected principal:
   - Immediately revise the secret: `hkey secret revise --ref /prod/payments:db/password --value "...new value..."`
   - Revoke the token used by the suspicious principal: `hkey pat revoke --id <id>`
   - Document the incident.

### 4.2 Incident: "Why was this request denied?"

A developer reports they can't access a secret they previously could.

Steps:

1. Check your audit logs for `result = denied` events for that principal.
2. Check current bindings: `hkey rbac bindings --account alice`
3. Explain a specific access decision: `hkey rbac explain --account alice --permission secret:reveal --secret /prod/payments:db/password`
4. Look for recent RBAC changes in the audit log (`action = rbac.*`).

You may find a role was removed, the namespace was renamed, or the policy is working exactly as intended (the access was revoked deliberately).

### 4.3 Periodic access review

For ISO 27001 / SOC 2-style compliance you need to periodically verify that access rights are appropriate.

Process:

1. Export current RBAC configuration:
   ```bash
   hkey rbac role list
   hkey rbac bindings
   ```

2. For each high-privilege role (`platform:admin`, `rbac:admin`, etc.):
   - Confirm only the right accounts are bound to it.
   - Verify those accounts actually need that level of access.
   - Check audit logs for any unexpected usage.

3. Document the review: who performed it, what was checked, what changes were made.

This documentation becomes evidence for external audits.

---

## 5. Privacy and data minimisation

Audit logs may contain personal data (account names, IPs). Practices to stay privacy-friendly:

**IP address handling** — The server's audit context captures the client IP. Handle it according to your privacy policy:
- Store raw IPs only if needed for investigation.
- Consider hashing IPs with a secret salt to allow correlation without storing identifiable data.
- Document your approach in your privacy policy.

**Retention** — Keep raw audit logs only as long as required (e.g. 90 days for operational use, longer for compliance). Use your log platform's retention settings.

**Minimal metadata** — Don't log more than you need. Audit events record the operation, not the secret value itself — the value never appears in logs.

---

## 6. Incident response checklist

When a security incident involves secrets managed in Hierarkey:

1. Identify all secrets that may be affected (namespaces, paths).
2. For each affected secret:
   - Query audit logs for `secret:reveal`, `secret:revise`, `secret:delete` in the relevant time window.
   - Identify all principals that accessed it.
3. Rotate secrets that may have been exposed: `hkey secret revise --ref <ref> --value "..."`
4. Revoke or limit access for suspicious principals: `hkey pat revoke --id <id>` or `hkey rbac unbind --account <name> --role <role>`
5. Review RBAC for any unauthorized changes: audit log `action = rbac.*`
6. Attach audit exports to the incident ticket as evidence.

---

## 7. Summary

Hierarkey records every important security event with principal, action, resource, and outcome. These events feed your existing log infrastructure for search, alerting, and compliance reporting.

Key operational practices:
- Grant `audit:read` only to security and compliance roles.
- Use your log platform for filtering, correlation, and retention.
- Run periodic access reviews against RBAC exports.
- Wire audit log patterns into your incident response playbooks.

Continue with **Part 6** for day-to-day account and token management.
