# Monitoring

How to monitor a production Hierarkey deployment and know when things go wrong.

---

## Health endpoints

| Endpoint | Purpose | When it returns non-200 |
|----------|---------|------------------------|
| `GET /healthz` | Liveness check | Server process is unhealthy |
| `GET /readyz` | Readiness check | Server is not ready to serve requests |

Use `/healthz` for liveness probes (restart the pod/process if it fails). Use `/readyz` for readiness probes (remove from load balancer rotation until it passes).

### What `/readyz` checks

- Database connectivity
- Master key unlocked (if a passphrase backend is configured)
- No critical background task failures

If any check fails, `/readyz` returns HTTP 503 with a JSON body indicating which check failed.

---

## 1. Kubernetes probes

```yaml
containers:
  - name: hierarkey
    image: jaytaph/hierarkey:latest
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 15
      failureThreshold: 3

    readinessProbe:
      httpGet:
        path: /readyz
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
      failureThreshold: 3
```

---

## 2. Uptime monitoring (external)

Use any uptime monitoring service (Uptime Kuma, Better Stack, Datadog Synthetics, Pingdom) to poll `/healthz` every minute from outside the cluster.

Alert when:
- `/healthz` returns non-200 for 2+ consecutive checks
- Response time exceeds 2 seconds

---

## 3. Log-based alerting

Hierarkey emits structured JSON logs when `format = "json"` is set in the config. Key log fields:

| Field | Values to alert on |
|-------|--------------------|
| `level` | `"error"`, `"critical"` |
| `msg` | Contains `"masterkey"` + `"lock"` |
| `msg` | Contains `"database"` + `"connect"` |
| `msg` | Contains `"auth"` + `"fail"` (repeated, may indicate brute force) |

### Example: Grafana Loki alert rule

```logql
# Alert when error rate exceeds 5 errors/minute
count_over_time({app="hierarkey"} |= "\"level\":\"error\"" [1m]) > 5
```

### Example: CloudWatch Metrics filter

```bash
aws logs put-metric-filter \
  --log-group-name /hierarkey/production \
  --filter-name HierakeyErrors \
  --filter-pattern '{ $.level = "error" }' \
  --metric-transformations \
    metricName=HierakeyErrorCount,metricNamespace=Hierarkey,metricValue=1
```

---

## 4. Database monitoring

Monitor the PostgreSQL connection pool and query latency. Key queries to watch:

```sql
-- Long-running queries (>5 seconds)
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state = 'active'
  AND now() - pg_stat_activity.query_start > interval '5 seconds';

-- Table sizes (catch unexpected growth)
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

Alert when:
- Active connections approach `max_connections`
- Replication lag exceeds your RPO (if using a standby)
- Disk usage exceeds 80%

---

## 5. Recommended alert summary

| Alert | Condition | Severity |
|-------|-----------|----------|
| Server down | `/healthz` non-200 for 2 min | Critical |
| Not ready | `/readyz` non-200 for 5 min | High |
| Master key locked | `/readyz` returns `master_key: locked` | High |
| Error rate spike | >10 errors/min in logs | High |
| Database unreachable | Connection errors in logs | Critical |
| High response latency | p99 > 1s over 5 min | Medium |
| Disk usage | PostgreSQL disk > 80% | Medium |
| Expired PATs | PATs expiring in next 7 days | Low |

---

## 6. Prometheus metrics (Commercial Edition)

The [Hierarkey Commercial Edition](https://hierarkey.com/commercial) exposes a `/metrics` endpoint in Prometheus text format. The community edition does not expose a metrics endpoint — use the PostgreSQL exporter and log-based alerting (sections 3–4 above) instead.

### Server configuration

Enable the metrics endpoint in `hierarkey-config.toml`:

```toml
[metrics]
enabled      = true
bind_address = "0.0.0.0:9090"   # separate port from the main API
```

Restrict access to port 9090 at the network level (firewall, Kubernetes `NetworkPolicy`). The endpoint is unauthenticated.

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: hierarkey
    static_configs:
      - targets: ['hierarkey.internal:9090']
    scrape_interval: 15s
```

### Kubernetes scrape annotation

```yaml
# on the Hierarkey Pod or Service
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port:   "9090"
  prometheus.io/path:   "/metrics"
```

### Grafana dashboard

Key panels to build:

| Panel | What to graph |
|-------|--------------|
| Request rate | HTTP requests/sec by endpoint and status code |
| Latency | p50/p95/p99 request duration per endpoint |
| Secret reveals | Reveal operations per minute, labelled by namespace |
| Auth failures | Failed logins per minute (spike -> possible brute force) |
| Master key status | Lock/unlock events and current state |
| DB pool | Connection pool utilisation and wait time |
| Active tokens | Count of valid access tokens over time |

---

## 7. Dashboards (community edition)

Without the Prometheus endpoint, build dashboards from:

- `/readyz` polling history
- Secret reveal volume (audit log events)
- Failed authentication attempts (log-based)

---

## 8. Audit log monitoring

Hierarkey records all mutating operations in the audit log. Use these events to detect anomalies:

| Event to watch | Anomaly indicator |
|----------------|-----------------|
| `auth.login.fail` | Multiple failures for the same account in short time |
| `secret.reveal` | Unusual spike in reveals from a single account |
| `account.admin.grant` | Any grant not initiated by known admin |
| `rbac.bind` | New role bindings outside a change window |
| `pat.create` with long TTL | PAT TTL > 30 days created for a service account |

Forward audit log events to your SIEM (Splunk, Elastic, Sentinel) for retention and alerting.
