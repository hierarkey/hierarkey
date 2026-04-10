# Hierarkey Benchmarks

## Prerequisites

1. **k6** installed — https://k6.io/docs/get-started/installation/
2. A running Hierarkey server with:
   - Admin account created (username + password)
   - Master key named `root` created, active, and unlocked
   - The `/bench` namespace does **not** need to exist — setup creates it

## Quick start

```sh
# Defaults: http://localhost:8080, admin/admin, 10 VUs, 30s per scenario
k6 run bench/benchmark.js

# Custom server / credentials
HKEY_URL=https://my-server:8443 \
HKEY_ADMIN_USER=admin \
HKEY_ADMIN_PASS=my-password \
k6 run bench/benchmark.js

# Higher load
HKEY_VUS=50 HKEY_DURATION=60s k6 run bench/benchmark.js
```

## Environment variables

| Variable         | Default                  | Description                  |
|------------------|--------------------------|------------------------------|
| `HKEY_URL`       | `http://localhost:8080`  | Server base URL              |
| `HKEY_ADMIN_USER`| `admin`                  | Admin account name           |
| `HKEY_ADMIN_PASS`| `admin`                  | Admin password               |
| `HKEY_VUS`       | `10`                     | Virtual users per scenario   |
| `HKEY_DURATION`  | `30s`                    | Duration per scenario        |

## Scenarios

The script runs five scenarios **sequentially** (each waits for the previous to finish):

| Scenario       | What it measures                              |
|----------------|-----------------------------------------------|
| `auth_only`    | Login + whoami round-trip latency/throughput  |
| `secret_write` | Secret creation (encryption + DB write)       |
| `secret_read`  | Secret reveal (DB read + decryption)          |
| `secret_search`| Search within a namespace (DB query)          |
| `mixed`        | 10% create / 60% reveal / 30% search         |

Setup seeds 100 secrets into `/bench` before the scenarios run. These are reused by the read and mixed scenarios.

## Metrics

Custom metrics reported in the summary:

| Metric                       | Description                        |
|------------------------------|------------------------------------|
| `hierarkey_auth_latency`     | Auth token + whoami latency (ms)   |
| `hierarkey_create_latency`   | Secret create latency (ms)         |
| `hierarkey_reveal_latency`   | Secret reveal latency (ms)         |
| `hierarkey_search_latency`   | Secret search latency (ms)         |
| `hierarkey_secrets_created`  | Total secrets created              |
| `hierarkey_error_rate`       | Fraction of failed requests        |

## Thresholds (pass/fail)

| Metric                     | Threshold  |
|----------------------------|------------|
| Auth latency p95           | < 500 ms   |
| Create latency p95         | < 1000 ms  |
| Reveal latency p95         | < 500 ms   |
| Search latency p95         | < 500 ms   |
| Error rate                 | < 1%       |

## Tips

- Run against a **local** server first to establish a baseline, then against a deployed instance.
- Increase `HKEY_VUS` gradually to find where latency starts climbing.
- The mixed scenario includes a 100ms think-time (`sleep(0.1)`) to simulate realistic pacing — remove it for maximum throughput testing.
- Use `k6 run --out json=results.json bench/benchmark.js` to save raw metrics for later analysis.
