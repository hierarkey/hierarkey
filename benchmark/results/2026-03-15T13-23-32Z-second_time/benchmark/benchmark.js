/**
 * Hierarkey k6 Benchmark
 *
 * Prerequisites (server must be pre-bootstrapped):
 *   - Admin account exists with username/password set via env vars
 *   - A master key named "root" must exist and be active (unlocked)
 *   - Benchmark namespace /bench will be created on setup
 *
 * Usage:
 *   k6 run bench/benchmark.js
 *
 * Environment variables (with defaults):
 *   HKEY_URL           Server base URL          (default: http://localhost:8080)
 *   HKEY_ADMIN_USER    Admin account name        (default: admin)
 *   HKEY_ADMIN_PASS    Admin password            (default: admin)
 *   HKEY_VUS           Virtual users             (default: 10)
 *   HKEY_DURATION      Test duration             (default: 30s)
 *
 * Scenarios:
 *   auth_only      - Repeated logins (measures Argon2 + token issuance throughput)
 *   secret_write   - Create a new secret each iteration (token reused per VU)
 *   secret_read    - Reveal an existing secret (token reused per VU)
 *   secret_search  - Search secrets with namespace scope (token reused per VU)
 *   mixed          - Realistic mix: 10% create, 60% reveal, 30% search
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import encoding from "k6/encoding";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.HKEY_URL        || "http://localhost:8080";
const ADMIN    = __ENV.HKEY_ADMIN_USER || "admin";
const PASS     = __ENV.HKEY_ADMIN_PASS || "admin";
const VUS      = parseInt(__ENV.HKEY_VUS      || "10");
const DURATION = __ENV.HKEY_DURATION          || "30s";

// Namespace used for all benchmark secrets
const BENCH_NS = "/bench";

// Pre-seeded secrets for read/reveal benchmarks (populated in setup())
const SEED_COUNT = 100;

// ---------------------------------------------------------------------------
// Per-VU token cache
//
// k6 module-level variables are per-VU: each VU gets its own copy.
// getToken() logs in once on the first iteration and reuses the token
// for all subsequent iterations of that VU.
// Only authScenario calls login() directly — that's what it benchmarks.
// ---------------------------------------------------------------------------

let vuToken = null;

function getToken() {
    if (vuToken === null) {
        vuToken = login();
    }
    return vuToken;
}

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const authLatency    = new Trend("hierarkey_auth_latency",    true);
const createLatency  = new Trend("hierarkey_create_latency",  true);
const revealLatency  = new Trend("hierarkey_reveal_latency",  true);
const searchLatency  = new Trend("hierarkey_search_latency",  true);
const errorRate      = new Rate("hierarkey_error_rate");
const secretsCreated = new Counter("hierarkey_secrets_created");

// ---------------------------------------------------------------------------
// k6 options
// ---------------------------------------------------------------------------

export const options = {
    scenarios: {
        // --- Argon2 + token issuance throughput ---
        auth_only: {
            executor: "constant-vus",
            vus: VUS,
            duration: DURATION,
            exec: "authScenario",
            tags: { scenario: "auth_only" },
        },

        // --- Secret creation throughput (token reused per VU) ---
        secret_write: {
            executor: "constant-vus",
            vus: VUS,
            duration: DURATION,
            exec: "writeScenario",
            tags: { scenario: "secret_write" },
            startTime: `${parseDuration(DURATION) + 5}s`,
        },

        // --- Secret reveal throughput (token reused per VU) ---
        secret_read: {
            executor: "constant-vus",
            vus: VUS,
            duration: DURATION,
            exec: "readScenario",
            tags: { scenario: "secret_read" },
            startTime: `${parseDuration(DURATION) * 2 + 10}s`,
        },

        // --- Search throughput (token reused per VU) ---
        secret_search: {
            executor: "constant-vus",
            vus: VUS,
            duration: DURATION,
            exec: "searchScenario",
            tags: { scenario: "secret_search" },
            startTime: `${parseDuration(DURATION) * 3 + 15}s`,
        },

        // --- Realistic mixed workload (token reused per VU) ---
        mixed: {
            executor: "ramping-vus",
            startVUs: 1,
            stages: [
                { duration: "10s", target: VUS },
                { duration: DURATION, target: VUS },
                { duration: "10s", target: 0 },
            ],
            exec: "mixedScenario",
            tags: { scenario: "mixed" },
            startTime: `${parseDuration(DURATION) * 4 + 20}s`,
        },
    },

    thresholds: {
        // Auth is Argon2 — intentionally slow, just track it (no hard limit)
        "hierarkey_auth_latency":   ["p(95)<10000"],
        // Creates involve crypto — allow headroom
        "hierarkey_create_latency": ["p(95)<500"],
        // Reveals involve crypto decryption
        "hierarkey_reveal_latency": ["p(95)<200"],
        // Search is a DB query
        "hierarkey_search_latency": ["p(95)<200"],
        // Overall error rate < 1%
        "hierarkey_error_rate":     ["rate<0.01"],
    },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse duration string like "30s", "2m" to integer seconds. */
function parseDuration(d) {
    if (d.endsWith("m")) return parseInt(d) * 60;
    if (d.endsWith("s")) return parseInt(d);
    return parseInt(d);
}

const JSON_HEADERS = { "Content-Type": "application/json" };

function authHeaders(token) {
    return {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
    };
}

/**
 * Login and return an access token.
 * Intentionally slow due to Argon2 — only call this once per VU via getToken(),
 * or deliberately in authScenario to measure that cost.
 */
function login() {
    const res = http.post(
        `${BASE_URL}/v1/auth/login`,
        JSON.stringify({
            account_name: ADMIN,
            password:     PASS,
            description:  "k6 benchmark token",
            ttl_minutes:  60,
            scope:        "auth",
        }),
        { headers: JSON_HEADERS, tags: { name: "auth/login" } }
    );

    const ok = check(res, {
        "login 200": (r) => r.status === 200,
        "login has token": (r) => {
            try { return JSON.parse(r.body).data.access_token !== undefined; }
            catch (_) { return false; }
        },
    });
    errorRate.add(!ok);
    authLatency.add(res.timings.duration);

    if (!ok) return null;
    return JSON.parse(res.body).data.access_token;
}

/** Generate a unique secret reference within the bench namespace. */
function randomRef(prefix) {
    return `${BENCH_NS}:${prefix}-${__VU}-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

/** Base64-encode a plaintext string. */
function b64(s) {
    return encoding.b64encode(s);
}

// ---------------------------------------------------------------------------
// Setup: create namespace + seed SEED_COUNT secrets for read benchmarks
// ---------------------------------------------------------------------------

export function setup() {
    const token = login();
    if (!token) {
        throw new Error("setup: login failed — check HKEY_ADMIN_USER / HKEY_ADMIN_PASS");
    }
    const headers = authHeaders(token);

    // Create benchmark namespace (ignore conflict if it already exists)
    const nsRes = http.post(
        `${BASE_URL}/v1/namespaces`,
        JSON.stringify({ namespace: BENCH_NS, description: "k6 benchmark namespace", labels: {} }),
        { headers }
    );
    const nsOk = nsRes.status === 200 || nsRes.status === 409;
    if (!nsOk) {
        console.error(`Namespace creation failed: HTTP ${nsRes.status} — ${nsRes.body}`);
        throw new Error(`setup: could not create namespace ${BENCH_NS}`);
    }
    check(nsRes, { "namespace created or exists": () => nsOk });

    // Seed secrets for read scenarios
    const seedRefs = [];
    for (let i = 0; i < SEED_COUNT; i++) {
        const ref = `${BENCH_NS}:seed-${i}`;
        const createRes = http.post(
            `${BASE_URL}/v1/secrets`,
            JSON.stringify({
                sec_ref:     ref,
                value_b64:   b64(`benchmark-seed-value-${i}`),
                secret_type: "opaque",
                description: `Benchmark seed secret ${i}`,
                labels:      { bench: "true" },
            }),
            { headers }
        );
        // 200 = created, 409 = already exists from a previous run — both fine
        if (createRes.status === 200 || createRes.status === 409) {
            seedRefs.push(ref);
        } else if (i === 0) {
            // Log the first failure to diagnose issues early
            console.error(`First seed secret failed: HTTP ${createRes.status} — ${createRes.body}`);
        }
    }

    if (seedRefs.length === 0) {
        throw new Error("setup: no seed secrets were created — reveal/mixed scenarios will not work");
    }

    console.log(`Setup complete. Seeded ${seedRefs.length} secrets in ${BENCH_NS}.`);
    return { seedRefs };
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

export function teardown(data) {
    console.log(`Teardown: ${data.seedRefs.length} seed secrets were used.`);
}

// ---------------------------------------------------------------------------
// Scenario: auth_only
//
// Deliberately calls login() every iteration — this measures Argon2 + token
// issuance throughput. Expect low req/s; that is intentional and correct.
// ---------------------------------------------------------------------------

export function authScenario() {
    const token = login();
    if (!token) return;

    // Also verify the token works (whoami — JWT validation only, no Argon2)
    const res = http.get(
        `${BASE_URL}/v1/auth/whoami`,
        { headers: authHeaders(token), tags: { name: "auth/whoami" } }
    );
    check(res, { "whoami 200": (r) => r.status === 200 });
    errorRate.add(res.status !== 200);
}

// ---------------------------------------------------------------------------
// Scenario: secret_write
// ---------------------------------------------------------------------------

export function writeScenario() {
    const token = getToken();
    if (!token) return;

    const ref = randomRef("write");
    const res = http.post(
        `${BASE_URL}/v1/secrets`,
        JSON.stringify({
            sec_ref:     ref,
            value_b64:   b64(`benchmark-secret-${__VU}-${__ITER}`),
            secret_type: "opaque",
            description: "k6 benchmark secret",
            labels:      { bench: "true", vu: String(__VU) },
        }),
        { headers: authHeaders(token), tags: { name: "secret/create" } }
    );

    const ok = check(res, { "create 200": (r) => r.status === 200 });
    errorRate.add(!ok);
    createLatency.add(res.timings.duration);
    if (ok) secretsCreated.add(1);
}

// ---------------------------------------------------------------------------
// Scenario: secret_read
// ---------------------------------------------------------------------------

export function readScenario(data) {
    const token = getToken();
    if (!token) return;

    // Pick a seed secret pseudo-randomly (deterministic per VU+iter for reproducibility)
    const idx = (__VU * 7 + __ITER * 13) % data.seedRefs.length;
    const ref  = data.seedRefs[idx];

    const res = http.post(
        `${BASE_URL}/v1/secrets/reveal`,
        JSON.stringify({ sec_ref: ref }),
        { headers: authHeaders(token), tags: { name: "secret/reveal" } }
    );

    const ok = check(res, {
        "reveal 200": (r) => r.status === 200,
        "reveal has value": (r) => {
            try { return JSON.parse(r.body).data.value_b64 !== undefined; }
            catch (_) { return false; }
        },
    });
    errorRate.add(!ok);
    revealLatency.add(res.timings.duration);
}

// ---------------------------------------------------------------------------
// Scenario: secret_search
// ---------------------------------------------------------------------------

export function searchScenario() {
    const token = getToken();
    if (!token) return;

    const res = http.post(
        `${BASE_URL}/v1/secrets/search`,
        JSON.stringify({
            scope: { namespace_prefixes: [BENCH_NS] },
            page:  { limit: 20, offset: 0 },
        }),
        { headers: authHeaders(token), tags: { name: "secret/search" } }
    );

    const ok = check(res, { "search 200": (r) => r.status === 200 });
    errorRate.add(!ok);
    searchLatency.add(res.timings.duration);
}

// ---------------------------------------------------------------------------
// Scenario: mixed — realistic workload (10% create, 60% reveal, 30% search)
// ---------------------------------------------------------------------------

export function mixedScenario(data) {
    const token = getToken();
    if (!token) return;

    const roll = Math.random();

    if (roll < 0.10) {
        // Create
        const ref = randomRef("mixed");
        const res = http.post(
            `${BASE_URL}/v1/secrets`,
            JSON.stringify({
                sec_ref:     ref,
                value_b64:   b64(`mixed-${__VU}-${__ITER}`),
                secret_type: "opaque",
                labels:      { bench: "true" },
            }),
            { headers: authHeaders(token), tags: { name: "secret/create" } }
        );
        const ok = check(res, { "mixed create 200": (r) => r.status === 200 });
        errorRate.add(!ok);
        createLatency.add(res.timings.duration);
        if (ok) secretsCreated.add(1);

    } else if (roll < 0.70) {
        // Reveal
        const idx = (__VU * 7 + __ITER * 13) % data.seedRefs.length;
        const res = http.post(
            `${BASE_URL}/v1/secrets/reveal`,
            JSON.stringify({ sec_ref: data.seedRefs[idx] }),
            { headers: authHeaders(token), tags: { name: "secret/reveal" } }
        );
        const ok = check(res, { "mixed reveal 200": (r) => r.status === 200 });
        errorRate.add(!ok);
        revealLatency.add(res.timings.duration);

    } else {
        // Search
        const res = http.post(
            `${BASE_URL}/v1/secrets/search`,
            JSON.stringify({
                scope: { namespace_prefixes: [BENCH_NS] },
                page:  { limit: 20, offset: 0 },
            }),
            { headers: authHeaders(token), tags: { name: "secret/search" } }
        );
        const ok = check(res, { "mixed search 200": (r) => r.status === 200 });
        errorRate.add(!ok);
        searchLatency.add(res.timings.duration);
    }

    sleep(0.1); // small think-time to avoid hammering in mixed scenario
}
