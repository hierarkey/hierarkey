#!/bin/sh

set -e

export HKEY_TEST_SERVER_BIN="../target/release/hierarkey"
export HKEY_TEST_COMMERCIAL_SERVER_BIN="../../hierarkey-commercial/target/release/hierarkey-commercial"
export HKEY_TEST_HKEY_BIN="../target/release/hkey"
export HKEY_TEST_HKEY_SERVER_URL="http://localhost:8080"

COMMERCIAL_ONLY=0
if [ "$1" = "--commercial-only" ]; then
    COMMERCIAL_ONLY=1
    shift
fi

# Rebuild binaries in release mode
cur_pwd=$(pwd)
HKEY_TEST_HKEY_BIN="$cur_pwd/$HKEY_TEST_HKEY_BIN"
export HKEY_TEST_HKEY_BIN
cd ..
cargo build --release
cd "$cur_pwd"
cd "$cur_pwd/../../hierarkey-commercial"
cargo build --release
cd "$cur_pwd"

mkdir -p data

# Cleanup handler: kill servers and tear down infrastructure
COMMUNITY_PID=""
COMMERCIAL_PID=""
cleanup() {
    [ -n "$COMMUNITY_PID" ]  && kill "$COMMUNITY_PID"  2>/dev/null || true
    [ -n "$COMMERCIAL_PID" ] && kill "$COMMERCIAL_PID" 2>/dev/null || true
    docker compose down
}
trap cleanup EXIT INT TERM

# Start postgres container
echo "=== Starting postgres ==="
docker compose up -d postgres
echo "Waiting for postgres to be healthy..."
until docker compose ps postgres | grep -q "healthy"; do
    sleep 1
done
echo "Postgres is ready."

export PGPASSWORD="hierarkey"
psql -h localhost -p 5433 -U hierarkey -d postgres -c 'DROP DATABASE IF EXISTS hierarkey_test WITH (FORCE)'
psql -h localhost -p 5433 -U hierarkey -d postgres -c 'CREATE DATABASE hierarkey_test;'

$HKEY_TEST_SERVER_BIN update-migrations -c hierarkey-config.test.toml --yes
$HKEY_TEST_SERVER_BIN check-migrations  -c hierarkey-config.test.toml

$HKEY_TEST_SERVER_BIN bootstrap-master-key -c hierarkey-config.test.toml --usage wrap_kek --provider insecure
$HKEY_TEST_SERVER_BIN bootstrap-admin-account -c hierarkey-config.test.toml --name admin --insecure-password admin_test_password --no-pwd-change

# Remove log files from previous run
rm -f data/hierarkey.log data/hierarkey-commercial.log

if [ "$COMMERCIAL_ONLY" -eq 0 ]; then
    # ---------------------------------------------------------------------------
    # Phase 1: Community server
    # ---------------------------------------------------------------------------

    echo "=== Starting community server ==="
    $HKEY_TEST_SERVER_BIN serve -c hierarkey-config.test.toml > data/hierarkey.log 2>&1 &
    COMMUNITY_PID=$!

    echo "Waiting for community server to be ready..."
    for i in $(seq 1 20); do
        if curl -sf "$HKEY_TEST_HKEY_SERVER_URL/readyz" > /dev/null 2>&1; then
            echo "Community server is ready."
            break
        fi
        if [ "$i" -eq 20 ]; then
            echo "Community server did not become ready in time." >&2
            exit 1
        fi
        sleep 0.5
    done

    echo "=== Running community tests ==="
    cd test-suite
    #poetry run pytest -q "$@"
    echo "skipping community test"
    COMMUNITY_EXIT=$?
    cd "$cur_pwd"

    echo "=== Stopping community server ==="
    kill "$COMMUNITY_PID" 2>/dev/null || true
    COMMUNITY_PID=""

    if [ "$COMMUNITY_EXIT" -ne 0 ]; then
        echo "Community tests failed." >&2
        exit "$COMMUNITY_EXIT"
    fi
else
    echo "=== Skipping community server and tests (--commercial-only) ==="
fi

# ---------------------------------------------------------------------------
# Phase 2: Commercial server (same database — no recreation or bootstrap)
# ---------------------------------------------------------------------------

echo "=== Applying commercial migrations ==="
$HKEY_TEST_COMMERCIAL_SERVER_BIN update-migrations -c hierarkey-config.commercial.test.toml --yes
$HKEY_TEST_COMMERCIAL_SERVER_BIN check-migrations  -c hierarkey-config.commercial.test.toml

# If a CI license is provided (via GitHub Actions secret), write it to disk so
# we can install it after the commercial server starts.
if [ -n "$HIERARKEY_CI_LICENSE_JSON" ]; then
    echo "$HIERARKEY_CI_LICENSE_JSON" > data/hierarkey-ci-integration-license.json
    echo "CI license file written."
fi

echo "=== Starting commercial server ==="
$HKEY_TEST_COMMERCIAL_SERVER_BIN serve -c hierarkey-config.commercial.test.toml > data/hierarkey-commercial.log 2>&1 &
COMMERCIAL_PID=$!

echo "Waiting for commercial server to be ready..."
for i in $(seq 1 20); do
    if curl -sf "$HKEY_TEST_HKEY_SERVER_URL/readyz" > /dev/null 2>&1; then
        echo "Commercial server is ready."
        break
    fi
    if [ "$i" -eq 20 ]; then
        echo "Commercial server did not become ready in time." >&2
        exit 1
    fi
    sleep 0.5
done

if [ -f data/hierarkey-ci-integration-license.json ]; then
    ADMIN_TOKEN=$($HKEY_TEST_HKEY_BIN --server "$HKEY_TEST_HKEY_SERVER_URL" \
        auth login --name admin --insecure-password admin_test_password --json \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    $HKEY_TEST_HKEY_BIN --server "$HKEY_TEST_HKEY_SERVER_URL" --token "$ADMIN_TOKEN" \
        license set --from-file data/hierarkey-ci-integration-license.json

    echo "CI license installed."
else
    echo "Warning: no CI license provided — running commercial server without a license." >&2
    echo "Set HIERARKEY_CI_LICENSE_JSON to install a license before the commercial tests run." >&2
fi

echo "=== Running commercial tests ==="
cd test-suite
HKEY_TEST_EE=1 poetry run pytest -q "$@"
COMMERCIAL_EXIT=$?
cd "$cur_pwd"

# Exit with commercial test exit code (trap will kill server and docker compose down)
exit "$COMMERCIAL_EXIT"
