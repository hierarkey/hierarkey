#!/usr/bin/env bash
set -euo pipefail

if [ ! -e "./hierarkey-config.toml" ]; then
  echo "Error: hierarkey-config.toml not found in current directory." >&2
  exit 1
fi

if [ ! -e "./target/release" ]; then
  echo "Error: target/release directory not found. Please build the project first." >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"

BENCH_SCRIPT="${PROJECT_DIR}/benchmark/benchmark.js"
RESULTS_BASE_DIR="${PROJECT_DIR}/benchmark/results"
TMP_DIR="${PROJECT_DIR}/.bench-tmp"

LABEL="${1:-baseline}"
TIMESTAMP="$(date -u +'%Y-%m-%dT%H-%M-%SZ')"
RUN_DIR="${RESULTS_BASE_DIR}/${TIMESTAMP}-${LABEL}"

RESULTS_JSON="${RUN_DIR}/results.json"
RESULTS_JSON_GZ="${RUN_DIR}/results.json.gz"
RUN_LOG="${RUN_DIR}/run.log"
SUMMARY_TXT="${RUN_DIR}/summary.txt"
NOTES_TXT="${RUN_DIR}/notes.txt"

# Optional config locations to archive if they exist
APP_CONFIG_FILES=(
  "${PROJECT_DIR}/hierarkey-config.toml"
)

# Optional extra benchmark-related files to archive if they exist
BENCH_FILES=(
  "${PROJECT_DIR}/benchmark/benchmark.js"
  "${ROOT_DIR}/scripts/bench-it.sh"
)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

log() {
  printf '[bench-it] %s\n' "$*"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

copy_if_exists() {
  local src="$1"
  local dst_dir="$2"

  if [[ -f "$src" ]]; then
    cp -f "$src" "$dst_dir/"
  fi
}

sanitize_env_file() {
  local src="$1"
  local dst="$2"

  if [[ ! -f "$src" ]]; then
    return 0
  fi

  sed -E \
    -e 's/^(.*(SECRET|TOKEN|PASSWORD|PASS|KEY)=).*/\1[REDACTED]/I' \
    -e 's/^(DATABASE_URL=).*/\1[REDACTED]/I' \
    "$src" > "$dst"
}

extract_summary() {
  local log_file="$1"
  local out_file="$2"

  {
    echo "Benchmark run summary"
    echo "====================="
    echo
    echo "Timestamp (UTC): ${TIMESTAMP}"
    echo "Label: ${LABEL}"
    echo "Results archive: ${RESULTS_JSON_GZ}"
    echo

    echo "Git"
    echo "---"
    git -C "${PROJECT_DIR}" rev-parse HEAD 2>/dev/null | sed 's/^/commit: /' || true
    git -C "${PROJECT_DIR}" branch --show-current 2>/dev/null | sed 's/^/branch: /' || true
    if git -C "${PROJECT_DIR}" diff --quiet && git -C "${PROJECT_DIR}" diff --cached --quiet; then
      echo "dirty: no"
    else
      echo "dirty: yes"
    fi
    echo

    echo "Extracted k6 metrics"
    echo "--------------------"
    grep -E 'Setup complete|Teardown:|checks_total|checks_succeeded|checks_failed|hierarkey_auth_latency|hierarkey_create_latency|hierarkey_error_rate|hierarkey_reveal_latency|hierarkey_search_latency|http_req_duration|http_req_failed|http_reqs|iterations' "$log_file" || true
    echo
  } > "$out_file"
}

# -----------------------------------------------------------------------------
# Prepare directories
# -----------------------------------------------------------------------------

mkdir -p "$RUN_DIR"
mkdir -p "${RUN_DIR}/benchmark"
mkdir -p "${RUN_DIR}/source"
mkdir -p "${RUN_DIR}/config"
mkdir -p "${RUN_DIR}/system"
mkdir -p "${TMP_DIR}"

log "Run directory: ${RUN_DIR}"

# -----------------------------------------------------------------------------
# Archive benchmark files
# -----------------------------------------------------------------------------

for f in "${BENCH_FILES[@]}"; do
  copy_if_exists "$f" "${RUN_DIR}/benchmark"
done

cat > "${RUN_DIR}/benchmark/scenario.txt" <<EOF
Benchmark script: ${BENCH_SCRIPT}
Label: ${LABEL}

This file is intended for human notes about:
- scenario definitions
- thresholds
- expected namespace
- seed count
- auth mode
Update this file manually or generate it from your benchmark config if desired.
EOF

# -----------------------------------------------------------------------------
# Archive git/source metadata
# -----------------------------------------------------------------------------

if have_cmd git; then
  {
    echo "repo: ${PROJECT_DIR}"
    echo "branch: $(git -C "${PROJECT_DIR}" branch --show-current 2>/dev/null || echo unknown)"
    echo "commit: $(git -C "${PROJECT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
    if git -C "${PROJECT_DIR}" diff --quiet && git -C "${PROJECT_DIR}" diff --cached --quiet; then
      echo "dirty: no"
    else
      echo "dirty: yes"
    fi
  } > "${RUN_DIR}/source/git.txt"

  git -C "${PROJECT_DIR}" status --short > "${RUN_DIR}/source/git-status.txt" 2>/dev/null || true
  git -C "${PROJECT_DIR}" diff > "${RUN_DIR}/source/git-diff.patch" 2>/dev/null || true
  git -C "${PROJECT_DIR}" diff --cached > "${RUN_DIR}/source/git-diff-staged.patch" 2>/dev/null || true
fi

# -----------------------------------------------------------------------------
# Archive config
# -----------------------------------------------------------------------------

for f in "${APP_CONFIG_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    base="$(basename "$f")"
    if [[ "$base" == ".env" || "$base" == ".env.local" ]]; then
      sanitize_env_file "$f" "${RUN_DIR}/config/${base}.public"
    else
      cp -f "$f" "${RUN_DIR}/config/"
    fi
  fi
done

cat > "${RUN_DIR}/config/dataset.txt" <<EOF
Fill this in after or during the run if it is not generated automatically.

Suggested contents:
- namespace used
- seeded secret count
- secret size
- benchmark users/roles
- database freshness (fresh/reused)
- migration/schema version
EOF

# -----------------------------------------------------------------------------
# Archive system information
# -----------------------------------------------------------------------------

{
  echo "date_utc=$(date -u --iso-8601=seconds 2>/dev/null || date -u)"
  echo "hostname=$(hostname 2>/dev/null || echo unknown)"
  echo "kernel=$(uname -a 2>/dev/null || echo unknown)"
  echo
  if have_cmd lsb_release; then
    lsb_release -a 2>&1 || true
    echo
  fi
  if have_cmd lscpu; then
    lscpu || true
    echo
  fi
  if have_cmd free; then
    free -h || true
    echo
  fi
  if have_cmd df; then
    df -h || true
    echo
  fi
} > "${RUN_DIR}/system/system.txt"

{
  echo "k6: $(k6 version 2>/dev/null || echo unavailable)"
  echo "git: $(git --version 2>/dev/null || echo unavailable)"
  echo "bash: ${BASH_VERSION}"
  if have_cmd psql; then
    echo "psql: $(psql --version 2>/dev/null || echo unavailable)"
  fi
  if have_cmd docker; then
    echo "docker: $(docker --version 2>/dev/null || echo unavailable)"
  fi
  if have_cmd kubectl; then
    echo "kubectl: $(kubectl version --client=true --output=yaml 2>/dev/null | tr '\n' ' ' || echo unavailable)"
  fi
} > "${RUN_DIR}/system/versions.txt"

# -----------------------------------------------------------------------------
# Create notes placeholder
# -----------------------------------------------------------------------------

cat > "${NOTES_TXT}" <<EOF
Notes for this run:
- Purpose:
- Environment:
- Namespace:
- Seed count:
- Special conditions:
- Observations:
EOF

# -----------------------------------------------------------------------------
# Run benchmark
# -----------------------------------------------------------------------------

log "Starting benchmark"
log "Script: ${BENCH_SCRIPT}"

set +e
k6 run --out "json=${RESULTS_JSON}" "${BENCH_SCRIPT}" 2>&1 | tee "${RUN_LOG}"
K6_EXIT=${PIPESTATUS[0]}
set -e

if [[ -f "${RESULTS_JSON}" ]]; then
  log "Compressing results.json"
  gzip -f "${RESULTS_JSON}"
fi

# -----------------------------------------------------------------------------
# Summarize
# -----------------------------------------------------------------------------

extract_summary "${RUN_LOG}" "${SUMMARY_TXT}"

cat > "${RUN_DIR}/RESULT.txt" <<EOF
exit_code=${K6_EXIT}
status=$([[ ${K6_EXIT} -eq 0 ]] && echo PASS || echo FAIL)
run_dir=${RUN_DIR}
results_file=${RESULTS_JSON_GZ}
run_log=${RUN_LOG}
summary_file=${SUMMARY_TXT}
EOF

if [[ ${K6_EXIT} -eq 0 ]]; then
  log "Benchmark completed successfully"
else
  log "Benchmark completed with failures (exit code ${K6_EXIT})"
fi

log "Artifacts stored in: ${RUN_DIR}"

exit "${K6_EXIT}"