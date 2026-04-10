#!/usr/bin/env bash
# setup-test-hsm.sh — Initialise a SoftHSM2 token for Hierarkey integration tests.
#
# Usage:
#   ./tools/setup-test-hsm.sh
#
# Environment (all have defaults):
#   SOFTHSM2_DIR      — directory for the SoftHSM2 data and config (default: /tmp/softhsm2-hierarkey)
#   SOFTHSM2_CONF     — path where the generated softhsm2.conf is written (default: $SOFTHSM2_DIR/softhsm2.conf)
#   HSM_TOKEN_LABEL   — token label (default: hierarkey-test)
#   HSM_SO_PIN        — Security Officer PIN (default: so-pin-1234)
#   HSM_USER_PIN      — User PIN (default: user-pin-5678)
#
# After running this script:
#   export SOFTHSM2_CONF=<value printed by the script>
#   export HIERARKEY_TEST_PKCS11=1
#   cargo test --features pkcs11 -- pkcs11
#
# To find the SoftHSM2 library on your system:
#   find /usr -name libsofthsm2.so 2>/dev/null
#   # common locations:
#   #   /usr/lib/softhsm/libsofthsm2.so
#   #   /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
#   #   /usr/local/lib/softhsm/libsofthsm2.so (macOS via Homebrew)

set -euo pipefail

SOFTHSM2_DIR="${SOFTHSM2_DIR:-/tmp/softhsm2-hierarkey}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-${SOFTHSM2_DIR}/softhsm2.conf}"
HSM_TOKEN_LABEL="${HSM_TOKEN_LABEL:-hierarkey-test}"
HSM_SO_PIN="${HSM_SO_PIN:-so-pin-1234}"
HSM_USER_PIN="${HSM_USER_PIN:-user-pin-5678}"

TOKEN_DIR="${SOFTHSM2_DIR}/tokens"

echo "==> Setting up SoftHSM2 test token"
echo "    SOFTHSM2_DIR  : ${SOFTHSM2_DIR}"
echo "    SOFTHSM2_CONF : ${SOFTHSM2_CONF}"
echo "    Token label   : ${HSM_TOKEN_LABEL}"

# Check softhsm2-util is installed
if ! command -v softhsm2-util &>/dev/null; then
    echo ""
    echo "ERROR: softhsm2-util not found. Install SoftHSM2 first:"
    echo "  Debian/Ubuntu : sudo apt-get install softhsm2"
    echo "  RHEL/Fedora   : sudo yum install softhsm"
    echo "  macOS         : brew install softhsm"
    exit 1
fi

# Create directories
mkdir -p "${TOKEN_DIR}"

# Write softhsm2.conf
cat > "${SOFTHSM2_CONF}" <<EOF
# SoftHSM2 configuration for Hierarkey integration tests
directories.tokendir = ${TOKEN_DIR}
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

export SOFTHSM2_CONF

# Delete existing token with the same label (if any)
if softhsm2-util --show-slots 2>/dev/null | grep -q "Token Label:.*${HSM_TOKEN_LABEL}"; then
    echo "==> Removing existing token '${HSM_TOKEN_LABEL}'"
    softhsm2-util --delete-token --token "${HSM_TOKEN_LABEL}" || true
fi

# Initialise a new token
echo "==> Initialising token '${HSM_TOKEN_LABEL}'"
softhsm2-util \
    --init-token \
    --free \
    --label "${HSM_TOKEN_LABEL}" \
    --so-pin "${HSM_SO_PIN}" \
    --pin "${HSM_USER_PIN}"

echo ""
echo "==> SoftHSM2 token ready."
echo ""
echo "To run PKCS#11 integration tests:"
echo ""
echo "  export SOFTHSM2_CONF=${SOFTHSM2_CONF}"
echo "  export HIERARKEY_TEST_PKCS11=1"
echo "  export HIERARKEY_TEST_PKCS11_TOKEN_LABEL=${HSM_TOKEN_LABEL}"
echo "  export HIERARKEY_TEST_PKCS11_USER_PIN=${HSM_USER_PIN}"
echo "  cargo test --features pkcs11 -- pkcs11"
echo ""

# Find the SoftHSM2 library automatically
SOFTHSM_LIB=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so \
    /usr/local/lib/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
    if [ -f "${candidate}" ]; then
        SOFTHSM_LIB="${candidate}"
        break
    fi
done

if [ -n "${SOFTHSM_LIB}" ]; then
    echo "  Found SoftHSM2 library: ${SOFTHSM_LIB}"
    echo "  export HIERARKEY_TEST_PKCS11_MODULE=${SOFTHSM_LIB}"
else
    echo "  SoftHSM2 library not found automatically."
    echo "  Set HIERARKEY_TEST_PKCS11_MODULE to the path of libsofthsm2.so."
    echo "  Find it with: find /usr -name libsofthsm2.so 2>/dev/null"
fi

echo ""
echo "  Sample hierarkey config snippet:"
echo ""
echo "    [masterkey.pkcs11]"
echo "    enabled = true"
echo "    module = \"${SOFTHSM_LIB:-/path/to/libsofthsm2.so}\""
echo "    token_label = \"${HSM_TOKEN_LABEL}\""
echo "    pin_source = \"env:HIERARKEY_PKCS11_PIN\""
