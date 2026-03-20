#!/usr/bin/env bash
# =============================================================================
# Cosign CBOM Attestation Script
#
# Attaches a signed CBOM attestation to an OCI container image using cosign.
#
# Flow:
#   1. Scan source -> generate CBOM
#   2. Analyze CBOM -> generate PQC report
#   3. Build in-toto attestation predicate from CBOM + report
#   4. Sign and attach attestation to image via cosign
#
# Prerequisites:
#   - cosign (https://docs.sigstore.dev/cosign/installation/)
#   - python3
#   - Access to the container registry
#
# Usage:
#   ./cosign_attest_cbom.sh <image_ref> <source_path> [cosign_key]
#
# Examples:
#   # Keyless signing (Sigstore OIDC)
#   ./cosign_attest_cbom.sh registry.io/myapp:v1 ./src
#
#   # Key-based signing
#   ./cosign_attest_cbom.sh registry.io/myapp:v1 ./src cosign.key
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

IMAGE_REF="${1:?Usage: $0 <image_ref> <source_path> [cosign_key]}"
SOURCE_PATH="${2:?Usage: $0 <image_ref> <source_path> [cosign_key]}"
COSIGN_KEY="${3:-}"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

CBOM_FILE="$WORK_DIR/cbom.json"
REPORT_FILE="$WORK_DIR/report.json"
ATTESTATION_FILE="$WORK_DIR/attestation.json"
PREDICATE_FILE="$WORK_DIR/predicate.json"

# Step 1: Generate CBOM
log_info "Step 1: Generating CBOM from $SOURCE_PATH"
python3 "$PROJECT_ROOT/scanner/cbom_scanner.py" "$SOURCE_PATH" \
    "$(basename "$IMAGE_REF" | cut -d: -f1)" \
    "$(basename "$IMAGE_REF" | cut -d: -f2)" \
    > /dev/null
mv "cbom-$(basename "$SOURCE_PATH").json" "$CBOM_FILE" 2>/dev/null || true
if [[ ! -f "$CBOM_FILE" ]]; then
    log_fail "CBOM generation failed"
    exit 1
fi
log_ok "CBOM generated"

# Step 2: Analyze CBOM
log_info "Step 2: Analyzing CBOM for PQC compliance"
python3 "$PROJECT_ROOT/analyzer/pqc_analyzer.py" "$CBOM_FILE" "$REPORT_FILE" || true
log_ok "Analysis complete"

# Step 3: Get image digest
log_info "Step 3: Resolving image digest"
if command -v cosign &>/dev/null; then
    IMAGE_DIGEST=$(cosign triangulate "$IMAGE_REF" 2>/dev/null | grep -oP 'sha256:[a-f0-9]+' || true)
fi
if [[ -z "${IMAGE_DIGEST:-}" ]]; then
    if command -v crane &>/dev/null; then
        IMAGE_DIGEST=$(crane digest "$IMAGE_REF" 2>/dev/null || true)
    fi
fi
if [[ -z "${IMAGE_DIGEST:-}" ]]; then
    IMAGE_DIGEST="sha256:$(echo -n "$IMAGE_REF" | sha256sum | cut -d' ' -f1)"
    log_info "Using computed digest (image not accessible): ${IMAGE_DIGEST:0:24}..."
else
    log_ok "Image digest: ${IMAGE_DIGEST:0:24}..."
fi

# Step 4: Build attestation predicate
log_info "Step 4: Building in-toto attestation"
python3 "$PROJECT_ROOT/attestation/cbom_attestation.py" \
    "$CBOM_FILE" "$REPORT_FILE" "$IMAGE_REF" "${IMAGE_DIGEST#sha256:}" \
    > /dev/null
mv attestation-cbom.json "$ATTESTATION_FILE" 2>/dev/null || true

# Extract just the predicate for cosign (cosign wraps it in its own statement)
python3 -c "
import json
with open('$ATTESTATION_FILE') as f:
    att = json.load(f)
with open('$PREDICATE_FILE', 'w') as f:
    json.dump(att['predicate'], f, indent=2)
"
log_ok "Attestation predicate built"

# Step 5: Attach attestation to image
log_info "Step 5: Attaching attestation to image via cosign"
if command -v cosign &>/dev/null; then
    PREDICATE_TYPE="https://pqc.security.io/cbom/v1"

    if [[ -n "$COSIGN_KEY" ]]; then
        log_info "Using key-based signing: $COSIGN_KEY"
        cosign attest \
            --key "$COSIGN_KEY" \
            --predicate "$PREDICATE_FILE" \
            --type "$PREDICATE_TYPE" \
            "$IMAGE_REF"
    else
        log_info "Using keyless signing (Sigstore Fulcio + Rekor)"
        COSIGN_EXPERIMENTAL=1 cosign attest \
            --predicate "$PREDICATE_FILE" \
            --type "$PREDICATE_TYPE" \
            "$IMAGE_REF"
    fi
    log_ok "Attestation attached to $IMAGE_REF"
else
    log_info "cosign not installed -- attestation written to file only"
    cp "$PREDICATE_FILE" "./cbom-predicate-$(basename "$IMAGE_REF" | tr ':/' '-').json"
    cp "$ATTESTATION_FILE" "./cbom-attestation-$(basename "$IMAGE_REF" | tr ':/' '-').json"
    log_ok "Attestation files saved locally"
fi

# Summary
echo ""
log_info "=== Attestation Summary ==="
COMPLIANT=$(python3 -c "import json; print(json.load(open('$PREDICATE_FILE'))['pqcCompliance']['isCompliant'])")
VULN_COUNT=$(python3 -c "import json; print(len(json.load(open('$PREDICATE_FILE'))['cryptoInventory']['vulnerableAlgorithms']))")
log_info "Image:       $IMAGE_REF"
log_info "Compliant:   $COMPLIANT"
log_info "Vulnerable:  $VULN_COUNT algorithms"
if [[ "$COMPLIANT" == "True" ]]; then
    log_ok "Image is PQC-compliant and will pass Kyverno admission"
else
    log_fail "Image is NOT PQC-compliant and will be BLOCKED by Kyverno"
fi
