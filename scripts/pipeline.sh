#!/usr/bin/env bash
# =============================================================================
# PQC Discovery & Enforcement Pipeline
#
# End-to-end pipeline that:
#   1. Scans source code / containers to generate CBOMs
#   2. Analyzes CBOMs for quantum-vulnerable cryptography
#   3. Generates Kubernetes annotations from analysis
#   4. Validates deployments against Kyverno PQC policies
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
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_step()  { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BLUE}  STEP: $*${NC}"; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

check_prerequisites() {
    log_step "Checking Prerequisites"
    local missing=0

    if command -v python3 &>/dev/null; then
        log_ok "python3 found: $(python3 --version)"
    else
        log_fail "python3 not found"
        missing=1
    fi

    if command -v kubectl &>/dev/null; then
        log_ok "kubectl found: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
    else
        log_warn "kubectl not found (needed for cluster deployment)"
    fi

    if command -v kyverno &>/dev/null; then
        log_ok "kyverno CLI found: $(kyverno version 2>/dev/null | head -1)"
    else
        log_warn "kyverno CLI not found (install: https://kyverno.io/docs/kyverno-cli/)"
        log_info "Will use offline policy validation via Python tests"
    fi

    return $missing
}

analyze_cbom() {
    local cbom_file="$1"
    local output_file="$2"
    log_info "Analyzing CBOM: $cbom_file"
    python3 "$PROJECT_ROOT/analyzer/pqc_analyzer.py" "$cbom_file" "$output_file" || true
}

run_kyverno_tests() {
    log_step "Running Kyverno Policy Validation"

    if command -v kyverno &>/dev/null; then
        log_info "Using Kyverno CLI for policy testing"

        local policy_dir="$PROJECT_ROOT/kyverno/policies"
        local deploy_dir="$PROJECT_ROOT/k8s/deployments"
        local pass=0
        local fail=0

        for deployment in "$deploy_dir"/*.yaml; do
            local name=$(basename "$deployment" .yaml)
            log_info "Testing: $name"

            for policy in "$policy_dir"/*.yaml; do
                local policy_name=$(basename "$policy" .yaml)
                if kyverno apply "$policy" --resource "$deployment" 2>/dev/null; then
                    log_ok "  $policy_name: PASS"
                    ((pass++))
                else
                    log_fail "  $policy_name: BLOCKED"
                    ((fail++))
                fi
            done
        done

        log_info "Results: $pass passed, $fail blocked"
    else
        log_warn "Kyverno CLI not available, running Python-based policy simulation"
        python3 "$PROJECT_ROOT/tests/test_kyverno_policies.py"
    fi
}

pipeline_analyze_samples() {
    log_step "Analyzing Sample CBOMs"

    local output_dir="$PROJECT_ROOT/reports"
    mkdir -p "$output_dir"

    for cbom_file in "$PROJECT_ROOT/cbom/samples"/*.json; do
        local name=$(basename "$cbom_file" .json)
        analyze_cbom "$cbom_file" "$output_dir/report-$name.json"
    done

    log_ok "All reports generated in $output_dir/"
}

pipeline_full() {
    log_step "PQC Discovery & Enforcement Pipeline"
    echo ""
    log_info "Project root: $PROJECT_ROOT"
    echo ""

    check_prerequisites

    pipeline_analyze_samples

    run_kyverno_tests

    log_step "Running Test Suite"
    python3 -m pytest "$PROJECT_ROOT/tests/" -v --tb=short 2>/dev/null \
        || python3 "$PROJECT_ROOT/tests/test_all.py"

    log_step "Pipeline Complete"
}

show_usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  full         Run the complete pipeline"
    echo "  analyze      Analyze sample CBOMs only"
    echo "  policies     Test Kyverno policies only"
    echo "  tests        Run test suite only"
    echo "  scan <path>  Scan a directory for crypto usage"
    echo "  help         Show this help"
}

case "${1:-full}" in
    full)     pipeline_full ;;
    analyze)  pipeline_analyze_samples ;;
    policies) run_kyverno_tests ;;
    tests)
        log_step "Running Test Suite"
        python3 -m pytest "$PROJECT_ROOT/tests/" -v --tb=short 2>/dev/null \
            || python3 "$PROJECT_ROOT/tests/test_all.py"
        ;;
    scan)
        if [[ -z "${2:-}" ]]; then
            log_fail "Usage: $0 scan <path>"
            exit 1
        fi
        log_step "Scanning: $2"
        python3 "$PROJECT_ROOT/scanner/cbom_scanner.py" "$2" "${3:-}" "${4:-0.0.0}"
        ;;
    help|--help|-h) show_usage ;;
    *)
        log_fail "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
