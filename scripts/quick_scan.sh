#!/bin/bash
#
# REVUEX Quick Scan Script
# ========================
# Run quick scans with common configurations
#
# Usage:
#   ./scripts/quick_scan.sh <target> [scan_type]
#
# Scan Types:
#   recon     - Reconnaissance only (subdomain, tech, secrets)
#   injection - Injection tests (ssrf, sqli, xss, ssti, xxe)
#   access    - Access control (idor, cors, csrf, session, jwt)
#   api       - API testing (graphql, ssrf)
#   full      - All scanners (default)
#
# Examples:
#   ./scripts/quick_scan.sh https://example.com
#   ./scripts/quick_scan.sh https://example.com recon
#   ./scripts/quick_scan.sh https://api.example.com injection
#
# Author: G33L0 (@x0x0h33l0)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}Error: Target URL required${NC}"
    echo ""
    echo "Usage: $0 <target> [scan_type]"
    echo ""
    echo "Scan Types:"
    echo "  recon     - Reconnaissance only"
    echo "  injection - Injection tests"
    echo "  access    - Access control tests"
    echo "  api       - API testing"
    echo "  full      - All scanners (default)"
    echo ""
    echo "Example: $0 https://example.com recon"
    exit 1
fi

TARGET="$1"
SCAN_TYPE="${2:-full}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="scans/${TIMESTAMP}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   REVUEX Quick Scan                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${BLUE}[*]${NC} Target: $TARGET"
echo -e "${BLUE}[*]${NC} Scan Type: $SCAN_TYPE"
echo -e "${BLUE}[*]${NC} Output: $OUTPUT_DIR"
echo ""

# Scan functions
run_recon() {
    echo -e "${YELLOW}[Phase 1] Reconnaissance${NC}"
    
    echo -e "${BLUE}[*]${NC} Running Tech Fingerprinter..."
    python -m tools.tech_fingerprinter -t "$TARGET" -o "$OUTPUT_DIR/tech.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running JS Secrets Miner..."
    python -m tools.js_secrets -t "$TARGET" -o "$OUTPUT_DIR/secrets.json" 2>/dev/null || true
    
    echo -e "${GREEN}[+]${NC} Reconnaissance complete"
}

run_injection() {
    echo -e "${YELLOW}[Phase 2] Injection Testing${NC}"
    
    echo -e "${BLUE}[*]${NC} Running SSRF Scanner..."
    python -m tools.ssrf -t "$TARGET" -o "$OUTPUT_DIR/ssrf.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running SQLi Scanner..."
    python -m tools.sqli -u "$TARGET" -o "$OUTPUT_DIR/sqli.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running XSS Scanner..."
    python -m tools.xss -t "$TARGET" -o "$OUTPUT_DIR/xss.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running SSTI Scanner..."
    python -m tools.ssti -t "$TARGET" -o "$OUTPUT_DIR/ssti.json" 2>/dev/null || true
    
    echo -e "${GREEN}[+]${NC} Injection testing complete"
}

run_access() {
    echo -e "${YELLOW}[Phase 3] Access Control Testing${NC}"
    
    echo -e "${BLUE}[*]${NC} Running CORS Scanner..."
    python -m tools.cors -t "$TARGET" -o "$OUTPUT_DIR/cors.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running CSRF Scanner..."
    python -m tools.csrf -t "$TARGET" -o "$OUTPUT_DIR/csrf.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running Session Scanner..."
    python -m tools.session -t "$TARGET" -o "$OUTPUT_DIR/session.json" 2>/dev/null || true
    
    echo -e "${GREEN}[+]${NC} Access control testing complete"
}

run_api() {
    echo -e "${YELLOW}[Phase 4] API Testing${NC}"
    
    echo -e "${BLUE}[*]${NC} Running GraphQL Scanner..."
    python -m tools.graphql -t "${TARGET}/graphql" -o "$OUTPUT_DIR/graphql.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*]${NC} Running Dependency Scanner..."
    python -m tools.dependency -t "$TARGET" -o "$OUTPUT_DIR/dependency.json" 2>/dev/null || true
    
    echo -e "${GREEN}[+]${NC} API testing complete"
}

# Run based on scan type
case "$SCAN_TYPE" in
    recon)
        run_recon
        ;;
    injection)
        run_injection
        ;;
    access)
        run_access
        ;;
    api)
        run_api
        ;;
    full)
        run_recon
        echo ""
        run_injection
        echo ""
        run_access
        echo ""
        run_api
        ;;
    *)
        echo -e "${RED}Unknown scan type: $SCAN_TYPE${NC}"
        exit 1
        ;;
esac

# Summary
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Scan Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Results saved to: ${CYAN}$OUTPUT_DIR/${NC}"
echo ""
echo -e "  View results:"
echo -e "    ${CYAN}ls -la $OUTPUT_DIR/${NC}"
echo -e "    ${CYAN}cat $OUTPUT_DIR/*.json | jq .${NC}"
echo ""
