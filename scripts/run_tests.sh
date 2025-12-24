#!/bin/bash
#
# REVUEX Test Runner Script
# =========================
# Run tests with various configurations
#
# Usage:
#   ./scripts/run_tests.sh [options]
#
# Options:
#   all       - Run all tests (default)
#   core      - Run core tests only
#   tools     - Run tool tests only
#   coverage  - Run with coverage report
#   fast      - Run fast tests only (skip slow)
#   verbose   - Run with verbose output
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

# Default options
TEST_TYPE="${1:-all}"
PYTEST_ARGS=""

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   REVUEX Test Runner                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${YELLOW}[!]${NC} pytest not found, installing..."
    pip install pytest pytest-cov --quiet
fi

# Run based on type
case "$TEST_TYPE" in
    all)
        echo -e "${BLUE}[*]${NC} Running all tests..."
        pytest tests/ -v
        ;;
    core)
        echo -e "${BLUE}[*]${NC} Running core tests..."
        pytest tests/test_core/ -v
        ;;
    tools)
        echo -e "${BLUE}[*]${NC} Running tool tests..."
        pytest tests/test_tools/ -v
        ;;
    coverage)
        echo -e "${BLUE}[*]${NC} Running tests with coverage..."
        pytest tests/ --cov=core --cov=tools --cov-report=html --cov-report=term
        echo ""
        echo -e "${GREEN}[+]${NC} Coverage report: htmlcov/index.html"
        ;;
    fast)
        echo -e "${BLUE}[*]${NC} Running fast tests..."
        pytest tests/ -v -m "not slow"
        ;;
    verbose)
        echo -e "${BLUE}[*]${NC} Running tests with verbose output..."
        pytest tests/ -vv --tb=long
        ;;
    ssrf|sqli|xss|cors|idor|xxe|ssti|jwt|graphql|csrf|session)
        echo -e "${BLUE}[*]${NC} Running $TEST_TYPE tests..."
        pytest tests/test_tools/test_${TEST_TYPE}.py -v
        ;;
    *)
        echo -e "${RED}Unknown test type: $TEST_TYPE${NC}"
        echo ""
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  all       - Run all tests (default)"
        echo "  core      - Run core tests only"
        echo "  tools     - Run tool tests only"
        echo "  coverage  - Run with coverage report"
        echo "  fast      - Run fast tests only"
        echo "  verbose   - Run with verbose output"
        echo "  <scanner> - Run specific scanner tests (e.g., ssrf, sqli, xss)"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}[+]${NC} Tests complete!"
