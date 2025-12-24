#!/bin/bash
#
# REVUEX Uninstall Script
# =======================
# Remove REVUEX installation
#
# Usage: ./scripts/uninstall.sh
#
# Author: G33L0 (@x0x0h33l0)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   REVUEX Uninstaller                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}[!]${NC} This will remove REVUEX from your system."
read -p "Are you sure? (y/n): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Uninstall cancelled."
    exit 0
fi

echo ""
echo -e "${BLUE}[*]${NC} Uninstalling REVUEX package..."
pip uninstall revuex -y 2>/dev/null || echo -e "${YELLOW}[!]${NC} Package not installed via pip"

echo -e "${BLUE}[*]${NC} Removing virtual environment..."
if [ -d "venv" ]; then
    rm -rf venv
    echo -e "${GREEN}[+]${NC} Virtual environment removed"
else
    echo -e "${YELLOW}[!]${NC} No virtual environment found"
fi

echo -e "${BLUE}[*]${NC} Removing output directories..."
rm -rf scans/ reports/ logs/ htmlcov/ .pytest_cache/ 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Output directories removed"

echo -e "${BLUE}[*]${NC} Removing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Cache removed"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  REVUEX Uninstalled${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  To reinstall: ${CYAN}./scripts/install.sh${NC}"
echo ""
