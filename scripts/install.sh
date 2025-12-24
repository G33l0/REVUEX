#!/bin/bash
#
# REVUEX Installation Script
# ==========================
# Bug Bounty Automation Framework
#
# Usage: ./scripts/install.sh
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
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║   ██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗     ║"
echo "║   ██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝     ║"
echo "║   ██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝      ║"
echo "║   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗      ║"
echo "║   ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗     ║"
echo "║   ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ║"
echo "║                                                           ║"
echo "║           Bug Bounty Automation Framework                 ║"
echo "║                    Installation                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Functions
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check Python version
check_python() {
    print_status "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            print_success "Python $PYTHON_VERSION detected"
            return 0
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            return 1
        fi
    else
        print_error "Python 3 not found. Please install Python 3.8+"
        return 1
    fi
}

# Check pip
check_pip() {
    print_status "Checking pip..."
    
    if command -v pip3 &> /dev/null; then
        print_success "pip3 detected"
        return 0
    elif command -v pip &> /dev/null; then
        print_success "pip detected"
        return 0
    else
        print_error "pip not found. Please install pip"
        return 1
    fi
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt --quiet
        print_success "Dependencies installed"
    else
        print_warning "requirements.txt not found, installing core dependencies..."
        pip3 install requests beautifulsoup4 colorama urllib3 --quiet
        print_success "Core dependencies installed"
    fi
}

# Install REVUEX package
install_package() {
    print_status "Installing REVUEX package..."
    
    if [ -f "setup.py" ]; then
        pip3 install -e . --quiet
        print_success "REVUEX package installed"
    else
        print_warning "setup.py not found, skipping package installation"
    fi
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    if python3 -c "from tools import print_scanner_table" 2>/dev/null; then
        print_success "REVUEX installed successfully!"
        echo ""
        print_status "Available scanners:"
        python3 -c "from tools import print_scanner_table; print_scanner_table()"
        return 0
    else
        print_error "Installation verification failed"
        return 1
    fi
}

# Create output directories
create_directories() {
    print_status "Creating output directories..."
    
    mkdir -p scans
    mkdir -p reports
    
    print_success "Directories created"
}

# Main installation
main() {
    echo ""
    print_status "Starting REVUEX installation..."
    echo ""
    
    # Pre-flight checks
    check_python || exit 1
    check_pip || exit 1
    
    echo ""
    
    # Installation
    install_dependencies
    install_package
    create_directories
    
    echo ""
    
    # Verify
    verify_installation
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  REVUEX Installation Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Quick Start:"
    echo -e "    ${CYAN}python revuex_suite.py -t https://target.com --all${NC}"
    echo ""
    echo -e "  Individual Scanner:"
    echo -e "    ${CYAN}python -m tools.ssrf -t https://target.com/api${NC}"
    echo ""
    echo -e "  Documentation:"
    echo -e "    ${CYAN}cat documentation/README.md${NC}"
    echo ""
    echo -e "  Run Tests:"
    echo -e "    ${CYAN}pytest tests/ -v${NC}"
    echo ""
}

# Run main
main "$@"
