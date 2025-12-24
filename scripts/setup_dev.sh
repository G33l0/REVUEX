#!/bin/bash
#
# REVUEX Development Setup Script
# ================================
# Sets up development environment with virtual env, dependencies, and dev tools
#
# Usage: ./scripts/setup_dev.sh
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

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           REVUEX Development Environment Setup            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

# Configuration
VENV_NAME="venv"
PYTHON_MIN_VERSION="3.8"

# Check Python version
check_python() {
    print_status "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        print_success "Python $PYTHON_VERSION detected"
    else
        print_error "Python 3 not found"
        exit 1
    fi
}

# Create virtual environment
create_venv() {
    print_status "Creating virtual environment..."
    
    if [ -d "$VENV_NAME" ]; then
        print_warning "Virtual environment already exists"
        read -p "Recreate? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_NAME"
            python3 -m venv "$VENV_NAME"
            print_success "Virtual environment recreated"
        else
            print_status "Using existing virtual environment"
        fi
    else
        python3 -m venv "$VENV_NAME"
        print_success "Virtual environment created"
    fi
}

# Activate virtual environment
activate_venv() {
    print_status "Activating virtual environment..."
    
    if [ -f "$VENV_NAME/bin/activate" ]; then
        source "$VENV_NAME/bin/activate"
        print_success "Virtual environment activated"
    else
        print_error "Could not find activation script"
        exit 1
    fi
}

# Upgrade pip
upgrade_pip() {
    print_status "Upgrading pip..."
    pip install --upgrade pip --quiet
    print_success "pip upgraded"
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt --quiet
        print_success "Dependencies installed"
    else
        print_warning "requirements.txt not found"
    fi
}

# Install dev dependencies
install_dev_dependencies() {
    print_status "Installing development dependencies..."
    
    pip install pytest pytest-cov black flake8 mypy --quiet
    print_success "Dev dependencies installed (pytest, black, flake8, mypy)"
}

# Install package in editable mode
install_package() {
    print_status "Installing REVUEX in editable mode..."
    
    if [ -f "setup.py" ]; then
        pip install -e . --quiet
        print_success "REVUEX installed in editable mode"
    else
        print_warning "setup.py not found"
    fi
}

# Create directories
create_directories() {
    print_status "Creating project directories..."
    
    mkdir -p scans
    mkdir -p reports
    mkdir -p logs
    
    print_success "Directories created"
}

# Setup git hooks (optional)
setup_git_hooks() {
    print_status "Setting up git hooks..."
    
    if [ -d ".git" ]; then
        # Pre-commit hook for linting
        cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Run linting before commit
echo "Running pre-commit checks..."

# Run flake8
echo "Checking code style with flake8..."
flake8 core/ tools/ --max-line-length=120 --ignore=E501,W503

# Run black check
echo "Checking formatting with black..."
black --check core/ tools/ --quiet 2>/dev/null || echo "Run 'black core/ tools/' to format code"

echo "Pre-commit checks complete!"
EOF
        chmod +x .git/hooks/pre-commit
        print_success "Git pre-commit hook installed"
    else
        print_warning "Not a git repository, skipping hooks"
    fi
}

# Print environment info
print_env_info() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Development Environment Ready!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Activate environment:${NC}"
    echo -e "    source $VENV_NAME/bin/activate"
    echo ""
    echo -e "  ${CYAN}Run tests:${NC}"
    echo -e "    pytest tests/ -v"
    echo -e "    pytest tests/ --cov=core --cov=tools"
    echo ""
    echo -e "  ${CYAN}Code formatting:${NC}"
    echo -e "    black core/ tools/"
    echo -e "    flake8 core/ tools/"
    echo ""
    echo -e "  ${CYAN}Type checking:${NC}"
    echo -e "    mypy core/ tools/"
    echo ""
    echo -e "  ${CYAN}Run a scanner:${NC}"
    echo -e "    python -m tools.ssrf -t https://example.com"
    echo ""
    echo -e "  ${CYAN}Deactivate:${NC}"
    echo -e "    deactivate"
    echo ""
}

# Main
main() {
    echo ""
    
    check_python
    create_venv
    activate_venv
    upgrade_pip
    install_dependencies
    install_dev_dependencies
    install_package
    create_directories
    setup_git_hooks
    print_env_info
}

main "$@"
