# REVUEX Scripts

Utility scripts for installation, development, and testing.

## Available Scripts

| Script | Description |
|--------|-------------|
| `install.sh` | Install REVUEX and dependencies |
| `setup_dev.sh` | Setup development environment |
| `quick_scan.sh` | Run quick scans with common configs |
| `run_tests.sh` | Run test suite with options |
| `uninstall.sh` | Remove REVUEX installation |

## Usage

### Make Scripts Executable

```bash
chmod +x scripts/*.sh
```

### Install REVUEX

```bash
./scripts/install.sh
```

### Setup Development Environment

```bash
./scripts/setup_dev.sh

# Then activate
source venv/bin/activate
```

### Quick Scan

```bash
# Full scan
./scripts/quick_scan.sh https://example.com

# Reconnaissance only
./scripts/quick_scan.sh https://example.com recon

# Injection testing
./scripts/quick_scan.sh https://example.com injection

# Access control testing
./scripts/quick_scan.sh https://example.com access

# API testing
./scripts/quick_scan.sh https://api.example.com api
```

### Run Tests

```bash
# All tests
./scripts/run_tests.sh

# Core tests only
./scripts/run_tests.sh core

# Tool tests only
./scripts/run_tests.sh tools

# With coverage
./scripts/run_tests.sh coverage

# Specific scanner
./scripts/run_tests.sh ssrf
./scripts/run_tests.sh sqli
./scripts/run_tests.sh cors
```

### Uninstall

```bash
./scripts/uninstall.sh
```

## Script Details

### install.sh

- Checks Python 3.8+ is installed
- Installs pip dependencies from `requirements.txt`
- Installs REVUEX package in editable mode
- Creates output directories
- Verifies installation

### setup_dev.sh

- Creates Python virtual environment
- Installs production dependencies
- Installs dev dependencies (pytest, black, flake8, mypy)
- Sets up git pre-commit hooks
- Installs package in editable mode

### quick_scan.sh

Scan types:
- `recon` - Tech fingerprinting, JS secrets
- `injection` - SSRF, SQLi, XSS, SSTI
- `access` - CORS, CSRF, Session
- `api` - GraphQL, Dependencies
- `full` - All of the above

Results saved to `scans/TIMESTAMP/`

### run_tests.sh

Test options:
- `all` - All tests
- `core` - Core module tests
- `tools` - Tool tests
- `coverage` - With coverage report
- `fast` - Skip slow tests
- `verbose` - Detailed output
- `<scanner>` - Specific scanner tests

### uninstall.sh

Removes:
- REVUEX pip package
- Virtual environment
- Output directories
- Python cache files
