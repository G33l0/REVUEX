# REVUEX Installation Guide

## Requirements

- Python 3.8+
- pip package manager
- Git (for cloning)

## Quick Install

```bash
# Clone the repository
git clone https://github.com/G33L0/revuex-vul-suite.git
cd revuex-vul-suite

# Install dependencies
pip install -r requirements.txt

# Install REVUEX package
pip install -e .
```

## Dependencies

Core dependencies installed via `requirements.txt`:

```
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
urllib3>=1.26.0
```

## Verify Installation

```bash
# Check REVUEX is installed
python -c "from tools import print_scanner_table; print_scanner_table()"

# Run a scanner
python -m tools.ssrf --help
```

## Optional Dependencies

### APK Analysis
```bash
# Install apktool for Android APK analysis
sudo apt install apktool  # Debian/Ubuntu
brew install apktool      # macOS
```

### Enhanced HTML Reports
```bash
pip install jinja2 markdown
```

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dev dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest tests/
```

## Troubleshooting

### Import Errors
```bash
# Ensure REVUEX is in Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/revuex-vul-suite"
```

### Permission Errors
```bash
# Use --user flag
pip install --user -r requirements.txt
```

### SSL Certificate Errors
```bash
pip install --upgrade certifi
```

## Next Steps

- Read [Usage Guide](USAGE.md)
- Explore [Tool Documentation](tools/)
- Try [Examples](examples/)
