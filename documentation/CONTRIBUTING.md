# Contributing to REVUEX

Thank you for your interest in contributing to REVUEX!

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. Check existing issues first
2. Create a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Suggesting Features

1. Open a feature request issue
2. Describe the use case
3. Explain why it benefits bug bounty hunters

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write/update tests
5. Submit pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/revuex-vul-suite.git
cd revuex-vul-suite

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest tests/
```

## Adding a New Scanner

### 1. Create Scanner Directory

```
tools/new_scanner/
├── __init__.py
├── __main__.py
├── new_scanner.py
└── README.md
```

### 2. Implement Scanner

```python
# tools/new_scanner/new_scanner.py

from core.base_scanner import BaseScanner, Finding, Severity

class NewScanner(BaseScanner):
    """
    REVUEX New Scanner GOLD
    =======================
    
    Description of what this scanner detects.
    
    GOLD Philosophy:
    - Zero exploitation
    - Differential analysis
    - Confidence scoring
    """
    
    def __init__(self, target, **kwargs):
        super().__init__(target=target, **kwargs)
        self.scanner_name = "New Scanner GOLD"
        self.scanner_version = "1.0.0"
    
    def scan(self):
        # 1. Capture baseline
        self._capture_baseline()
        
        # 2. Run detection tests
        self._run_tests()
        
        # 3. Correlate findings
        self._correlate_findings()
    
    def _capture_baseline(self):
        """Capture baseline response."""
        pass
    
    def _run_tests(self):
        """Run detection tests."""
        pass
    
    def _correlate_findings(self):
        """Correlate signals and create findings."""
        pass
```

### 3. Create __init__.py

```python
# tools/new_scanner/__init__.py

from .new_scanner import NewScanner, main

__all__ = ["NewScanner", "main"]
__version__ = "1.0.0"
```

### 4. Create __main__.py

```python
# tools/new_scanner/__main__.py

from .new_scanner import main

if __name__ == "__main__":
    main()
```

### 5. Add to Registry

Update `tools/__init__.py`:

```python
from tools.new_scanner import NewScanner

SCANNERS["new_scanner"] = NewScanner

SCANNER_INFO["new_scanner"] = {
    "name": "New Scanner GOLD",
    "category": "Category",
    "description": "Description",
    "version": "1.0.0"
}
```

### 6. Create Payload File

```
payloads/new_scanner/payloads.json
```

### 7. Write Documentation

```
tools/new_scanner/README.md
documentation/tools/new_scanner.md
```

## GOLD Standard Requirements

All scanners must follow GOLD principles:

### 1. Zero Exploitation
- Detection only, no harmful payloads
- No file exfiltration
- No network callback abuse

### 2. Differential Analysis
- Capture baseline response
- Compare with test responses
- Identify meaningful deviations

### 3. Confidence Scoring
- Multiple detection signals
- Threshold-based findings (75-80%)
- Clear evidence collection

### 4. Professional Output
- Bug bounty ready reports
- Clear remediation guidance
- Reproducible evidence

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings
- Keep functions focused

```python
def calculate_confidence(self, signals: List[str]) -> int:
    """
    Calculate confidence score from detection signals.
    
    Args:
        signals: List of detection signal names
        
    Returns:
        Confidence score (0-100)
    """
    base_score = 20
    signal_score = len(signals) * 15
    return min(100, base_score + signal_score)
```

## Testing

### Unit Tests

```python
# tests/test_tools/test_new_scanner.py

import pytest
from tools.new_scanner import NewScanner

def test_scanner_init():
    scanner = NewScanner(target="https://example.com")
    assert scanner.target == "https://example.com"

def test_confidence_calculation():
    scanner = NewScanner(target="https://example.com")
    confidence = scanner.calculate_confidence(["signal1", "signal2"])
    assert confidence >= 50
```

### Run Tests

```bash
# All tests
python -m pytest tests/

# Specific test
python -m pytest tests/test_tools/test_new_scanner.py

# With coverage
python -m pytest --cov=tools tests/
```

## Commit Messages

Use conventional commits:

```
feat: add new scanner for X vulnerability
fix: correct false positive in SSRF scanner
docs: update API reference
test: add tests for CORS scanner
refactor: simplify confidence calculation
```

## Pull Request Checklist

- [ ] Code follows GOLD principles
- [ ] Scanner inherits from BaseScanner
- [ ] Confidence scoring implemented
- [ ] CLI interface working
- [ ] README.md created
- [ ] Payload file created
- [ ] Tests written
- [ ] Documentation updated
- [ ] No breaking changes

## Questions?

- Open an issue for questions
- Telegram: @x0x0h33l0

Thank you for contributing to REVUEX!
