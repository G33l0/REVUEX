# REVUEX Test Suite

Unit tests for the REVUEX Bug Bounty Automation Framework.

## Structure

```
tests/
├── __init__.py
├── conftest.py              ← Pytest fixtures
├── README.md                ← This file
├── test_core/
│   ├── __init__.py
│   ├── test_base_scanner.py ← BaseScanner tests
│   └── test_utils.py        ← Utility function tests
└── test_tools/
    ├── __init__.py
    ├── test_scanner_registry.py ← Registry tests
    ├── test_ssrf.py         ← SSRF scanner tests
    ├── test_cors.py         ← CORS scanner tests
    └── test_xxe.py          ← XXE scanner tests
```

## Running Tests

### Run All Tests

```bash
# Basic run
pytest tests/

# Verbose output
pytest tests/ -v

# With coverage
pytest tests/ --cov=core --cov=tools

# Stop on first failure
pytest tests/ -x
```

### Run Specific Tests

```bash
# Run core tests only
pytest tests/test_core/

# Run tools tests only
pytest tests/test_tools/

# Run specific file
pytest tests/test_tools/test_ssrf.py

# Run specific test class
pytest tests/test_tools/test_ssrf.py::TestSSRFScannerInit

# Run specific test
pytest tests/test_tools/test_ssrf.py::TestSSRFScannerInit::test_basic_init
```

### Run by Markers

```bash
# Run only unit tests
pytest tests/ -m unit

# Skip slow tests
pytest tests/ -m "not slow"

# Run integration tests
pytest tests/ -m integration
```

## Test Coverage

```bash
# Generate coverage report
pytest tests/ --cov=core --cov=tools --cov-report=html

# View HTML report
open htmlcov/index.html
```

## Writing Tests

### Test Structure

```python
import pytest
from tools.ssrf import SSRFScanner

class TestSSRFScanner:
    """Tests for SSRFScanner."""
    
    def test_initialization(self, sample_target):
        """Test scanner initialization."""
        scanner = SSRFScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_detection_logic(self):
        """Test detection logic."""
        # Test implementation
        pass
```

### Using Fixtures

Fixtures are defined in `conftest.py`:

```python
def test_with_fixture(sample_target, sample_headers):
    """Test using fixtures."""
    scanner = SomeScanner(
        target=sample_target,
        custom_headers=sample_headers
    )
    assert scanner is not None
```

### Available Fixtures

| Fixture | Description |
|---------|-------------|
| `sample_target` | Sample HTTPS URL |
| `sample_api_target` | Sample API URL |
| `sample_headers` | Sample HTTP headers |
| `sample_jwt` | Sample JWT token |
| `sample_xml` | Sample XML payload |
| `sample_graphql_endpoint` | Sample GraphQL URL |
| `mock_response` | Mock HTTP response factory |

## Test Categories

### Core Tests

- `test_base_scanner.py` - BaseScanner class, Finding, ScanResult
- `test_utils.py` - Utility functions, URL parsing, headers

### Tool Tests

- `test_scanner_registry.py` - Scanner imports, registry, metadata
- `test_ssrf.py` - SSRF detection logic, payloads, scoring
- `test_cors.py` - CORS headers, origin testing, vulnerabilities
- `test_xxe.py` - XXE payloads, parser detection, entity expansion

## Adding New Tests

1. Create test file in appropriate directory
2. Follow naming convention: `test_<module>.py`
3. Use fixtures from `conftest.py`
4. Add appropriate markers (@pytest.mark.unit, etc.)

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Tests
  run: |
    pip install pytest pytest-cov
    pytest tests/ --cov=core --cov=tools
```

## Requirements

```bash
pip install pytest pytest-cov
```
