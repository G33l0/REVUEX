#!/usr/bin/env python3
"""
REVUEX Test Configuration
=========================

Pytest fixtures and configuration for REVUEX tests.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_target():
    """Sample target URL for testing."""
    return "https://example.com"


@pytest.fixture
def sample_api_target():
    """Sample API target URL."""
    return "https://api.example.com/v1"


@pytest.fixture
def sample_headers():
    """Sample HTTP headers."""
    return {
        "Authorization": "Bearer test_token_123",
        "Content-Type": "application/json",
        "User-Agent": "REVUEX-Test/1.0"
    }


@pytest.fixture
def sample_jwt():
    """Sample JWT token for testing."""
    # This is a valid JWT structure (not a real token)
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.fixture
def sample_xml():
    """Sample XML payload."""
    return '<?xml version="1.0"?><root><test>value</test></root>'


@pytest.fixture
def sample_graphql_endpoint():
    """Sample GraphQL endpoint."""
    return "https://example.com/graphql"


@pytest.fixture
def mock_response():
    """Mock HTTP response factory."""
    class MockResponse:
        def __init__(self, text="", status_code=200, headers=None):
            self.text = text
            self.status_code = status_code
            self.headers = headers or {}
            self.content = text.encode()
        
        def json(self):
            import json
            return json.loads(self.text)
    
    return MockResponse


# =============================================================================
# CONFIGURATION
# =============================================================================

def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
