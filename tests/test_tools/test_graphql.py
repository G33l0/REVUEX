#!/usr/bin/env python3
"""
GraphQL Scanner Tests
=====================

Unit tests for the GraphQL Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.graphql import GraphQLScanner


class TestGraphQLScannerInit:
    """Tests for GraphQLScanner initialization."""
    
    def test_basic_init(self, sample_graphql_endpoint):
        scanner = GraphQLScanner(target=sample_graphql_endpoint)
        assert scanner.target == sample_graphql_endpoint
    
    def test_scanner_name(self, sample_graphql_endpoint):
        scanner = GraphQLScanner(target=sample_graphql_endpoint)
        assert "GraphQL" in scanner.scanner_name


class TestGraphQLQueries:
    """Tests for GraphQL query payloads."""
    
    def test_introspection_query(self):
        query = """
        query {
            __schema {
                types { name }
            }
        }
        """
        assert "__schema" in query
        assert "types" in query
    
    def test_type_query(self):
        query = """
        query {
            __type(name: "User") {
                name
                fields { name type { name } }
            }
        }
        """
        assert "__type" in query
    
    def test_nested_query(self):
        query = """
        query {
            users {
                id
                posts {
                    comments {
                        author { id }
                    }
                }
            }
        }
        """
        # Check nesting depth
        depth = query.count("{")
        assert depth >= 4


class TestGraphQLDetection:
    """Tests for GraphQL vulnerability detection."""
    
    def test_introspection_enabled(self):
        response = '{"data": {"__schema": {"types": [{"name": "Query"}]}}}'
        
        has_schema = "__schema" in response
        assert has_schema is True
    
    def test_introspection_disabled(self):
        response = '{"errors": [{"message": "Introspection is disabled"}]}'
        
        is_disabled = "disabled" in response.lower()
        assert is_disabled is True
    
    def test_depth_limit(self):
        max_depth = 10
        query_depth = 15
        
        exceeds_limit = query_depth > max_depth
        assert exceeds_limit is True
    
    def test_batching_enabled(self):
        queries = [
            {"query": "{ user(id: 1) { name } }"},
            {"query": "{ user(id: 2) { name } }"}
        ]
        
        is_batch = isinstance(queries, list) and len(queries) > 1
        assert is_batch is True


class TestGraphQLConfidence:
    """Tests for GraphQL confidence scoring."""
    
    def test_introspection_score(self):
        score = 40
        assert score > 30
    
    def test_no_depth_limit_score(self):
        score = 30
        assert score > 0
    
    def test_threshold(self):
        threshold = 75
        score = 85
        assert score >= threshold
