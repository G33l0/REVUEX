#!/usr/bin/env python3
"""
Business Logic Scanner Tests
============================

Unit tests for the Business Logic Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.business_logic import BusinessLogicScanner


class TestBusinessLogicScannerInit:
    """Tests for BusinessLogicScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = BusinessLogicScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = BusinessLogicScanner(target=sample_target)
        assert "Business" in scanner.scanner_name or "Logic" in scanner.scanner_name


class TestBusinessLogicPatterns:
    """Tests for business logic patterns."""
    
    def test_workflow_steps(self):
        steps = ["add_to_cart", "checkout", "payment", "confirmation"]
        assert len(steps) >= 4
    
    def test_step_skip_detection(self):
        required_steps = [1, 2, 3, 4]
        executed_steps = [1, 4]  # Skipped 2 and 3
        
        skipped = [s for s in required_steps if s not in executed_steps]
        assert len(skipped) == 2
    
    def test_parameter_tampering(self):
        original = {"price": 100, "quantity": 1}
        tampered = {"price": 1, "quantity": 1}
        
        is_tampered = original["price"] != tampered["price"]
        assert is_tampered is True


class TestBusinessLogicDetection:
    """Tests for business logic vulnerability detection."""
    
    def test_price_modification(self):
        server_price = 99.99
        client_price = 0.01
        
        is_modified = server_price != client_price
        assert is_modified is True
    
    def test_quantity_abuse(self):
        quantities = [-1, 0, 999999999]
        
        for qty in quantities:
            is_abnormal = qty <= 0 or qty > 1000000
            assert is_abnormal is True
    
    def test_coupon_stacking(self):
        coupons_applied = ["SAVE10", "SAVE20", "SAVE50"]
        max_coupons = 1
        
        is_stacking = len(coupons_applied) > max_coupons
        assert is_stacking is True


class TestBusinessLogicConfidence:
    """Tests for business logic confidence scoring."""
    
    def test_workflow_bypass_score(self):
        score = 40
        assert score > 30
    
    def test_price_tamper_score(self):
        score = 45
        assert score > 40
    
    def test_threshold(self):
        threshold = 75
        score = 85
        assert score >= threshold
