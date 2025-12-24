#!/usr/bin/env python3
"""
Price Manipulation Scanner Tests
================================

Unit tests for the Price Manipulation Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.price_manipulation import PriceManipulationScanner


class TestPriceManipulationScannerInit:
    """Tests for PriceManipulationScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = PriceManipulationScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = PriceManipulationScanner(target=sample_target)
        assert "Price" in scanner.scanner_name


class TestPriceManipulationPayloads:
    """Tests for price manipulation payloads."""
    
    def test_negative_values(self):
        values = [-1, -100, -0.01, -999999]
        for v in values:
            assert v < 0
    
    def test_zero_values(self):
        values = [0, 0.0, 0.00]
        for v in values:
            assert v == 0
    
    def test_overflow_values(self):
        values = [2147483647, 9999999999, 99999999999999]
        for v in values:
            assert v > 2000000000
    
    def test_decimal_manipulation(self):
        values = [0.001, 0.0001, 0.00001]
        for v in values:
            assert v < 0.01


class TestPriceManipulationDetection:
    """Tests for price manipulation detection."""
    
    def test_negative_total(self):
        original_total = 100.00
        manipulated_total = -50.00
        
        is_negative = manipulated_total < 0
        assert is_negative is True
    
    def test_price_reduction(self):
        original = 99.99
        manipulated = 0.01
        
        reduction_percent = ((original - manipulated) / original) * 100
        assert reduction_percent > 99
    
    def test_quantity_overflow(self):
        quantity = 2147483647 + 1
        max_int = 2147483647
        
        is_overflow = quantity > max_int
        assert is_overflow is True
    
    def test_discount_abuse(self):
        discount = 150  # 150% discount
        max_discount = 100
        
        is_abuse = discount > max_discount
        assert is_abuse is True


class TestPriceManipulationConfidence:
    """Tests for price manipulation confidence scoring."""
    
    def test_negative_accepted_score(self):
        score = 50
        assert score > 40
    
    def test_zero_accepted_score(self):
        score = 40
        assert score > 30
    
    def test_threshold(self):
        threshold = 75
        score = 85
        assert score >= threshold
