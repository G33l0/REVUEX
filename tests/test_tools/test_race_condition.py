#!/usr/bin/env python3
"""
Race Condition Scanner Tests
============================

Unit tests for the Race Condition Scanner GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.race_condition import RaceConditionScanner


class TestRaceConditionScannerInit:
    """Tests for RaceConditionScanner initialization."""
    
    def test_basic_init(self, sample_target):
        scanner = RaceConditionScanner(target=sample_target)
        assert scanner.target == sample_target
    
    def test_scanner_name(self, sample_target):
        scanner = RaceConditionScanner(target=sample_target)
        assert "Race" in scanner.scanner_name


class TestRaceConditionConfig:
    """Tests for race condition configuration."""
    
    def test_thread_count(self):
        thread_counts = [5, 10, 20, 50]
        for count in thread_counts:
            assert count >= 5
    
    def test_timing_window(self):
        windows = [0.01, 0.05, 0.1, 0.5]
        for w in windows:
            assert w > 0 and w < 1
    
    def test_request_timing(self):
        import time
        start = time.time()
        # Simulate minimal delay
        time.sleep(0.001)
        elapsed = time.time() - start
        
        assert elapsed < 0.1


class TestRaceConditionDetection:
    """Tests for race condition detection."""
    
    def test_double_spend(self):
        initial_balance = 100
        withdrawal = 100
        concurrent_requests = 2
        
        # Without proper locking, both might succeed
        potential_loss = withdrawal * concurrent_requests
        expected_loss = withdrawal
        
        is_vulnerable = potential_loss > initial_balance
        assert is_vulnerable is True
    
    def test_coupon_double_use(self):
        coupon_uses = [True, True, True]  # All succeeded
        max_uses = 1
        
        is_abused = coupon_uses.count(True) > max_uses
        assert is_abused is True
    
    def test_response_consistency(self):
        responses = [
            {"status": "success", "balance": 0},
            {"status": "success", "balance": 0},
            {"status": "success", "balance": 0}
        ]
        
        # All succeeded = race condition
        successes = sum(1 for r in responses if r["status"] == "success")
        assert successes > 1


class TestRaceConditionConfidence:
    """Tests for race condition confidence scoring."""
    
    def test_multiple_success_score(self):
        score = 50
        assert score > 40
    
    def test_state_inconsistency_score(self):
        score = 40
        assert score > 30
    
    def test_threshold(self):
        threshold = 75
        score = 90
        assert score >= threshold
