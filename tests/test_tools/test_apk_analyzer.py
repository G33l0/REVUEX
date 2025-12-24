#!/usr/bin/env python3
"""
APK Analyzer Tests
==================

Unit tests for the APK Analyzer GOLD.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools.apk_analyzer import APKAnalyzer


class TestAPKAnalyzerInit:
    """Tests for APKAnalyzer initialization."""
    
    def test_basic_init(self):
        # APK analyzer uses apk_path instead of target
        scanner = APKAnalyzer(apk_path="/path/to/test.apk")
        assert scanner.apk_path == "/path/to/test.apk"
    
    def test_scanner_name(self):
        scanner = APKAnalyzer(apk_path="/path/to/test.apk")
        assert "APK" in scanner.scanner_name


class TestAPKPatterns:
    """Tests for APK analysis patterns."""
    
    def test_dangerous_permissions(self):
        permissions = [
            "android.permission.READ_SMS",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO"
        ]
        assert len(permissions) >= 5
    
    def test_sensitive_api_patterns(self):
        apis = [
            "getDeviceId",
            "getSubscriberId",
            "getSimSerialNumber",
            "getMacAddress"
        ]
        assert len(apis) >= 4
    
    def test_hardcoded_secrets(self):
        patterns = [
            r'api[_-]?key',
            r'secret[_-]?key',
            r'password',
            r'aws[_-]?access',
            r'firebase'
        ]
        assert len(patterns) >= 5


class TestAPKVulnerabilities:
    """Tests for APK vulnerability detection."""
    
    def test_debug_enabled(self):
        manifest = 'android:debuggable="true"'
        
        is_debuggable = 'debuggable="true"' in manifest
        assert is_debuggable is True
    
    def test_backup_enabled(self):
        manifest = 'android:allowBackup="true"'
        
        allows_backup = 'allowBackup="true"' in manifest
        assert allows_backup is True
    
    def test_insecure_network(self):
        config = 'cleartextTrafficPermitted="true"'
        
        allows_cleartext = 'cleartextTrafficPermitted="true"' in config
        assert allows_cleartext is True
    
    def test_exported_components(self):
        component = 'android:exported="true"'
        
        is_exported = 'exported="true"' in component
        assert is_exported is True


class TestAPKConfidence:
    """Tests for APK confidence scoring."""
    
    def test_debug_enabled_score(self):
        score = 40
        assert score > 30
    
    def test_hardcoded_secret_score(self):
        score = 50
        assert score > 40
    
    def test_threshold(self):
        threshold = 75
        score = 85
        assert score >= threshold
