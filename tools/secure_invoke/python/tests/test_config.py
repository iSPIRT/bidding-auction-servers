#!/usr/bin/env python3
"""
Unit tests for SecureRequestClient configuration validation.
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_request import SecureRequestConfig


class TestSecureRequestConfig(unittest.TestCase):
    """Test cases for SecureRequestConfig validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = SecureRequestConfig()
    
    def test_valid_config_with_file(self):
        """Test valid configuration with request file."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.offer_host = "127.0.0.1:51052"
        self.config.request_payload = "sample_offer_request.json"
        self.config.insecure = True
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"test": "data"}')
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            self.assertTrue(self.config.validate())
        finally:
            os.unlink(temp_file)
    
    def test_valid_config_with_json_payload(self):
        """Test valid configuration with direct JSON payload."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.offer_host = "127.0.0.1:51052"
        self.config.request_payload = '{"client_type": "CLIENT_TYPE_BROWSER"}'
        self.config.insecure = True
        
        self.assertTrue(self.config.validate())
    
    def test_missing_kms_host(self):
        """Test validation fails when kms_host is missing."""
        self.config.offer_host = "127.0.0.1:51052"
        self.config.request_payload = '{"test": "data"}'
        self.config.insecure = True
        
        self.assertFalse(self.config.validate())
    
    def test_missing_offer_host(self):
        """Test validation fails when offer_host is missing."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.request_payload = '{"test": "data"}'
        self.config.insecure = True
        
        self.assertFalse(self.config.validate())
    
    def test_missing_request_payload(self):
        """Test validation fails when request_payload is missing."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.offer_host = "127.0.0.1:51052"
        self.config.insecure = True
        
        self.assertFalse(self.config.validate())
    
    def test_nonexistent_file(self):
        """Test validation fails when request file doesn't exist."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.offer_host = "127.0.0.1:51052"
        self.config.request_payload = "nonexistent.json"
        self.config.insecure = True
        
        self.assertFalse(self.config.validate())
    
    def test_ssl_certificate_requirements_secure_mode(self):
        """Test SSL certificate requirements in secure mode."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.offer_host = "127.0.0.1:51052"
        self.config.request_payload = '{"test": "data"}'
        self.config.insecure = False  # Secure mode
        
        # Should fail without certificates
        self.assertFalse(self.config.validate())
        
        # Should pass with CA cert
        self.config.ca_cert = "ca.crt"
        self.assertTrue(self.config.validate())
        
        # Should pass with client certs
        self.config.ca_cert = None
        self.config.client_cert = "client.crt"
        self.config.client_key = "client.key"
        self.assertTrue(self.config.validate())
    
    def test_ssl_certificate_requirements_insecure_mode(self):
        """Test SSL certificate requirements in insecure mode."""
        self.config.kms_host = "127.0.0.1:8000"
        self.config.offer_host = "127.0.0.1:51052"
        self.config.request_payload = '{"test": "data"}'
        self.config.insecure = True  # Insecure mode
        
        # Should pass without certificates
        self.assertTrue(self.config.validate())
    
    def test_file_path_detection(self):
        """Test file path detection logic."""
        # JSON payload (starts with {)
        self.assertTrue(self.config._is_file_path('{"test": "data"}') == False)
        
        # File path indicators
        self.assertTrue(self.config._is_file_path('test.json') == True)
        self.assertTrue(self.config._is_file_path('/path/to/file.json') == True)
        self.assertTrue(self.config._is_file_path('path/to/file.jsonl') == True)
        
        # Array JSON (starts with [)
        self.assertTrue(self.config._is_file_path('[{"test": "data"}]') == False)


if __name__ == '__main__':
    unittest.main()
