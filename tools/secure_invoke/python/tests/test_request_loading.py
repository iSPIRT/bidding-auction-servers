#!/usr/bin/env python3
"""
Unit tests for request data loading functionality.
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_invoke import SecureInvokeTool, SecureInvokeConfig


class TestRequestLoading(unittest.TestCase):
    """Test cases for request data loading."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = SecureInvokeConfig()
        self.config.kms_host = "127.0.0.1:8000"
        self.config.buyer_host = "127.0.0.1:51052"
        self.config.insecure = True
        self.tool = SecureInvokeTool(self.config)
    
    def test_load_json_file(self):
        """Test loading JSON file."""
        test_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test"}]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            import json
            json.dump(test_data, f)
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            result = self.tool.load_request_data()
            
            self.assertEqual(result, test_data)
        finally:
            os.unlink(temp_file)
    
    def test_load_jsonl_file(self):
        """Test loading JSONL file (first line only)."""
        test_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test"}]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            import json
            json.dump(test_data, f)
            f.write('\n')  # Add second line
            json.dump({"other": "data"}, f)
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            result = self.tool.load_request_data()
            
            self.assertEqual(result, test_data)
        finally:
            os.unlink(temp_file)
    
    def test_load_direct_json_payload(self):
        """Test loading direct JSON payload."""
        test_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test"}]
            }
        }
        
        self.config.request_payload = str(test_data).replace("'", '"')
        result = self.tool.load_request_data()
        
        self.assertEqual(result, test_data)
    
    def test_load_wrapped_request(self):
        """Test loading wrapped request (with 'request' wrapper)."""
        wrapped_data = {
            "id": 1,
            "request": {
                "client_type": "CLIENT_TYPE_BROWSER",
                "buyerInput": {
                    "interestGroups": [{"name": "test"}]
                }
            }
        }
        
        expected_data = wrapped_data["request"]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            import json
            json.dump(wrapped_data, f)
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            result = self.tool.load_request_data()
            
            self.assertEqual(result, expected_data)
        finally:
            os.unlink(temp_file)
    
    def test_load_invalid_json_file(self):
        """Test loading invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('invalid json content')
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            result = self.tool.load_request_data()
            
            self.assertIsNone(result)
        finally:
            os.unlink(temp_file)
    
    def test_load_empty_jsonl_file(self):
        """Test loading empty JSONL file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            result = self.tool.load_request_data()
            
            self.assertIsNone(result)
        finally:
            os.unlink(temp_file)
    
    def test_load_invalid_json_payload(self):
        """Test loading invalid JSON payload."""
        self.config.request_payload = 'invalid json string'
        result = self.tool.load_request_data()
        
        self.assertIsNone(result)
    
    def test_file_path_detection_json(self):
        """Test file path detection for JSON strings."""
        # Direct JSON (starts with {)
        self.assertFalse(self.config._is_file_path('{"test": "data"}'))
        
        # Array JSON (starts with [)
        self.assertFalse(self.config._is_file_path('[{"test": "data"}]'))
    
    def test_file_path_detection_file_paths(self):
        """Test file path detection for file paths."""
        # File extensions
        self.assertTrue(self.config._is_file_path('test.json'))
        self.assertTrue(self.config._is_file_path('test.jsonl'))
        
        # Path separators
        self.assertTrue(self.config._is_file_path('/path/to/file.json'))
        self.assertTrue(self.config._is_file_path('path/to/file.json'))
        self.assertTrue(self.config._is_file_path('path\\to\\file.json'))
    
    def test_file_path_detection_existing_file(self):
        """Test file path detection for existing files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"test": "data"}')
            temp_file = f.name
        
        try:
            # Should detect as file path if file exists
            self.assertTrue(self.config._is_file_path(temp_file))
        finally:
            os.unlink(temp_file)
    
    def test_file_path_detection_single_word(self):
        """Test file path detection for single words."""
        # Single word without special characters
        self.assertTrue(self.config._is_file_path('testfile'))
        
        # Single word with JSON characters
        self.assertFalse(self.config._is_file_path('{"test"}'))


if __name__ == '__main__':
    unittest.main()
