#!/usr/bin/env python3
"""
Unit tests for KMS client functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_invoke_crypto.kms_client import KMSClient, KMSClientError


class TestKMSClient(unittest.TestCase):
    """Test cases for KMSClient."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.kms_host = "https://test-kms.example.com"
        self.client = KMSClient(self.kms_host, verbose=False)
    
    def test_init_with_defaults(self):
        """Test KMS client initialization with defaults."""
        client = KMSClient("https://test.example.com")
        self.assertEqual(client.kms_host, "https://test.example.com")
        self.assertEqual(client.timeout, 30)
        self.assertEqual(client.insecure, False)
        self.assertEqual(client.verbose, False)
    
    def test_init_with_custom_params(self):
        """Test KMS client initialization with custom parameters."""
        client = KMSClient(
            kms_host="https://test.example.com",
            timeout=60,
            insecure=True,
            client_cert="client.crt",
            client_key="client.key",
            ca_cert="ca.crt",
            verbose=True
        )
        self.assertEqual(client.kms_host, "https://test.example.com")
        self.assertEqual(client.timeout, 60)
        self.assertEqual(client.insecure, True)
        self.assertEqual(client.client_cert, "client.crt")
        self.assertEqual(client.client_key, "client.key")
        self.assertEqual(client.ca_cert, "ca.crt")
        self.assertEqual(client.verbose, True)
    
    @patch('requests.Session.get')
    def test_list_public_keys_success(self, mock_get):
        """Test successful public key listing."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'keys': [
                {
                    'id': '22',
                    'key': 'test_public_key_data'
                }
            ]
        }
        mock_get.return_value = mock_response
        
        keys = self.client.list_public_keys()
        
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]['key_id'], '22')
        self.assertEqual(keys[0]['public_key'], 'test_public_key_data')
        mock_get.assert_called_once()
    
    @patch('requests.Session.get')
    def test_list_public_keys_connection_error(self, mock_get):
        """Test connection error handling."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        with self.assertRaises(KMSClientError):
            self.client.list_public_keys()
    
    @patch('requests.Session.get')
    def test_list_public_keys_timeout_error(self, mock_get):
        """Test timeout error handling."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout("Request timeout")
        
        with self.assertRaises(KMSClientError):
            self.client.list_public_keys()
    
    @patch('requests.Session.get')
    def test_list_public_keys_http_error(self, mock_get):
        """Test HTTP error handling."""
        import requests
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("HTTP 404")
        mock_get.return_value = mock_response
        
        with self.assertRaises(KMSClientError):
            self.client.list_public_keys()
    
    @patch('requests.Session.get')
    def test_list_public_keys_invalid_json(self, mock_get):
        """Test invalid JSON response handling."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response
        
        with self.assertRaises(KMSClientError):
            self.client.list_public_keys()
    
    @patch('requests.Session.get')
    def test_list_public_keys_no_valid_keys(self, mock_get):
        """Test handling when no valid keys are found."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'keys': []}
        mock_get.return_value = mock_response
        
        with self.assertRaises(KMSClientError):
            self.client.list_public_keys()
    
    def test_normalize_key_valid(self):
        """Test key normalization with valid data."""
        key_data = {
            'id': '22',
            'key': 'test_public_key'
        }
        
        normalized = self.client._normalize_key(key_data, 0)
        
        self.assertEqual(normalized['key_id'], '22')
        self.assertEqual(normalized['public_key'], 'test_public_key')
    
    def test_normalize_key_missing_id(self):
        """Test key normalization with missing ID."""
        key_data = {
            'key': 'test_public_key'
        }
        
        with self.assertRaises(ValueError):
            self.client._normalize_key(key_data, 0)
    
    def test_normalize_key_missing_key(self):
        """Test key normalization with missing public key."""
        key_data = {
            'id': '22'
        }
        
        with self.assertRaises(ValueError):
            self.client._normalize_key(key_data, 0)
    
    @patch('requests.Session.get')
    def test_get_key_by_id_success(self, mock_get):
        """Test getting key by ID successfully."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'keys': [
                {'id': '22', 'key': 'key22'},
                {'id': '23', 'key': 'key23'}
            ]
        }
        mock_get.return_value = mock_response
        
        key = self.client.get_key_by_id('22')
        
        self.assertIsNotNone(key)
        self.assertEqual(key['key_id'], '22')
        self.assertEqual(key['public_key'], 'key22')
    
    @patch('requests.Session.get')
    def test_get_key_by_id_not_found(self, mock_get):
        """Test getting key by ID when not found."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'keys': [
                {'id': '22', 'key': 'key22'}
            ]
        }
        mock_get.return_value = mock_response
        
        key = self.client.get_key_by_id('99')
        
        self.assertIsNone(key)


if __name__ == '__main__':
    unittest.main()
