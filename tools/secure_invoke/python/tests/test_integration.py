#!/usr/bin/env python3
"""
Integration tests for the main SecureRequestClient pipeline.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
import sys
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_request import SecureRequestClient, SecureRequestConfig


class TestSecureRequestIntegration(unittest.TestCase):
    """Integration tests for SecureRequestClient pipeline."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = SecureRequestConfig()
        self.config.kms_host = "https://test-kms.example.com"
        self.config.offer_host = "http://test-offer.example.com"
        self.config.insecure = True
        self.config.enable_verbose = False
        self.tool = SecureRequestClient(self.config)
    
    @patch('secure_request_client.kms_client.KMSClient.list_public_keys')
    @patch('secure_request_client.OfferRequestClient.encrypt_offer_request')
    @patch('secure_request_client.http_client.OfferHTTPClient.send_offer_request')
    @patch('secure_request_client.OfferRequestClient.decrypt_offer_response')
    def test_full_pipeline_success(self, mock_decrypt, mock_send, mock_encrypt, mock_list_keys):
        """Test full pipeline execution with success for offer requests."""
        # Mock KMS response
        mock_list_keys.return_value = [
            {'key_id': '22', 'public_key': 'test_public_key'}
        ]
        
        # Mock encryption
        mock_encrypt_result = Mock()
        mock_encrypt_result.encrypted_data = '{"requestCiphertext": "encrypted", "keyId": "22"}'
        mock_encrypt_result.secret = 'secret_key'
        mock_encrypt.return_value = mock_encrypt_result
        
        # Mock HTTP response
        mock_send.return_value = {
            'responseCiphertext': 'encrypted_response'
        }
        
        # Mock decryption
        mock_decrypt.return_value = {'result': 'success'}
        
        # Test data
        request_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        # Run pipeline
        result = self.tool.process_single_request(request_data, {'key_id': '22', 'public_key': 'test_public_key'})
        
        # Verify result
        self.assertEqual(result, {'result': 'success'})
        
        # Verify all mocks were called
        mock_encrypt.assert_called_once_with(request_data)
        mock_send.assert_called_once()
        mock_decrypt.assert_called_once()
    
    @patch('secure_request_client.kms_client.KMSClient.list_public_keys')
    def test_fetch_public_key_success(self, mock_list_keys):
        """Test successful public key fetching for offer requests."""
        mock_list_keys.return_value = [
            {'key_id': '22', 'public_key': 'test_public_key'}
        ]
        
        result = self.tool.fetch_public_key()
        
        self.assertIsNotNone(result)
        self.assertEqual(result['key_id'], '22')
        self.assertEqual(result['public_key'], 'test_public_key')
    
    @patch('secure_request_client.kms_client.KMSClient.list_public_keys')
    def test_fetch_public_key_failure(self, mock_list_keys):
        """Test public key fetching failure for offer requests."""
        from secure_request_client.kms_client import KMSClientError
        mock_list_keys.side_effect = KMSClientError("KMS connection failed")
        
        result = self.tool.fetch_public_key()
        
        self.assertIsNone(result)
    
    def test_setup_kms_client_success(self):
        """Test successful KMS client setup for offer requests."""
        result = self.tool.setup_kms_client()
        
        self.assertTrue(result)
        self.assertIsNotNone(self.tool.kms_client)
    
    def test_setup_kms_client_failure(self):
        """Test KMS client setup failure with invalid host for offer requests."""
        # Use invalid host to trigger failure
        self.config.kms_host = "invalid://host"
        tool = SecureRequestClient(self.config)
        
        result = tool.setup_kms_client()
        
        self.assertFalse(result)
    
    def test_setup_http_client_success(self):
        """Test successful HTTP client setup for offer requests."""
        result = self.tool.setup_http_client()
        
        self.assertTrue(result)
        self.assertIsNotNone(self.tool.http_client)
    
    def test_setup_http_client_failure(self):
        """Test HTTP client setup failure with invalid host."""
        # Use invalid host to trigger failure
        self.config.offer_host = "invalid://host"
        tool = SecureRequestClient(self.config)
        
        result = tool.setup_http_client()
        
        self.assertFalse(result)
    
    def test_load_request_data_from_file(self):
        """Test loading request data from file."""
        test_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_data, f)
            temp_file = f.name
        
        try:
            self.config.request_payload = temp_file
            result = self.tool.load_request_data()
            
            self.assertEqual(result, test_data)
        finally:
            os.unlink(temp_file)
    
    def test_load_request_data_from_json(self):
        """Test loading request data from JSON string."""
        test_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        self.config.request_payload = json.dumps(test_data)
        result = self.tool.load_request_data()
        
        self.assertEqual(result, test_data)
    
    @patch('secure_request_client.kms_client.KMSClient.list_public_keys')
    @patch('secure_request_client.OfferRequestClient.encrypt_offer_request')
    @patch('secure_request_client.http_client.OfferHTTPClient.send_offer_request')
    def test_pipeline_without_encrypted_response(self, mock_send, mock_encrypt, mock_list_keys):
        """Test pipeline when server doesn't return encrypted response for offer requests."""
        # Mock KMS response
        mock_list_keys.return_value = [
            {'key_id': '22', 'public_key': 'test_public_key'}
        ]
        
        # Mock encryption
        mock_encrypt_result = Mock()
        mock_encrypt_result.encrypted_data = '{"requestCiphertext": "encrypted", "keyId": "22"}'
        mock_encrypt_result.secret = 'secret_key'
        mock_encrypt.return_value = mock_encrypt_result
        
        # Mock HTTP response without encrypted response
        mock_send.return_value = {'result': 'success'}
        
        # Test data
        request_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        # Run pipeline
        result = self.tool.process_single_request(request_data, {'key_id': '22', 'public_key': 'test_public_key'})
        
        # Verify result
        self.assertEqual(result, {'result': 'success'})
    
    @patch('secure_request_client.kms_client.KMSClient.list_public_keys')
    @patch('secure_request_client.OfferRequestClient.encrypt_offer_request')
    @patch('secure_request_client.http_client.OfferHTTPClient.send_offer_request')
    def test_pipeline_encryption_failure(self, mock_send, mock_encrypt, mock_list_keys):
        """Test pipeline when encryption fails for offer requests."""
        # Mock KMS response
        mock_list_keys.return_value = [
            {'key_id': '22', 'public_key': 'test_public_key'}
        ]
        
        # Mock encryption failure
        mock_encrypt.side_effect = Exception("Encryption failed")
        
        # Test data
        request_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        # Run pipeline
        result = self.tool.process_single_request(request_data, {'key_id': '22', 'public_key': 'test_public_key'})
        
        # Verify result
        self.assertIsNone(result)
    
    @patch('secure_request_client.kms_client.KMSClient.list_public_keys')
    @patch('secure_request_client.OfferRequestClient.encrypt_offer_request')
    @patch('secure_request_client.http_client.OfferHTTPClient.send_offer_request')
    def test_pipeline_http_failure(self, mock_send, mock_encrypt, mock_list_keys):
        """Test pipeline when HTTP request fails for offer requests."""
        # Mock KMS response
        mock_list_keys.return_value = [
            {'key_id': '22', 'public_key': 'test_public_key'}
        ]
        
        # Mock encryption
        mock_encrypt_result = Mock()
        mock_encrypt_result.encrypted_data = '{"requestCiphertext": "encrypted", "keyId": "22"}'
        mock_encrypt_result.secret = 'secret_key'
        mock_encrypt.return_value = mock_encrypt_result
        
        # Mock HTTP failure
        from secure_request_client.http_client import HTTPClientError
        mock_send.side_effect = HTTPClientError("HTTP request failed")
        
        # Test data
        request_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        # Run pipeline
        result = self.tool.process_single_request(request_data, {'key_id': '22', 'public_key': 'test_public_key'})
        
        # Verify result
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
