#!/usr/bin/env python3
"""
Unit tests for HTTP client functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_invoke_crypto.http_client import BiddingHTTPClient, HTTPClientError


class TestBiddingHTTPClient(unittest.TestCase):
    """Test cases for BiddingHTTPClient."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.buyer_host = "http://test-buyer.example.com"
        self.client = BiddingHTTPClient(self.buyer_host, verbose=False)
    
    def test_init_with_defaults(self):
        """Test HTTP client initialization with defaults."""
        client = BiddingHTTPClient("http://test.example.com")
        self.assertEqual(client.bidding_host, "http://test.example.com")
        self.assertEqual(client.timeout, 20)
        self.assertEqual(client.retry_attempts, 2)
        self.assertEqual(client.retry_delay, 5.0)
        self.assertEqual(client.insecure, False)
        self.assertEqual(client.verbose, False)
    
    def test_init_with_custom_params(self):
        """Test HTTP client initialization with custom parameters."""
        client = BiddingHTTPClient(
            bidding_host="http://test.example.com",
            timeout=30,
            retry_attempts=3,
            retry_delay=2.0,
            insecure=True,
            client_cert="client.crt",
            client_key="client.key",
            ca_cert="ca.crt",
            custom_headers={"Authorization": "Bearer token"},
            verbose=True
        )
        self.assertEqual(client.bidding_host, "http://test.example.com")
        self.assertEqual(client.timeout, 30)
        self.assertEqual(client.retry_attempts, 3)
        self.assertEqual(client.retry_delay, 2.0)
        self.assertEqual(client.insecure, True)
        self.assertEqual(client.client_cert, "client.crt")
        self.assertEqual(client.client_key, "client.key")
        self.assertEqual(client.ca_cert, "ca.crt")
        self.assertEqual(client.verbose, True)
    
    @patch('requests.Session.post')
    def test_send_bid_request_success(self, mock_post):
        """Test successful bid request."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'responseCiphertext': 'encrypted_response_data'
        }
        mock_post.return_value = mock_response
        
        encrypted_data = '{"requestCiphertext": "test", "keyId": "22"}'
        result = self.client.send_bid_request(encrypted_data)
        
        self.assertEqual(result['responseCiphertext'], 'encrypted_response_data')
        mock_post.assert_called_once()
    
    @patch('requests.Session.post')
    def test_send_bid_request_with_key_conversion(self, mock_post):
        """Test bid request with hex to decimal key conversion."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'success'}
        mock_post.return_value = mock_response
        
        encrypted_data = '{"requestCiphertext": "test", "keyId": "16"}'  # hex 16 = decimal 22
        result = self.client.send_bid_request(encrypted_data)
        
        # Verify the request was made with converted key ID
        call_args = mock_post.call_args
        self.assertIn('data', call_args.kwargs)
        request_data = json.loads(call_args.kwargs['data'])
        self.assertEqual(request_data['keyId'], '22')  # Converted from hex 16
    
    @patch('requests.Session.post')
    def test_send_bid_request_connection_error(self, mock_post):
        """Test connection error handling."""
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        with self.assertRaises(HTTPClientError):
            self.client.send_bid_request('{"test": "data"}')
    
    @patch('requests.Session.post')
    def test_send_bid_request_timeout_error(self, mock_post):
        """Test timeout error handling."""
        import requests
        mock_post.side_effect = requests.exceptions.Timeout("Request timeout")
        
        with self.assertRaises(HTTPClientError):
            self.client.send_bid_request('{"test": "data"}')
    
    @patch('requests.Session.post')
    def test_send_bid_request_http_error(self, mock_post):
        """Test HTTP error handling."""
        import requests
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("HTTP 404")
        mock_post.return_value = mock_response
        
        with self.assertRaises(HTTPClientError):
            self.client.send_bid_request('{"test": "data"}')
    
    @patch('requests.Session.post')
    def test_send_bid_request_invalid_json_response(self, mock_post):
        """Test invalid JSON response handling."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_response
        
        with self.assertRaises(HTTPClientError):
            self.client.send_bid_request('{"test": "data"}')
    
    @patch('requests.Session.post')
    def test_send_bid_request_retry_mechanism(self, mock_post):
        """Test retry mechanism on failure."""
        import requests
        
        # First call fails, second succeeds
        mock_post.side_effect = [
            requests.exceptions.ConnectionError("Connection failed"),
            Mock(status_code=200, json=lambda: {'result': 'success'})
        ]
        
        client = BiddingHTTPClient(self.buyer_host, retry_attempts=2, verbose=False)
        result = client.send_bid_request('{"test": "data"}')
        
        self.assertEqual(result['result'], 'success')
        self.assertEqual(mock_post.call_count, 2)
    
    @patch('requests.Session.post')
    def test_send_bid_request_with_response_handling(self, mock_post):
        """Test bid request with response handling."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'responseCiphertext': 'encrypted_response_data'
        }
        mock_post.return_value = mock_response
        
        encrypted_data = '{"requestCiphertext": "test", "keyId": "22"}'
        server_response, encrypted_response = self.client.send_bid_request_with_response_handling(encrypted_data)
        
        self.assertEqual(server_response['responseCiphertext'], 'encrypted_response_data')
        self.assertEqual(encrypted_response, 'encrypted_response_data')
    
    @patch('requests.Session.post')
    def test_send_bid_request_with_response_handling_no_ciphertext(self, mock_post):
        """Test bid request with response handling when no ciphertext."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'success'}
        mock_post.return_value = mock_response
        
        encrypted_data = '{"requestCiphertext": "test", "keyId": "22"}'
        
        with self.assertRaises(HTTPClientError):
            self.client.send_bid_request_with_response_handling(encrypted_data)
    
    @patch('requests.Session.get')
    def test_get_service_info_success(self, mock_get):
        """Test successful service info retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'service': 'test', 'version': '1.0'}
        mock_get.return_value = mock_response
        
        info = self.client.get_service_info()
        
        self.assertEqual(info['service'], 'test')
        self.assertEqual(info['version'], '1.0')
    
    @patch('requests.Session.get')
    def test_get_service_info_failure(self, mock_get):
        """Test service info retrieval failure."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        info = self.client.get_service_info()
        
        self.assertIsNone(info)
    
    def test_ssl_configuration_insecure(self):
        """Test SSL configuration in insecure mode."""
        client = BiddingHTTPClient(self.buyer_host, insecure=True)
        self.assertFalse(client.session.verify)
    
    def test_ssl_configuration_secure_with_ca_cert(self):
        """Test SSL configuration in secure mode with CA cert."""
        client = BiddingHTTPClient(self.buyer_host, ca_cert="ca.crt")
        self.assertEqual(client.session.verify, "ca.crt")
    
    def test_ssl_configuration_secure_with_client_cert(self):
        """Test SSL configuration in secure mode with client cert."""
        client = BiddingHTTPClient(self.buyer_host, client_cert="client.crt", client_key="client.key")
        self.assertEqual(client.session.cert, ("client.crt", "client.key"))


if __name__ == '__main__':
    unittest.main()
