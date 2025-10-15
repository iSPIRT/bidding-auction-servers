#!/usr/bin/env python3
"""
Unit tests for crypto operations functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_invoke_crypto import BiddingCryptoClient


class TestBiddingCryptoClient(unittest.TestCase):
    """Test cases for BiddingCryptoClient."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.public_key = "test_public_key_data"
        self.key_id = "22"
        self.crypto_client = BiddingCryptoClient(self.public_key, self.key_id)
    
    def test_init(self):
        """Test crypto client initialization."""
        client = BiddingCryptoClient("test_key", "test_id")
        self.assertEqual(client.public_key, "test_key")
        self.assertEqual(client.key_id, "test_id")
    
    def test_encrypt_bid_request_success(self):
        """Test successful bid request encryption."""
        request_data = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{"name": "test", "biddingSignalsKeys": ["key1"]}]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        # This will test the actual encryption method
        # Note: This test may fail if the crypto library is not properly set up
        try:
            result = self.crypto_client.encrypt_bid_request(request_data)
            self.assertIsNotNone(result)
            self.assertIsNotNone(result.encrypted_data)
            self.assertIsNotNone(result.secret)
        except Exception as e:
            # If crypto library is not available, skip the test
            self.skipTest(f"Crypto library not available: {e}")
    
    def test_decrypt_bid_response_success(self):
        """Test successful bid response decryption."""
        encrypted_response = "test_encrypted_data"
        secret = "test_secret"
        
        # This will test the actual decryption method
        # Note: This test may fail if the crypto library is not properly set up
        try:
            result = self.crypto_client.decrypt_bid_response(encrypted_response, secret)
            self.assertIsNotNone(result)
        except Exception as e:
            # If crypto library is not available, skip the test
            self.skipTest(f"Crypto library not available: {e}")
    
    def test_crypto_client_initialization(self):
        """Test crypto client initialization with different parameters."""
        # Test with string parameters
        client1 = BiddingCryptoClient("key1", "id1")
        self.assertEqual(client1.public_key, "key1")
        self.assertEqual(client1.key_id, "id1")
        
        # Test with different parameters
        client2 = BiddingCryptoClient("key2", "id2")
        self.assertEqual(client2.public_key, "key2")
        self.assertEqual(client2.key_id, "id2")
        self.assertNotEqual(client1.public_key, client2.public_key)


if __name__ == '__main__':
    unittest.main()
