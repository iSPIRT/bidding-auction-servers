#!/usr/bin/env python3
"""
KMS (Key Management Service) client for fetching public keys.

This module provides functionality to fetch public keys from a KMS endpoint
for use with the SecureInvoke Crypto library.
"""

import requests
import json
import base64
import urllib3
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KMSClientError(Exception):
    """Custom exception for KMS client errors"""
    pass


class KMSClient:
    """
    Client for fetching public keys from a KMS endpoint.
    """
    
    def __init__(self, kms_host: str, timeout: int = 30, insecure: bool = False,
                 client_cert: Optional[str] = None, client_key: Optional[str] = None,
                 ca_cert: Optional[str] = None, verbose: bool = False):
        """
        Initialize the KMS client.
        
        Args:
            kms_host: Base URL of the KMS service (e.g., "https://depa-inferencing-kms.centralindia.cloudapp.azure.com")
            timeout: Request timeout in seconds
            insecure: Disable SSL certificate verification
            client_cert: Path to client certificate file
            client_key: Path to client private key file
            ca_cert: Path to CA certificate file
        """
        self.kms_host = kms_host.rstrip('/')
        self.timeout = timeout
        self.insecure = insecure
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.verbose = verbose
        self.session = requests.Session()
        
        # Configure SSL
        self._configure_ssl()
        
        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'SecureInvoke-KMS-Client/1.0'
        })
    
    def _configure_ssl(self):
        """Configure SSL settings for the session."""
        if self.insecure:
            # Disable SSL verification
            self.session.verify = False
        else:
            # Configure SSL certificates if provided
            if self.client_cert and self.client_key:
                self.session.cert = (self.client_cert, self.client_key)
            elif self.client_cert:
                self.session.cert = self.client_cert
            
            if self.ca_cert:
                self.session.verify = self.ca_cert
            else:
                self.session.verify = True
    
    def list_public_keys(self, endpoint: str = "/listpubkeys") -> List[Dict[str, Any]]:
        """
        Fetch public keys from the KMS endpoint.
        
        Args:
            endpoint: API endpoint for listing public keys (default: "/listpubkeys")
            
        Returns:
            List of public key dictionaries containing key_id, public_key, and metadata
            
        Raises:
            KMSClientError: If the request fails or response is invalid
        """
        url = urljoin(self.kms_host, endpoint)
        
        try:
            if self.verbose:
                print(f"Fetching public keys from: {url}")
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            
            # Parse the response
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                raise KMSClientError(f"Invalid JSON response from KMS: {e}")
            
            keys = data['keys']
            
            # Validate and normalize the keys
            normalized_keys = []
            for i, key in enumerate(keys):
                try:
                    normalized_key = self._normalize_key(key, i)
                    normalized_keys.append(normalized_key)
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Skipping invalid key {i}: {e}")
                    continue
            
            if not normalized_keys:
                raise KMSClientError("No valid public keys found in KMS response")
            
            if self.verbose:
                print(f"✓ Successfully fetched {len(normalized_keys)} public keys")
            return normalized_keys
            
        except requests.exceptions.ConnectionError as e:
            raise KMSClientError(f"Failed to connect to KMS at {url}: {e}")
        except requests.exceptions.Timeout as e:
            raise KMSClientError(f"Request to KMS timed out: {e}")
        except requests.exceptions.HTTPError as e:
            raise KMSClientError(f"HTTP error from KMS: {e}")
        except requests.exceptions.RequestException as e:
            raise KMSClientError(f"Request error: {e}")
    
    def _normalize_key(self, key_data: Dict[str, Any], index: int) -> Dict[str, Any]:
        """
        Normalize a key dictionary to a standard format.
        
        Args:
            key_data: Raw key data from KMS
            index: Index of the key (for error reporting)
            
        Returns:
            Normalized key dictionary with 'key_id', 'public_key', and 'metadata'
        """
        normalized = {
            'key_id': None, # hex key id
            'public_key': None, # base64 public key
        }
        
        # Extract key_id
        normalized['key_id'] = str(key_data['id'])
        
        # Extract public_key
        normalized['public_key'] = str(key_data['key'])
        
        # Validate required fields
        if not normalized['key_id']:
            raise ValueError(f"Key {index} missing 'id' field for key_id")
        if not normalized['public_key']:
            raise ValueError(f"Key {index} missing 'key' field for public_key")
        
        return normalized
    
    def get_key_by_id(self, key_id: str, endpoint: str = "/listpubkeys") -> Optional[Dict[str, Any]]:
        """
        Get a specific public key by ID.
        
        Args:
            key_id: The key ID to search for
            endpoint: API endpoint for listing public keys
            
        Returns:
            Key dictionary if found, None otherwise
        """
        keys = self.list_public_keys(endpoint)
        
        for key in keys:
            if key['key_id'] == str(key_id):
                return key
        
        return None

def demo():
    """
    Demonstration of the KMS client.
    """
    print("KMS Client Demo")
    print("=" * 40)
    
    # Example KMS configuration (fallback only)
    kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    endpoint = "/listpubkeys"
    
    try:
        # Initialize KMS client
        print(f"Connecting to KMS: {kms_host}")
        kms_client = KMSClient(kms_host)
        
        # Fetch public keys
        print(f"Fetching public keys from {endpoint}...")
        keys = kms_client.list_public_keys(endpoint)
        
        print(f"\n✓ Found {len(keys)} public keys:")
        for i, key in enumerate(keys, 1):
            print(f"  Key {i}:")
            print(f"    ID: {key['key_id']}")
            print(f"    Public Key: {key['public_key'][:50]}...")
            if key['metadata']:
                print(f"    Metadata: {key['metadata']}")
        
        # Example: Get a specific key
        if keys:
            first_key = keys[0]
            print(f"\nUsing key ID: {first_key['key_id']}")
            print(f"Public key: {first_key['public_key']}")
        
    except KMSClientError as e:
        print(f"✗ KMS error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


if __name__ == '__main__':
    demo()