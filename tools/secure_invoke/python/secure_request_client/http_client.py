#!/usr/bin/env python3
"""
HTTP client for sending encrypted requests to bidding services.

This module provides functionality to send encrypted bid requests
to bidding servers and handle responses.
"""

import requests
import json
import time
import urllib3
import ssl
from typing import Dict, Optional, Any, Tuple
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClientError(Exception):
    """Custom exception for HTTP client errors"""
    pass


class OfferHTTPClient:
    """
    HTTP client for sending encrypted requests to bidding services.
    """
    
    def __init__(self, 
                 offer_host: str, 
                 timeout: int = 20,
                 retry_attempts: int = 2,
                 retry_delay: float = 5.0,
                 insecure: bool = False,
                 client_cert: Optional[str] = None,
                 client_key: Optional[str] = None,
                 ca_cert: Optional[str] = None,
                 custom_headers: Optional[Dict[str, str]] = None,
                 verbose: bool = False):
        """
        Initialize the offer HTTP client.
        
        Args:
            offer_host: Base URL of the offer service (e.g., "http://98.70.217.115:51052")
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts for failed requests
            retry_delay: Delay between retries in seconds
            insecure: Disable SSL certificate verification
            client_cert: Path to client certificate file
            client_key: Path to client private key file
            ca_cert: Path to CA certificate file
            custom_headers: Additional custom headers
        """
        self.offer_host = offer_host.rstrip('/')
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
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
            'Accept': 'application/json'
        })
        
        # Add custom headers
        if custom_headers:
            self.session.headers.update(custom_headers)
    
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
    
    def send_offer_request(self, 
                       encrypted_data: str, 
                       endpoint: str = "/v1/getbids",
                       additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Send an encrypted offer request to the offer service.
        
        Args:
            encrypted_data: JSON string containing the encrypted request
            endpoint: API endpoint for offer requests (default: "/v1/getbids")
            additional_headers: Optional additional headers to include
            
        Returns:
            Server response as dictionary
            
        Raises:
            HTTPClientError: If the request fails after all retries
        """
        url = urljoin(self.offer_host, endpoint)
        
        # Prepare headers
        headers = self.session.headers.copy()
        if additional_headers:
            headers.update(additional_headers)
        
        # Parse the encrypted data to extract key information for headers
        try:
            request_data = json.loads(encrypted_data)
            if 'keyId' in request_data:
                key_id = request_data['keyId']
                headers['x-key-id'] = str(key_id)
                if self.verbose:
                    print(f"Using key ID: {key_id}")
                
        except (json.JSONDecodeError, KeyError):
            # If we can't parse the encrypted data, continue without key ID header
            pass
        
        last_exception = None
        
        for attempt in range(self.retry_attempts):
            try:
                if self.verbose:
                    print(f"Sending offer request to: {url} (attempt {attempt + 1}/{self.retry_attempts})")
                    print(f"Request payload length: {len(encrypted_data)} bytes")
                
                response = self.session.post(
                    url,
                    data=encrypted_data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
                
                if self.verbose:
                    print(f"✓ Request completed with status: {response.status_code}")
                    print(f"Response headers: {dict(response.headers)}")
                    print(f"Response length: {len(response.text)} bytes")
                
                # Check for HTTP errors
                response.raise_for_status()
                
                # Parse JSON response
                try:
                    return response.json()
                except json.JSONDecodeError as e:
                    raise HTTPClientError(f"Invalid JSON response from server: {e}")
                
            except requests.exceptions.ConnectionError as e:
                last_exception = HTTPClientError(f"Connection error: {e}")
                if self.verbose:
                    print(f"✗ Connection error (attempt {attempt + 1}): {e}")
                
            except requests.exceptions.Timeout as e:
                last_exception = HTTPClientError(f"Request timeout: {e}")
                if self.verbose:
                    print(f"✗ Timeout error (attempt {attempt + 1}): {e}")
                
            except requests.exceptions.HTTPError as e:
                last_exception = HTTPClientError(f"HTTP error {response.status_code}: {e}")
                if self.verbose:
                    print(f"✗ HTTP error (attempt {attempt + 1}): {e}")
                    if hasattr(response, 'text'):
                        print(f"Response body: {response.text[:500]}...")
                
            except requests.exceptions.RequestException as e:
                last_exception = HTTPClientError(f"Request error: {e}")
                if self.verbose:
                    print(f"✗ Request error (attempt {attempt + 1}): {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < self.retry_attempts - 1:
                if self.verbose:
                    print(f"Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
        
        # All retries failed
        raise last_exception or HTTPClientError("All retry attempts failed")
    
    def get_offer(self, 
                  encrypted_data: str, 
                  endpoint: str = "/v1/getbids",
                  additional_headers: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, Any], str]:
        """
        Send an encrypted offer request and extract the encrypted response.
        
        Args:
            encrypted_data: JSON string containing the encrypted request
            endpoint: API endpoint for offer requests
            additional_headers: Optional additional headers to include
            
        Returns:
            Tuple of (server_response_dict, encrypted_response_ciphertext)
            
        Raises:
            HTTPClientError: If the request fails or response format is invalid
        """
        # Send the request
        server_response = self.send_offer_request(encrypted_data, endpoint, additional_headers)
        
        # Extract the encrypted response
        if 'responseCiphertext' not in server_response:
            available_keys = list(server_response.keys())
            raise HTTPClientError(f"No 'responseCiphertext' found in server response. Available keys: {available_keys}")
        
        encrypted_response = server_response['responseCiphertext']
        if self.verbose:
            print(f"✓ Extracted encrypted response: {len(encrypted_response)} bytes")
        
        return server_response, encrypted_response
    
    def get_service_info(self, endpoint: str = "/info") -> Optional[Dict[str, Any]]:
        """
        Get information about the offer service.
        
        Args:
            endpoint: Info endpoint (default: "/info")
            
        Returns:
            Service information dictionary or None if not available
        """
        url = urljoin(self.offer_host, endpoint)
        
        try:
            response = self.session.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None