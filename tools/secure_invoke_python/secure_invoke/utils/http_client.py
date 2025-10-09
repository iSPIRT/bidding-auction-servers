"""HTTP client for communicating with BFE service."""

import json
import logging
from typing import Dict, Any, Optional

import requests


logger = logging.getLogger(__name__)


class BFEClient:
    """HTTP client for BFE (Buyer Front End) service."""
    
    def __init__(
        self,
        host: str,
        endpoint: str = '/v1/getbids',
        client_ip: str = '0.0.0.0',
        user_agent: str = 'SecureInvoke/1.0',
        accept_language: str = 'en-US,en;q=0.9',
        insecure: bool = False,
        timeout: int = 120,
        verbose: bool = False
    ):
        """
        Initialize BFE client.
        
        Args:
            host: BFE host address (e.g., "4.187.223.221:51052")
            endpoint: API endpoint path
            client_ip: Client IP address for x-bna-client-ip header
            user_agent: User agent string
            accept_language: Accept-Language header value
            insecure: Disable SSL verification
            timeout: Request timeout in seconds
            verbose: Enable verbose logging
        """
        self.host = host.rstrip('/')
        self.endpoint = endpoint
        self.client_ip = client_ip
        self.user_agent = user_agent
        self.accept_language = accept_language
        self.insecure = insecure
        self.timeout = timeout
        self.verbose = verbose
        
        # Determine protocol
        if not self.host.startswith('http'):
            # Default to https unless insecure
            protocol = 'http' if insecure else 'https'
            self.host = f'{protocol}://{self.host}'
        
        self.url = f'{self.host}{self.endpoint}'
        
        # Create session
        self.session = requests.Session()
        if insecure:
            logger.warning("SSL verification disabled - this is insecure!")
            self.session.verify = False
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        logger.info(f"BFE client initialized for {self.url}")
    
    def send_request(
        self,
        request_json: Dict[str, Any],
        additional_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Send encrypted request to BFE.
        
        Args:
            request_json: Packaged request with requestCiphertext and keyId
            additional_headers: Optional additional HTTP headers
            
        Returns:
            Response JSON from BFE
        """
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'x-bna-client-ip': self.client_ip,
            'x-user-agent': self.user_agent,
            'x-accept-language': self.accept_language,
        }
        
        # Add additional headers if provided
        if additional_headers:
            headers.update(additional_headers)
        
        # Log request details
        logger.info(f"\n🌐 Sending HTTP Request")
        logger.info(f"  📍 URL: {self.url}")
        logger.info(f"  🔒 SSL Verification: {'Disabled' if self.insecure else 'Enabled'}")
        logger.info(f"  ⏱️  Timeout: {self.timeout}s")
        
        if self.verbose:
            logger.info(f"\n  📋 Request Headers:")
            for key, value in headers.items():
                logger.info(f"     {key}: {value}")
            
            logger.info(f"\n  📦 Request Body:")
            request_str = json.dumps(request_json, indent=2)
            # Show abbreviated ciphertext
            if 'requestCiphertext' in request_json:
                ct = request_json['requestCiphertext']
                abbreviated = {
                    **request_json,
                    'requestCiphertext': f"{ct[:50]}...{ct[-50:]} ({len(ct)} chars total)"
                }
                logger.info(f"     {json.dumps(abbreviated, indent=2)}")
            else:
                logger.info(f"     {request_str}")
        
        try:
            # Send POST request
            logger.info(f"  🚀 Sending POST request...")
            response = self.session.post(
                self.url,
                json=request_json,
                headers=headers,
                timeout=self.timeout
            )
            
            # Log response details
            logger.info(f"\n  ✅ Response Received")
            logger.info(f"  📊 Status Code: {response.status_code}")
            
            if self.verbose:
                logger.info(f"\n  📋 Response Headers:")
                for key, value in response.headers.items():
                    logger.info(f"     {key}: {value}")
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse response JSON
            response_json = response.json()
            
            if self.verbose:
                logger.info(f"\n  📦 Response Body:")
                response_str = json.dumps(response_json, indent=2)
                # Show abbreviated ciphertext
                if 'responseCiphertext' in response_json:
                    ct = response_json['responseCiphertext']
                    abbreviated = {
                        **response_json,
                        'responseCiphertext': f"{ct[:50]}...{ct[-50:]} ({len(ct)} chars total)"
                    }
                    logger.info(f"     {json.dumps(abbreviated, indent=2)}")
                else:
                    logger.info(f"     {response_str}")
            
            logger.info(f"  ✅ Request completed successfully")
            
            return response_json
        
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out after {self.timeout} seconds")
            raise RuntimeError(f"Request timeout: {self.timeout}s")
        
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            raise RuntimeError(f"Failed to connect to {self.url}: {e}")
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            logger.error(f"Response body: {e.response.text}")
            raise RuntimeError(f"HTTP error {e.response.status_code}: {e.response.text}")
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise RuntimeError(f"Request failed: {e}")
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse response JSON: {e}")
            raise ValueError(f"Invalid JSON response: {e}")
    
    def close(self):
        """Close the HTTP session."""
        self.session.close()
        logger.info("BFE client session closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

