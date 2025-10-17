#!/usr/bin/env python3
"""
Secure Request Client CLI

A command-line tool for secure request operations with support for:
- Direct offer request payload input or file-based payloads
- Configurable KMS and Offer hosts
- SSL certificate management
- Custom headers and retry logic for Offer service
- Verbose debugging output
"""

import json
import os
import sys
import argparse
import ssl
import contextlib
import subprocess
from pathlib import Path
from typing import Dict, Optional, Any
from io import StringIO

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_request_client import OfferRequestClient
from secure_request_client.kms_client import KMSClient, KMSClientError
from secure_request_client.http_client import OfferHTTPClient, HTTPClientError


@contextlib.contextmanager
def suppress_stdout():
    """Context manager to suppress stdout output."""
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        yield
    finally:
        sys.stdout = old_stdout


class SecureRequestConfig:
    """Configuration class for Secure Request Client parameters."""
    
    def __init__(self):
        # Core parameters
        self.kms_host: str = ""
        self.offer_host: str = ""
        self.request_payload: str = ""
        
        # Retry and connection parameters
        self.retries: int = 1
        self.insecure: bool = False
        self.headers: Dict[str, str] = {}
        
        # SSL certificate parameters
        self.client_key: Optional[str] = None
        self.client_cert: Optional[str] = None
        self.ca_cert: Optional[str] = None
        
        # Debug parameters
        self.enable_verbose: bool = False
    
    def validate(self) -> bool:
        """Validate the configuration parameters."""
        if not self.kms_host:
            print("✗ Error: kms-host is required")
            return False
        
        if not self.offer_host:
            print("✗ Error: offer-host is required")
            return False
        
        if not self.request_payload:
            print("✗ Error: request-payload is required")
            return False
        
        # Check if request_payload is a file path or direct JSON
        if self._is_file_path(self.request_payload):
            if not os.path.exists(self.request_payload):
                print(f"✗ Error: Request file not found: {self.request_payload}")
                return False
        
        # SSL certificate validation
        if not self.insecure:
            # In secure mode, we need at least a CA certificate or client certificates
            if not self.ca_cert and not (self.client_cert and self.client_key):
                print("✗ Error: SSL certificates are required when not in insecure mode")
                print("  Either provide --ca-cert or both --client-cert and --client-key")
                print("  Or use --insecure to disable certificate verification")
                return False
        
        return True
    
    def _is_file_path(self, payload: str) -> bool:
        """Check if the payload is a file path or direct JSON."""
        # If it starts with { or [, it's likely direct JSON
        if payload.strip().startswith(('{', '[')):
            return False
        
        # If it contains file path indicators, it's likely a file path
        if ('/' in payload or '\\' in payload or 
            payload.endswith(('.json', '.jsonl')) or
            os.path.exists(payload)):
            return True
        
        # If it's a single word without special characters, it might be a file
        if len(payload.split()) == 1 and not any(c in payload for c in '{[]}"'):
            return True
        
        # Default to treating as direct JSON
        return False


class SecureRequestClient:
    """Enhanced Secure Request Client with comprehensive parameter support."""
    
    def __init__(self, config: SecureRequestConfig):
        self.config = config
        self.kms_client: Optional[KMSClient] = None
        self.http_client: Optional[OfferHTTPClient] = None
        
    def log(self, message: str, level: str = "INFO"):
        """Log a message if verbose mode is enabled."""
        if self.config.enable_verbose:
            print(f"[{level}] {message}")
    
    def setup_kms_client(self) -> bool:
        """Setup KMS client with SSL configuration."""
        try:
            self.log(f"Setting up KMS client for: {self.config.kms_host}")
            
            # Add protocol if not specified
            kms_host = self.config.kms_host
            if not kms_host.startswith(('http://', 'https://')):
                kms_host = f"https://{kms_host}"
            
            self.kms_client = KMSClient(
                kms_host=kms_host,
                insecure=self.config.insecure,
                client_cert=self.config.client_cert,
                client_key=self.config.client_key,
                ca_cert=self.config.ca_cert,
                verbose=self.config.enable_verbose
            )
            
            self.log("✓ KMS client configured successfully")
            return True
            
        except Exception as e:
            print(f"✗ Failed to setup KMS client: {e}")
            return False
    
    def setup_http_client(self) -> bool:
        """Setup HTTP client with SSL configuration."""
        try:
            self.log(f"Setting up HTTP client for: {self.config.offer_host}")
            
            # Add protocol if not specified
            offer_host = self.config.offer_host
            if not offer_host.startswith(('http://', 'https://')):
                offer_host = f"http://{offer_host}"
            
            self.http_client = OfferHTTPClient(
                offer_host=offer_host,
                retry_attempts=self.config.retries,
                insecure=self.config.insecure,
                client_cert=self.config.client_cert,
                client_key=self.config.client_key,
                ca_cert=self.config.ca_cert,
                custom_headers=self.config.headers,
                verbose=self.config.enable_verbose
            )
            
            self.log("✓ HTTP client configured successfully")
            return True
            
        except Exception as e:
            print(f"✗ Failed to setup HTTP client: {e}")
            return False
    
    def load_request_data(self) -> Dict[str, Any]:
        """Load request data from file or payload string."""
        try:
            # Check if request_payload is a file path or direct JSON
            if self.config._is_file_path(self.config.request_payload):
                # Load from file
                self.log(f"Loading request data from file: {self.config.request_payload}")
                
                file_path = Path(self.config.request_payload)
                
                if file_path.suffix.lower() == '.jsonl':
                    # For JSONL files, we'll process the first line only
                    with open(file_path, 'r') as f:
                        first_line = f.readline().strip()
                        if not first_line:
                            print("✗ Error: JSONL file is empty")
                            return None
                        
                        try:
                            request_data = json.loads(first_line)
                            # Handle wrapped requests (e.g., {"id": 1, "request": {...}})
                            if isinstance(request_data, dict) and "request" in request_data:
                                request_data = request_data["request"]
                            
                            self.log("✓ Loaded request data from JSONL file (first line only)")
                            return request_data
                            
                        except json.JSONDecodeError as e:
                            print(f"✗ Error parsing JSONL line: {e}")
                            print(f"  Line content: {first_line[:100]}...")
                            return None
                
                else:
                    # Load JSON file
                    with open(file_path, 'r') as f:
                        request_data = json.load(f)
                    
                    # Handle wrapped requests (e.g., {"id": 1, "request": {...}})
                    if isinstance(request_data, dict) and "request" in request_data:
                        request_data = request_data["request"]
                    
                    self.log("✓ Loaded request data from JSON file")
                    return request_data
                
            else:
                # Load from direct JSON payload
                self.log("Loading request data from direct JSON payload")
                request_data = json.loads(self.config.request_payload)
                
                # Handle wrapped requests (e.g., {"id": 1, "request": {...}})
                if isinstance(request_data, dict) and "request" in request_data:
                    request_data = request_data["request"]
                
                self.log("✓ Loaded request data from direct JSON payload")
                return request_data
                
        except json.JSONDecodeError as e:
            print(f"✗ Error parsing JSON payload: {e}")
            return None
        except Exception as e:
            print(f"✗ Failed to load request data: {e}")
            return None
    
    def fetch_public_key(self) -> Optional[Dict[str, Any]]:
        """Fetch public key from KMS."""
        try:
            self.log("Fetching public key from KMS...")
            
            keys = self.kms_client.list_public_keys()
            if not keys:
                print("✗ No keys found from KMS")
                return None
            
            selected_key = keys[0]
            self.log(f"✓ Selected key ID: {selected_key['key_id']}")
            return selected_key
            
        except KMSClientError as e:
            print(f"✗ KMS error: {e}")
            return None
        except Exception as e:
            print(f"✗ Unexpected error fetching keys: {e}")
            return None
    
    def process_single_request(self, request_data: Dict[str, Any], public_key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single request."""
        try:
            self.log("Processing single request...")
            self.log(f"Request data: {json.dumps(request_data, indent=2)}")
            
            # Initialize crypto client
            crypto_client = OfferRequestClient(
                public_key=public_key['public_key'],
                key_id=public_key['key_id']
            )
            
            # Encrypt the request
            self.log("Encrypting request...")
            if self.config.enable_verbose:
                encryption_result = crypto_client.encrypt_offer_request(request_data)
            else:
                with suppress_stdout():
                    encryption_result = crypto_client.encrypt_offer_request(request_data)
            
            # Send to offer service
            self.log("Sending request to offer service...")
            server_response = self.http_client.send_offer_request(encryption_result.encrypted_data)
            
            # Decrypt response if available
            if 'responseCiphertext' in server_response:
                self.log("Decrypting response...")
                if self.config.enable_verbose:
                    decrypted_response = crypto_client.decrypt_offer_response(
                        server_response['responseCiphertext'],
                        encryption_result.secret
                    )
                else:
                    with suppress_stdout():
                        decrypted_response = crypto_client.decrypt_offer_response(
                            server_response['responseCiphertext'],
                            encryption_result.secret
                        )
                return decrypted_response
            else:
                self.log("No encrypted response to decrypt")
                return server_response
                
        except Exception as e:
            self.log(f"Error processing request: {e}", "ERROR")
            print(f"✗ Error processing request: {e}")
            return None
    
    def run(self) -> bool:
        """Run the Secure Request Client."""
        try:
            # Validate configuration
            if not self.config.validate():
                return False
            
            # Setup clients
            if not self.setup_kms_client():
                return False
            
            if not self.setup_http_client():
                return False
            
            # Load request data
            request_data = self.load_request_data()
            if request_data is None:
                return False
            
            # Fetch public key
            public_key = self.fetch_public_key()
            if not public_key:
                return False
            
            # Process single request
            result = self.process_single_request(request_data, public_key)
            
            if result:
                if self.config.enable_verbose:
                    print("\n" + "="*60)
                    print("REQUEST RESULT")
                    print("="*60)
                    print(json.dumps(result, indent=2))
                else:
                    # Clean output - just the result
                    print(json.dumps(result, indent=2))
                return True
            else:
                return False
            
        except Exception as e:
            if self.config.enable_verbose:
                print(f"✗ Unexpected error: {e}")
            return False


def parse_headers(headers_str: str) -> Dict[str, str]:
    """Parse headers string into dictionary."""
    try:
        if not headers_str:
            return {}
        
        # Remove outer quotes if present
        headers_str = headers_str.strip('\'"')
        
        # Parse as JSON
        headers = json.loads(headers_str)
        
        if not isinstance(headers, dict):
            raise ValueError("Headers must be a JSON object")
        
        return headers
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid headers JSON format: {e}")
    except Exception as e:
        raise ValueError(f"Error parsing headers: {e}")


def main():
    """Main entry point for the Secure Request Client."""
    parser = argparse.ArgumentParser(
        description='Secure Request Client for secure request operations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using request file with SSL certificates (required)
  secure-request --kms-host 127.0.0.1:8000 --offer-host 127.0.0.1:51052 --request-payload request.json --ca-cert ca.crt

  # Using direct JSON payload with client certificates
  secure-request --kms-host 127.0.0.1:8000 --offer-host 127.0.0.1:51052 --request-payload '{"client_type":"CLIENT_TYPE_BROWSER",...}' --client-cert client.crt --client-key client.key

  # Insecure mode (no SSL certificates required)
  secure-request --kms-host 127.0.0.1:8000 --offer-host 127.0.0.1:51052 --request-payload request.json --insecure

  # With custom headers and retries
  secure-request --kms-host 127.0.0.1:8000 --offer-host 127.0.0.1:51052 --request-payload request.json --ca-cert ca.crt --headers '{"Authorization":"Bearer token"}' --retries 3 --enable-verbose
        """
    )
    
    # Core parameters
    parser.add_argument('--kms-host', 
                       required=True,
                       help='Host and port of the KMS service (e.g., 127.0.0.1:8000)')
    
    parser.add_argument('--offer-host', 
                       required=True,
                       help='Host and port of the Offer service (e.g., 127.0.0.1:51052)')
    
    # Request payload parameter (can be file path or direct JSON)
    parser.add_argument('--request-payload', 
                       required=True,
                       help='Offer request payload as JSON string or file path (JSON/JSONL format)')
    
    # Retry and connection parameters
    parser.add_argument('--retries', 
                       type=int, 
                       default=1,
                       help='Number of retries before failing the transaction (default: 1)')
    
    parser.add_argument('--insecure', 
                       action='store_true',
                       help='Disable certificate verification (default: false). When not specified, SSL certificates are required.')
    
    parser.add_argument('--headers', 
                       type=str,
                       help='Additional HTTP headers in JSON format (e.g., \'{"Authorization":"Bearer token"}\')')
    
    # SSL certificate parameters
    parser.add_argument('--client-key', 
                       help='Client key file (required unless --insecure is used)')
    
    parser.add_argument('--client-cert', 
                       help='Client certificate file (required unless --insecure is used)')
    
    parser.add_argument('--ca-cert', 
                       help='CA certificate file (required unless --insecure is used)')
    
    # Debug parameters
    parser.add_argument('--enable-verbose', 
                       action='store_true',
                       help='Enable verbose output for debugging (default: false)')
    
    args = parser.parse_args()
    
    # Create configuration
    config = SecureRequestConfig()
    config.kms_host = args.kms_host
    config.offer_host = args.offer_host
    config.request_payload = args.request_payload
    config.retries = args.retries
    config.insecure = args.insecure
    config.client_key = args.client_key
    config.client_cert = args.client_cert
    config.ca_cert = args.ca_cert
    config.enable_verbose = args.enable_verbose
    
    # Parse headers
    if args.headers:
        try:
            config.headers = parse_headers(args.headers)
        except ValueError as e:
            print(f"✗ Error parsing headers: {e}")
            sys.exit(1)
    
    # Set up the library path
    os.environ['LD_LIBRARY_PATH'] = './secure_request_client/lib:' + os.environ.get('LD_LIBRARY_PATH', '')
    
    # Run the tool
    tool = SecureRequestClient(config)
    
    success = tool.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()