#!/usr/bin/env python3
"""
Python crypto API for secure request client.

This module provides clean Python APIs for encrypting and decrypting offer requests
and responses, designed for programmatic use in other Python code.
"""

import ctypes
import os
import sys
import json
from ctypes import Structure, c_char_p, c_int, POINTER
from typing import Dict, Optional, Any, Union, Tuple, NamedTuple
import base64


class SecureRequestResult(Structure):
    """C-compatible result structure"""
    _fields_ = [
        ("success", c_int),
        ("response", c_char_p),
        ("error_message", c_char_p),
    ]


class OfferEncryptionResult(NamedTuple):
    """Result from offer request encryption operation"""
    encrypted_data: str
    secret: str
    

class SecureRequestError(Exception):
    """Custom exception for secure request client errors"""
    pass


class SecureRequestCrypto:
    """
    Python crypto interface for secure request operations.
    
    This class provides clean encrypt and decrypt APIs for offer requests and responses.
    """
    
    def __init__(self, library_path: Optional[str] = None):
        """
        Initialize the SecureRequestCrypto.
        
        Args:
            library_path: Path to the shared library. If None, attempts to find it automatically.
        """
        self._lib = None
        self._load_library(library_path)
        self._setup_function_signatures()
        
        # Initialize the library
        if not self._lib.secure_invoke_init():
            raise SecureRequestError("Failed to initialize secure_invoke library")
    
    def __del__(self):
        """Cleanup when the object is destroyed"""
        if self._lib:
            self._lib.secure_invoke_cleanup()
    
    def _load_library(self, library_path: Optional[str]):
        """Load the shared library"""
        if library_path is None:
            # Get the package directory
            package_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Try to find the library in common locations
            possible_paths = [
                os.path.join(package_dir, "lib", "libsecure_invoke.so"),  # Package lib directory
                "./libsecure_invoke.so",
                "../bazel-bin/tools/secure_invoke/libsecure_invoke.so",
                "/usr/local/lib/libsecure_invoke.so",
                "/usr/lib/libsecure_invoke.so",
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    library_path = path
                    break
            
            if library_path is None:
                raise SecureRequestError(
                    "Could not find secure_invoke shared library. "
                    "Please provide the library_path parameter."
                )
        
        try:
            self._lib = ctypes.CDLL(library_path)
        except OSError as e:
            raise SecureRequestError(f"Failed to load library {library_path}: {e}")
    
    def _setup_function_signatures(self):
        """Setup function signatures for proper ctypes interfacing"""
        # secure_invoke_init
        self._lib.secure_invoke_init.argtypes = []
        self._lib.secure_invoke_init.restype = c_int
        
        # secure_invoke_cleanup
        self._lib.secure_invoke_cleanup.argtypes = []
        self._lib.secure_invoke_cleanup.restype = None
        
        # secure_invoke_encrypt
        self._lib.secure_invoke_encrypt.argtypes = [c_char_p, c_char_p, c_char_p]
        self._lib.secure_invoke_encrypt.restype = POINTER(SecureRequestResult)
        
        # secure_invoke_decrypt
        self._lib.secure_invoke_decrypt.argtypes = [c_char_p, c_char_p]
        self._lib.secure_invoke_decrypt.restype = POINTER(SecureRequestResult)
        
        # secure_invoke_free_result
        self._lib.secure_invoke_free_result.argtypes = [POINTER(SecureRequestResult)]
        self._lib.secure_invoke_free_result.restype = None
        
        # secure_invoke_get_version
        self._lib.secure_invoke_get_version.argtypes = []
        self._lib.secure_invoke_get_version.restype = c_char_p
    
    def get_version(self) -> str:
        """Get the library version"""
        version = self._lib.secure_invoke_get_version()
        return version.decode('utf-8') if version else "unknown"
    
    def encrypt_offer_request(self, 
                input_json: Union[Dict, str],
                public_key: str,
                key_id: str) -> OfferEncryptionResult:
        """
        Encrypt an offer request.
        
        Args:
            input_json: Either a dictionary representing GetBidsRawRequest or JSON string
            public_key: Base64 encoded public key
            key_id: Key ID as string (can be hex or decimal)
            
        Returns:
            OfferEncryptionResult containing encrypted_data and secret
            
        Raises:
            SecureRequestError: If the encryption operation fails
        """
        # Convert input to JSON string if it's a dictionary
        if isinstance(input_json, dict):
            json_str = json.dumps(input_json)
        elif isinstance(input_json, str):
            # Validate that it's valid JSON
            try:
                json.loads(input_json)
                json_str = input_json
            except json.JSONDecodeError as e:
                raise SecureRequestError(f"Invalid JSON string: {e}")
        else:
            raise SecureRequestError(f"input_json must be dict or JSON string, got {type(input_json)}")
        
        # Convert hex key ID to decimal if needed
        try:
            decimal_key_id = str(int(key_id, 16))
        except ValueError:
            decimal_key_id = key_id
        
        # Call the C++ encrypt function with decimal key ID
        result_ptr = self._lib.secure_invoke_encrypt(
            json_str.encode('utf-8'),
            public_key.encode('utf-8'),
            decimal_key_id.encode('utf-8')
        )
        
        if not result_ptr:
            raise SecureRequestError("secure_invoke_encrypt returned null")
        
        try:
            result = result_ptr.contents
            
            if not result.success:
                error_msg = result.error_message.decode('utf-8') if result.error_message else "Unknown error"
                raise SecureRequestError(f"Encryption failed: {error_msg}")
            
            if not result.response:
                raise SecureRequestError("Encryption succeeded but no response data")
            
            # Parse the response to extract encrypted data and secret
            response_str = result.response.decode('utf-8')
            
            # Look for the secret delimiter
            delimiter = "|||SECRET|||"
            delimiter_pos = response_str.find(delimiter)
            if delimiter_pos == -1:
                raise SecureRequestError("Secret delimiter not found in encryption response")
            
            encrypted_data = response_str[:delimiter_pos]
            secret = response_str[delimiter_pos + len(delimiter):]
            
            return OfferEncryptionResult(encrypted_data=encrypted_data, secret=secret)
        
        finally:
            # Free the result
            self._lib.secure_invoke_free_result(result_ptr)
    
    def decrypt_offer_response(self, 
                encrypted_response: str,
                secret: str) -> Dict[str, Any]:
        """
        Decrypt an offer response from the server.
        
        Args:
            encrypted_response: Base64 encoded encrypted response from server
            secret: Secret string from the encryption step
            
        Returns:
            Decrypted response as a dictionary
            
        Raises:
            SecureRequestError: If the decryption operation fails
        """
        # Call the C++ decrypt function
        result_ptr = self._lib.secure_invoke_decrypt(
            encrypted_response.encode('utf-8'),
            secret.encode('utf-8')
        )
        
        if not result_ptr:
            raise SecureRequestError("secure_invoke_decrypt returned null")
        
        try:
            result = result_ptr.contents
            
            if not result.success:
                error_msg = result.error_message.decode('utf-8') if result.error_message else "Unknown error"
                raise SecureRequestError(f"Decryption failed: {error_msg}")
            
            if not result.response:
                raise SecureRequestError("Decryption succeeded but no response data")
            
            # Parse the JSON response
            response_str = result.response.decode('utf-8')
            try:
                return json.loads(response_str)
            except json.JSONDecodeError as e:
                raise SecureRequestError(f"Failed to parse decrypted response as JSON: {e}")
        
        finally:
            # Free the result
            self._lib.secure_invoke_free_result(result_ptr)


class OfferRequestClient:
    """
    High-level client for offer request operations.
    
    This class provides convenient methods for common offer request operations.
    """
    
    def __init__(self, 
                 public_key: str, 
                 key_id: str,
                 library_path: Optional[str] = None):
        """
        Initialize the offer request client.
        
        Args:
            public_key: Base64 encoded public key for encryption
            key_id: Key ID for the public key
            library_path: Path to the shared library (optional)
        """
        self.crypto = SecureRequestCrypto(library_path)
        self.public_key = public_key
        self.key_id = key_id
    
    def encrypt_offer_request(self, offer_request: Dict[str, Any]) -> OfferEncryptionResult:
        """
        Encrypt an offer request.
        
        Args:
            offer_request: Dictionary representing the GetBidsRawRequest
            
        Returns:
            OfferEncryptionResult with encrypted data and secret
        """
        return self.crypto.encrypt_offer_request(offer_request, self.public_key, self.key_id)
    
    def decrypt_offer_response(self, encrypted_response: str, secret: str) -> Dict[str, Any]:
        """
        Decrypt an offer response from the server.
        
        Args:
            encrypted_response: Encrypted response from the server
            secret: Secret from the encryption operation
            
        Returns:
            Decrypted response as a dictionary
        """
        return self.crypto.decrypt_offer_response(encrypted_response, secret)

