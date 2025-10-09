"""
Secure Invoke - Python SDK for encrypting and sending requests to BFE services.

This package provides both CLI and programmatic interfaces for:
- Fetching keys from KMS
- Encrypting requests using HPKE (X25519, AES-256-GCM, HKDF-SHA256)
- Sending requests to BFE services
- Decrypting responses
- Batch processing with retries and concurrency
"""

__version__ = '1.0.0'

from .api import SecureInvoke, create_client
from .utils.kms_client import KMSClient, HpkeKeyset
from .utils.crypto import CryptoClient, create_crypto_client
from .utils.payload import PayloadPackager
from .utils.http_client import BFEClient
from .utils.batch import BatchProcessor, BatchLogger, BatchResult

__all__ = [
    # Main API
    'SecureInvoke',
    'create_client',
    
    # KMS and keys
    'KMSClient',
    'HpkeKeyset',
    
    # Crypto
    'CryptoClient',
    'create_crypto_client',
    
    # Payload
    'PayloadPackager',
    
    # HTTP client
    'BFEClient',
    
    # Batch processing
    'BatchProcessor',
    'BatchLogger',
    'BatchResult',
]

