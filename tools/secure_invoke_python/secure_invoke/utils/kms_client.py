"""KMS client for fetching encryption keys."""

import base64
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

import requests


logger = logging.getLogger(__name__)


@dataclass
class HpkeKeyset:
    """HPKE keyset containing public key, private key, and key ID."""
    public_key: str  # hex encoded
    private_key: str  # hex encoded
    key_id: int  # decimal uint8


class KMSClient:
    """Client for fetching keys from KMS."""
    
    def __init__(self, kms_url: str, insecure: bool = False, timeout: int = 30):
        """
        Initialize KMS client.
        
        Args:
            kms_url: Base URL of the KMS service
            insecure: Whether to disable SSL verification
            timeout: Request timeout in seconds
        """
        self.kms_url = kms_url.rstrip('/')
        self.insecure = insecure
        self.timeout = timeout
        self.session = requests.Session()
        
        if insecure:
            logger.warning("SSL verification disabled - this is insecure!")
            self.session.verify = False
            # Suppress SSL warnings when insecure mode is enabled
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def fetch_keys(self, endpoint: str = '/listpubkeys') -> List[HpkeKeyset]:
        """
        Fetch keys from KMS.
        
        The KMS returns keys in the following format:
        {
          "keys": [
            {
              "key": "base64_encoded_key",
              "id": "hex_string_key_id"
            }
          ]
        }
        
        The function transforms:
        1. key: base64 -> bytes -> hex
        2. id: hex string -> decimal uint8
        
        Args:
            endpoint: KMS endpoint path
            
        Returns:
            List of HpkeKeyset objects
        """
        url = f"{self.kms_url}{endpoint}"
        logger.info(f"🔑 Fetching keys from KMS: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            logger.debug(f"📥 KMS Response: {data}")
            
            if 'keys' not in data:
                raise ValueError("Invalid KMS response: missing 'keys' field")
            
            logger.info(f"✓ Received {len(data['keys'])} key(s) from KMS")
            
            keysets = []
            for idx, key_data in enumerate(data['keys'], 1):
                logger.info(f"\n📍 Processing Key #{idx}:")
                keyset = self._parse_key_data(key_data)
                keysets.append(keyset)
                logger.info(f"✓ Key #{idx} processed successfully")
            
            return keysets
        
        except requests.RequestException as e:
            logger.error(f"Failed to fetch keys from KMS: {e}")
            raise RuntimeError(f"KMS request failed: {e}") from e
        except (ValueError, KeyError) as e:
            logger.error(f"Failed to parse KMS response: {e}")
            raise ValueError(f"Invalid KMS response: {e}") from e
    
    def _parse_key_data(self, key_data: Dict) -> HpkeKeyset:
        """
        Parse key data from KMS response.
        
        Transforms:
        - key (base64) -> bytes -> hex
        - id (hex string) -> decimal uint8
        
        Args:
            key_data: Dictionary containing 'key' and 'id' fields
            
        Returns:
            HpkeKeyset object
        """
        if 'key' not in key_data or 'id' not in key_data:
            raise ValueError("Key data missing required fields")
        
        # Decode base64 public key to bytes, then convert to hex
        public_key_base64 = key_data['key']
        logger.info(f"  📝 Public Key (base64): {public_key_base64[:20]}...{public_key_base64[-20:]}")
        
        public_key_bytes = base64.b64decode(public_key_base64)
        logger.info(f"  🔄 Decoded to bytes: {len(public_key_bytes)} bytes")
        
        public_key_hex = public_key_bytes.hex()
        logger.info(f"  🔄 Converted to hex: {public_key_hex[:20]}...{public_key_hex[-20:]}")
        
        # Convert hex key ID to decimal uint8
        key_id_hex = key_data['id']
        logger.info(f"  📝 Key ID (hex): {key_id_hex}")
        
        key_id_decimal = int(key_id_hex, 16)
        logger.info(f"  🔄 Key ID (decimal): {key_id_decimal}")
        
        # Ensure key_id fits in uint8 (0-255)
        if not 0 <= key_id_decimal <= 255:
            raise ValueError(f"Key ID {key_id_decimal} out of uint8 range")
        
        # For public key only scenarios, private key can be empty
        # In full implementation, private key would also come from KMS
        private_key_hex = ""
        if 'private_key' in key_data:
            private_key_base64 = key_data['private_key']
            logger.info(f"  📝 Private Key (base64): {private_key_base64[:20]}...{private_key_base64[-20:]}")
            private_key_bytes = base64.b64decode(private_key_base64)
            private_key_hex = private_key_bytes.hex()
            logger.info(f"  🔄 Private Key (hex): {private_key_hex[:20]}...{private_key_hex[-20:]}")
        
        return HpkeKeyset(
            public_key=public_key_hex,
            private_key=private_key_hex,
            key_id=key_id_decimal
        )
    
    @staticmethod
    def create_keyset_from_base64(
        public_key_b64: str,
        key_id_hex: str,
        private_key_b64: Optional[str] = None
    ) -> HpkeKeyset:
        """
        Create HpkeKeyset from base64-encoded keys.
        
        Args:
            public_key_b64: Base64-encoded public key
            key_id_hex: Hex string key ID
            private_key_b64: Optional base64-encoded private key
            
        Returns:
            HpkeKeyset object
        """
        # Decode public key
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key_hex = public_key_bytes.hex()
        
        # Decode private key if provided
        private_key_hex = ""
        if private_key_b64:
            private_key_bytes = base64.b64decode(private_key_b64)
            private_key_hex = private_key_bytes.hex()
        
        # Convert key ID
        key_id_decimal = int(key_id_hex, 16)
        if not 0 <= key_id_decimal <= 255:
            raise ValueError(f"Key ID {key_id_decimal} out of uint8 range")
        
        return HpkeKeyset(
            public_key=public_key_hex,
            private_key=private_key_hex,
            key_id=key_id_decimal
        )

