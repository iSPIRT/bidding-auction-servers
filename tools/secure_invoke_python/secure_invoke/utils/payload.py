"""Payload packaging and transformation utilities."""

import json
import logging
from typing import Dict, Any

from google.protobuf import json_format

from .kms_client import HpkeKeyset
from .crypto import CryptoClient


logger = logging.getLogger(__name__)


class PayloadPackager:
    """Handles payload transformation: JSON -> Protobuf -> Encryption."""
    
    def __init__(self, keyset: HpkeKeyset):
        """
        Initialize payload packager.
        
        Args:
            keyset: HpkeKeyset for encryption
        """
        self.keyset = keyset
        self.crypto_client = CryptoClient(keyset)
    
    def package_get_bids_request(
        self,
        request_json: Dict[str, Any],
        enable_debug_reporting: bool = False,
        enable_unlimited_egress: bool = False
    ) -> Dict[str, Any]:
        """
        Package a GetBidsRawRequest into an encrypted request.
        
        Transformation flow:
        1. JSON -> Protobuf serialization
        2. Protobuf -> bytes
        3. bytes -> HPKE encryption
        4. encrypted bytes -> base64
        5. Package as {"requestCiphertext": "...", "keyId": "..."}
        
        Args:
            request_json: Raw request as JSON dict
            enable_debug_reporting: Enable debug reporting
            enable_unlimited_egress: Enable unlimited egress
            
        Returns:
            Dict with requestCiphertext and keyId
        """
        # Import proto here to avoid circular imports
        from ..protos import bidding_auction_servers_pb2
        
        logger.info("\n📦 Packaging GetBidsRequest")
        logger.info(f"  🔧 Debug reporting: {enable_debug_reporting}")
        logger.info(f"  🔧 Unlimited egress: {enable_unlimited_egress}")
        
        # Create GetBidsRawRequest proto from JSON
        raw_request = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        
        # Set debug flags if provided
        if enable_debug_reporting:
            raw_request.enable_debug_reporting = enable_debug_reporting
        if enable_unlimited_egress:
            raw_request.enable_unlimited_egress = enable_unlimited_egress
        
        # Parse JSON into proto
        # Handle nested structures properly
        logger.info(f"  📝 Input JSON:")
        logger.info(f"     {json.dumps(request_json, indent=2)[:500]}...")
        
        try:
            logger.info(f"  🔄 Converting JSON to Protobuf...")
            json_format.ParseDict(request_json, raw_request)
            logger.info(f"  ✓ JSON parsed successfully")
        except Exception as e:
            logger.error(f"Failed to parse JSON to proto: {e}")
            raise ValueError(f"Invalid request JSON: {e}") from e
        
        # Serialize proto to bytes
        logger.info(f"  🔄 Serializing Protobuf to bytes...")
        plaintext = raw_request.SerializeToString()
        logger.info(f"  ✓ Serialized to {len(plaintext)} bytes")
        logger.debug(f"     Bytes (first 50): {plaintext[:50].hex()}")
        
        # Encrypt using HPKE
        logger.info(f"  🔄 Encrypting with HPKE...")
        encrypted_b64 = self.crypto_client.encrypt_to_base64(plaintext)
        logger.info(f"  ✓ Encrypted and base64 encoded: {len(encrypted_b64)} chars")
        logger.debug(f"     Base64 (first 100): {encrypted_b64[:100]}...")
        
        # Package the encrypted request
        packaged_request = {
            "requestCiphertext": encrypted_b64,
            "keyId": str(self.keyset.key_id)  # Convert decimal to string
        }
        
        logger.info(f"  ✅ Request packaged successfully!")
        logger.info(f"     Key ID: {self.keyset.key_id}")
        logger.info(f"     Ciphertext length: {len(encrypted_b64)} chars")
        
        return packaged_request
    
    def unpackage_get_bids_response(
        self,
        response_json: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Unpackage an encrypted GetBidsResponse.
        
        Transformation flow:
        1. Extract responseCiphertext (base64)
        2. base64 -> bytes
        3. HPKE decryption -> bytes
        4. bytes -> Protobuf deserialization
        5. Protobuf -> JSON
        
        Args:
            response_json: Encrypted response with responseCiphertext and keyId
            
        Returns:
            Decrypted response as JSON dict
        """
        # Import proto here to avoid circular imports
        from ..protos import bidding_auction_servers_pb2
        
        logger.info("\n📥 Unpackaging GetBidsResponse")
        
        # Extract encrypted response
        if 'responseCiphertext' not in response_json:
            raise ValueError("Response missing 'responseCiphertext' field")
        
        ciphertext_b64 = response_json['responseCiphertext']
        logger.info(f"  📝 Response ciphertext: {len(ciphertext_b64)} chars (base64)")
        logger.debug(f"     Base64 (first 100): {ciphertext_b64[:100]}...")
        
        if 'keyId' in response_json:
            logger.info(f"  🔑 Response Key ID: {response_json['keyId']}")
        
        # Decrypt using HPKE
        try:
            logger.info(f"  🔄 Decrypting response...")
            plaintext = self.crypto_client.decrypt_from_base64(ciphertext_b64)
            logger.info(f"  ✓ Decrypted to {len(plaintext)} bytes")
            logger.debug(f"     Bytes (first 50): {plaintext[:50].hex()}")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise RuntimeError(f"Failed to decrypt response: {e}") from e
        
        # Deserialize proto
        logger.info(f"  🔄 Deserializing Protobuf...")
        raw_response = bidding_auction_servers_pb2.GetBidsResponse.GetBidsRawResponse()
        try:
            raw_response.ParseFromString(plaintext)
            logger.info(f"  ✓ Protobuf deserialized successfully")
        except Exception as e:
            logger.error(f"Failed to parse proto: {e}")
            raise ValueError(f"Invalid response proto: {e}") from e
        
        # Convert proto to JSON
        logger.info(f"  🔄 Converting Protobuf to JSON...")
        response_dict = json_format.MessageToDict(
            raw_response,
            preserving_proto_field_name=True,
            including_default_value_fields=True
        )
        
        logger.info(f"  ✅ Response unpackaged successfully!")
        logger.info(f"     Response JSON:")
        logger.info(f"     {json.dumps(response_dict, indent=2)[:500]}...")
        
        return response_dict
    
    @staticmethod
    def load_json_request(file_path: str) -> Dict[str, Any]:
        """
        Load request from JSON file.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Request as dict
        """
        logger.info(f"Loading request from {file_path}")
        try:
            with open(file_path, 'r') as f:
                request = json.load(f)
            return request
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            raise ValueError(f"Invalid JSON file: {e}") from e
    
    @staticmethod
    def load_jsonl_batch(file_path: str):
        """
        Load batch requests from JSONL file.
        
        Each line should be a JSON object with 'id' and 'request' fields.
        
        Args:
            file_path: Path to JSONL file
            
        Yields:
            Tuples of (id, request_dict)
        """
        logger.info(f"Loading batch requests from {file_path}")
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        entry = json.loads(line)
                        if 'id' not in entry or 'request' not in entry:
                            logger.warning(
                                f"Line {line_num}: missing 'id' or 'request', skipping"
                            )
                            continue
                        
                        yield entry['id'], entry['request']
                    
                    except json.JSONDecodeError as e:
                        logger.warning(f"Line {line_num}: invalid JSON, skipping: {e}")
                        continue
        
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise

