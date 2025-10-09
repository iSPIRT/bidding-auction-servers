"""HPKE encryption and decryption utilities."""

import base64
import logging
from typing import Tuple

import pyhpke
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .kms_client import HpkeKeyset


logger = logging.getLogger(__name__)


class CryptoClient:
    """Client for HPKE encryption and decryption operations."""
    
    # HPKE cipher suite configuration matching C++ implementation
    # - Key Encapsulation: X25519 (DHKEM)
    # - KDF: HKDF-SHA256
    # - AEAD: AES-256-GCM
    CIPHER_SUITE = CipherSuite.new(
        kem_id=KEMId.DHKEM_X25519_HKDF_SHA256,
        kdf_id=KDFId.HKDF_SHA256,
        aead_id=AEADId.AES256_GCM
    )
    
    def __init__(self, keyset: HpkeKeyset):
        """
        Initialize crypto client with keyset.
        
        Args:
            keyset: HpkeKeyset containing public/private keys and key ID
        """
        self.keyset = keyset
        
        # Convert hex keys to bytes
        public_key_bytes = bytes.fromhex(keyset.public_key)
        
        # Load public key using cryptography
        public_key_crypto = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Convert to pyhpke KEMKey
        self._public_key = KEMKey.from_pyca_cryptography_key(public_key_crypto)
        
        # Load private key if available
        if keyset.private_key:
            private_key_bytes = bytes.fromhex(keyset.private_key)
            private_key_crypto = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
            self._private_key = KEMKey.from_pyca_cryptography_key(private_key_crypto)
        else:
            self._private_key = None
    
    def encrypt(self, plaintext: bytes, info: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using HPKE.
        
        Args:
            plaintext: Data to encrypt
            info: Optional application-specific info string
            
        Returns:
            Tuple of (ciphertext, encapsulated_key)
            The encapsulated_key should be prepended to ciphertext for transmission
        """
        logger.info(f"\n🔐 Starting HPKE Encryption")
        logger.info(f"  📊 Input plaintext: {len(plaintext)} bytes")
        logger.debug(f"  📝 Plaintext (first 100 bytes): {plaintext[:100]}")
        logger.info(f"  🔑 Using Key ID: {self.keyset.key_id}")
        logger.info(f"  ⚙️  Algorithm: X25519 + AES-256-GCM + HKDF-SHA256")
        
        try:
            # Create HPKE sender (encryption context)
            # pyhpke expects KEMKey objects
            # Don't pass psk/psk_id if not using PSK mode
            logger.info(f"  🔨 Creating HPKE sender context...")
            enc, sender_context = self.CIPHER_SUITE.create_sender_context(
                self._public_key,
                info=info
            )
            logger.info(f"  ✓ Sender context created")
            logger.info(f"  📦 Encapsulated key: {len(enc)} bytes")
            logger.debug(f"     Hex: {enc.hex()}")
            
            # Encrypt the plaintext
            # AAD (Additional Authenticated Data) is empty in our case
            logger.info(f"  🔒 Sealing plaintext with AES-256-GCM...")
            ciphertext = sender_context.seal(plaintext, aad=b"")
            logger.info(f"  ✓ Plaintext sealed")
            logger.info(f"  📦 Ciphertext: {len(ciphertext)} bytes")
            
            # The full encrypted message is: encapsulated_key || ciphertext
            # This matches the C++ HPKE implementation
            encrypted_data = enc + ciphertext
            
            logger.info(
                f"  ✅ Encryption successful!\n"
                f"     Encapsulated key: {len(enc)} bytes\n"
                f"     Ciphertext: {len(ciphertext)} bytes\n"
                f"     Total encrypted: {len(encrypted_data)} bytes"
            )
            
            return encrypted_data, enc
        
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise RuntimeError(f"HPKE encryption failed: {e}") from e
    
    def decrypt(self, encrypted_data: bytes, info: bytes = b"") -> bytes:
        """
        Decrypt ciphertext using HPKE.
        
        Args:
            encrypted_data: Encrypted data (encapsulated_key || ciphertext)
            info: Optional application-specific info string (must match encryption)
            
        Returns:
            Decrypted plaintext
        """
        if not self._private_key:
            raise ValueError("Private key required for decryption")
        
        logger.info(f"\n🔓 Starting HPKE Decryption")
        logger.info(f"  📊 Encrypted data: {len(encrypted_data)} bytes")
        logger.info(f"  🔑 Using Key ID: {self.keyset.key_id}")
        logger.info(f"  ⚙️  Algorithm: X25519 + AES-256-GCM + HKDF-SHA256")
        
        try:
            # Extract encapsulated key (first 32 bytes for X25519)
            enc_len = 32  # X25519 public key length
            if len(encrypted_data) < enc_len:
                raise ValueError(
                    f"Encrypted data too short: {len(encrypted_data)} < {enc_len}"
                )
            
            enc = encrypted_data[:enc_len]
            ciphertext = encrypted_data[enc_len:]
            
            logger.info(f"  📦 Encapsulated key: {len(enc)} bytes")
            logger.debug(f"     Hex: {enc.hex()}")
            logger.info(f"  📦 Ciphertext: {len(ciphertext)} bytes")
            
            # Create HPKE receiver (decryption context)
            # pyhpke expects KEMKey objects
            # Don't pass psk/psk_id if not using PSK mode
            logger.info(f"  🔨 Creating HPKE receiver context...")
            receiver_context = self.CIPHER_SUITE.create_recipient_context(
                enc=enc,
                skr=self._private_key,
                info=info
            )
            logger.info(f"  ✓ Receiver context created")
            
            # Decrypt the ciphertext
            logger.info(f"  🔓 Opening ciphertext with AES-256-GCM...")
            plaintext = receiver_context.open(ciphertext, aad=b"")
            
            logger.info(
                f"  ✅ Decryption successful!\n"
                f"     Plaintext: {len(plaintext)} bytes"
            )
            logger.debug(f"  📝 Plaintext (first 100 bytes): {plaintext[:100]}")
            
            return plaintext
        
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise RuntimeError(f"HPKE decryption failed: {e}") from e
    
    def encrypt_to_base64(self, plaintext: bytes, info: bytes = b"") -> str:
        """
        Encrypt plaintext and return base64-encoded ciphertext.
        
        Args:
            plaintext: Data to encrypt
            info: Optional application-specific info string
            
        Returns:
            Base64-encoded encrypted data
        """
        encrypted_data, _ = self.encrypt(plaintext, info)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_from_base64(self, ciphertext_b64: str, info: bytes = b"") -> bytes:
        """
        Decrypt base64-encoded ciphertext.
        
        Args:
            ciphertext_b64: Base64-encoded encrypted data
            info: Optional application-specific info string
            
        Returns:
            Decrypted plaintext
        """
        encrypted_data = base64.b64decode(ciphertext_b64)
        return self.decrypt(encrypted_data, info)


def create_crypto_client(keyset: HpkeKeyset) -> CryptoClient:
    """
    Factory function to create a CryptoClient.
    
    Args:
        keyset: HpkeKeyset containing encryption keys
        
    Returns:
        CryptoClient instance
    """
    return CryptoClient(keyset)

