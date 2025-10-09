#!/usr/bin/env python3
"""Test pyhpke basic encryption to understand the API."""

import pyhpke
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Create a cipher suite
suite = CipherSuite.new(
    kem_id=KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id=KDFId.HKDF_SHA256,
    aead_id=AEADId.AES256_GCM
)

# Generate a test keypair using cryptography
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize to raw bytes
pub_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
priv_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

print(f"Public key: {pub_bytes.hex()}")
print(f"Private key: {priv_bytes.hex()}")
print(f"Public key length: {len(pub_bytes)}")
print(f"Private key length: {len(priv_bytes)}")

# Convert to KEMKey objects
from pyhpke import KEMKey
pub_key_obj = KEMKey.from_pyca_cryptography_key(public_key)
priv_key_obj = KEMKey.from_pyca_cryptography_key(private_key)

print(f"\nPublic key object: {pub_key_obj}")
print(f"Private key object: {priv_key_obj}")

# Test encryption
plaintext = b"Hello, World!"
enc, sender_ctx = suite.create_sender_context(pub_key_obj)
ciphertext = sender_ctx.seal(plaintext)

print(f"\nEncapsulated key: {enc.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")

# Test decryption
recipient_ctx = suite.create_recipient_context(enc, priv_key_obj)
decrypted = recipient_ctx.open(ciphertext)

print(f"Decrypted: {decrypted}")
print(f"Match: {decrypted == plaintext}")

