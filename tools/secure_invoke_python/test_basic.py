#!/usr/bin/env python3
"""Basic test to verify package functionality."""

import sys
import json

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    try:
        from secure_invoke import SecureInvoke, create_client
        from secure_invoke.utils import KMSClient, HpkeKeyset, CryptoClient
        from secure_invoke.utils import PayloadPackager, BFEClient
        from secure_invoke.utils import BatchProcessor, BatchLogger
        print("✓ All imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_keyset_creation():
    """Test keyset creation from base64."""
    print("\nTesting keyset creation...")
    try:
        from secure_invoke.utils import KMSClient
        
        keyset = KMSClient.create_keyset_from_base64(
            public_key_b64='dZRQTjI+R0INCRjmULIWkMJiqFuHet7NMbtif5tlchY=',
            key_id_hex='15'
        )
        
        assert keyset.key_id == 21, f"Expected key_id=21, got {keyset.key_id}"
        assert len(keyset.public_key) == 64, f"Expected 64 hex chars, got {len(keyset.public_key)}"
        
        print(f"✓ Keyset created: key_id={keyset.key_id}")
        return True
    except Exception as e:
        print(f"✗ Keyset creation failed: {e}")
        return False

def test_encryption():
    """Test encryption/decryption."""
    print("\nTesting encryption...")
    try:
        from secure_invoke.utils import KMSClient, CryptoClient
        
        # Create test keyset (using test keys)
        # Note: Key ID 40 (hex) = 64 (decimal)
        keyset = KMSClient.create_keyset_from_base64(
            public_key_b64='87ey8XZPXAd+/+ytKv2GFUWW5j9zdepSJ2G4gebDwyM=',
            key_id_hex='40',
            private_key_b64='57KS9J3yi4BlmSzerbydAyoOCehHbLbY1QchLnvjubQ='
        )
        
        # Create crypto client
        crypto_client = CryptoClient(keyset)
        
        # Test encryption/decryption
        plaintext = b"Hello, World!"
        encrypted, _ = crypto_client.encrypt(plaintext)
        decrypted = crypto_client.decrypt(encrypted)
        
        assert decrypted == plaintext, f"Decryption mismatch: {decrypted} != {plaintext}"
        
        print(f"✓ Encryption/decryption successful")
        return True
    except Exception as e:
        print(f"✗ Encryption test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_payload_packaging():
    """Test payload packaging."""
    print("\nTesting payload packaging...")
    try:
        from secure_invoke.utils import KMSClient, PayloadPackager
        
        # Create test keyset
        # Note: Key ID 40 (hex) = 64 (decimal)
        keyset = KMSClient.create_keyset_from_base64(
            public_key_b64='87ey8XZPXAd+/+ytKv2GFUWW5j9zdepSJ2G4gebDwyM=',
            key_id_hex='40'
        )
        
        # Create packager
        packager = PayloadPackager(keyset)
        
        # Test request
        request = {
            "client_type": "CLIENT_TYPE_BROWSER",
            "buyerInput": {
                "interestGroups": [{
                    "name": "Test",
                    "biddingSignalsKeys": ["key1"]
                }]
            },
            "seller": "test.com",
            "publisherName": "test.com"
        }
        
        # Package request
        packaged = packager.package_get_bids_request(request)
        
        assert 'requestCiphertext' in packaged, "Missing requestCiphertext"
        assert 'keyId' in packaged, "Missing keyId"
        assert packaged['keyId'] == '64', f"Expected keyId=64, got {packaged['keyId']}"
        
        print(f"✓ Payload packaging successful")
        print(f"  - Ciphertext length: {len(packaged['requestCiphertext'])} chars")
        print(f"  - Key ID: {packaged['keyId']}")
        return True
    except Exception as e:
        print(f"✗ Payload packaging failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_proto_compilation():
    """Test that proto files were compiled correctly."""
    print("\nTesting proto compilation...")
    try:
        from secure_invoke.protos import bidding_auction_servers_pb2
        from secure_invoke.protos import logger_pb2
        from secure_invoke.protos import generate_bid_pb2
        
        # Create a test message
        request = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        request.seller = "test.com"
        request.publisher_name = "test.com"
        
        # Serialize
        serialized = request.SerializeToString()
        
        # Deserialize
        request2 = bidding_auction_servers_pb2.GetBidsRequest.GetBidsRawRequest()
        request2.ParseFromString(serialized)
        
        assert request2.seller == "test.com"
        assert request2.publisher_name == "test.com"
        
        print("✓ Proto compilation successful")
        return True
    except Exception as e:
        print(f"✗ Proto test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("="*60)
    print("Testing Secure Invoke Python SDK")
    print("="*60)
    
    results = []
    results.append(("Imports", test_imports()))
    results.append(("Proto Compilation", test_proto_compilation()))
    results.append(("Keyset Creation", test_keyset_creation()))
    results.append(("Encryption", test_encryption()))
    results.append(("Payload Packaging", test_payload_packaging()))
    
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{name:30s} {status}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print("="*60)
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())

