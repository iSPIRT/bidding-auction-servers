#!/usr/bin/env python3
"""Test verbose logging to ensure all steps are printed."""

import logging
from secure_invoke import SecureInvoke
from secure_invoke.utils import KMSClient

# Configure logging to see everything
logging.basicConfig(
    level=logging.DEBUG,
    format='%(message)s'
)

def test_verbose_logging():
    """Test that verbose mode prints all details."""
    
    print("="*80)
    print("Testing Verbose Logging with Mock Keys")
    print("="*80)
    
    # Create keyset from test keys
    keyset = KMSClient.create_keyset_from_base64(
        public_key_b64='87ey8XZPXAd+/+ytKv2GFUWW5j9zdepSJ2G4gebDwyM=',
        key_id_hex='40'  # Hex 40 = decimal 64
    )
    
    # Create client with verbose mode
    client = SecureInvoke(
        kms_url='dummy',
        bfe_host='example.com:51052',
        client_ip='192.168.1.1',
        insecure=True,
        verbose=True  # Enable verbose logging
    )
    
    # Set keyset
    client.set_keyset(keyset)
    
    # Test request
    request = {
        "clientType": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Test Group",
                "biddingSignalsKeys": ["key1", "key2"],
                "userBiddingSignals": '{"age": 29}'
            }]
        },
        "seller": "example.com",
        "publisherName": "example.com"
    }
    
    print("\n" + "="*80)
    print("Testing Encryption Pipeline")
    print("="*80)
    
    # Test encrypt only (no network call)
    try:
        encrypted = client.encrypt_only(request)
        print(f"\n✅ Verbose logging test completed!")
        print(f"\nFinal encrypted request:")
        print(f"  Key ID: {encrypted['keyId']}")
        print(f"  Ciphertext: {len(encrypted['requestCiphertext'])} chars")
        print(f"  First 100 chars: {encrypted['requestCiphertext'][:100]}...")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_verbose_logging()

