#!/usr/bin/env python3
"""Example using custom keys instead of fetching from KMS."""

import json
from secure_invoke import SecureInvoke
from secure_invoke.utils import KMSClient

def main():
    # Create keyset from base64-encoded keys
    # These are example keys - replace with your actual keys
    keyset = KMSClient.create_keyset_from_base64(
        public_key_b64='dZRQTjI+R0INCRjmULIWkMJiqFuHet7NMbtif5tlchY=',
        key_id_hex='15'  # Hex string (will be converted to decimal 21)
    )
    
    print(f"Created keyset with key ID: {keyset.key_id} (decimal)")
    
    # Create client
    client = SecureInvoke(
        kms_url='dummy',  # Not used when setting keyset manually
        bfe_host='4.187.223.221:51052',
        client_ip='192.168.1.1',
        insecure=True,
        verbose=True
    )
    
    # Set the keyset manually
    client.set_keyset(keyset)
    
    # Prepare request
    request = {
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Test Group",
                "biddingSignalsKeys": ["9999999990"],
                "userBiddingSignals": '{"age": 29, "average_amount": 10000}'
            }]
        },
        "seller": "irctc.com",
        "publisherName": "irctc.com"
    }
    
    # Encrypt and print
    print("\nEncrypting request...")
    encrypted = client.encrypt_only(request)
    print("\nEncrypted Request:")
    print(json.dumps(encrypted, indent=2))

if __name__ == '__main__':
    main()

