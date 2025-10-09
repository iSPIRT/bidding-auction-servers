#!/usr/bin/env python3
"""Example of encrypting request without sending it."""

import json
from secure_invoke import SecureInvoke

def main():
    # Create client
    client = SecureInvoke(
        kms_url='https://depa-inferencing-kms.centralindia.cloudapp.azure.com',
        bfe_host='dummy',  # Not needed for encrypt-only
        insecure=True,
        verbose=True
    )
    
    # Fetch keys from KMS
    print("Fetching keys from KMS...")
    keyset = client.fetch_keys()
    print(f"Using key ID: {keyset.key_id}")
    
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
    
    # Encrypt only (no network call)
    print("\nEncrypting request...")
    encrypted = client.encrypt_only(request)
    
    # Print encrypted request
    print("\nEncrypted Request:")
    print(json.dumps(encrypted, indent=2))
    
    # Save to file
    output_file = 'encrypted_request.json'
    with open(output_file, 'w') as f:
        json.dump(encrypted, f, indent=2)
    print(f"\nEncrypted request saved to: {output_file}")

if __name__ == '__main__':
    main()

