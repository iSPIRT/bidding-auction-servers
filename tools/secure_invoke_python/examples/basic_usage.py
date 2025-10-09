#!/usr/bin/env python3
"""Basic usage example for secure invoke SDK."""

from secure_invoke import SecureInvoke

def main():
    # Create client
    client = SecureInvoke(
        kms_url='https://depa-inferencing-kms.centralindia.cloudapp.azure.com',
        bfe_host='4.187.223.221:51052',
        client_ip='192.168.1.1',
        insecure=True,  # For testing only!
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
    
    # Send request
    print("\nSending request to BFE...")
    response = client.invoke(request)
    
    # Print response
    print("\nResponse:")
    import json
    print(json.dumps(response, indent=2))

if __name__ == '__main__':
    main()

