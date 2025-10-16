#!/usr/bin/env python3
"""
Minimal Programmatic Example for Secure Request Client

This script demonstrates how to use the Secure Request Client programmatically
with various parameters and configurations.

Usage:
    python3 programmatic_example.py
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secure_request import SecureRequestClient, SecureRequestConfig


def main():  
    # Set up environment
    os.environ['LD_LIBRARY_PATH'] = './secure_request_client/lib:' + os.environ.get('LD_LIBRARY_PATH', '')
    
    # Example 1: Basic Usage
    print("\n=== Example 1: Basic Usage ===")
    config = SecureRequestConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    config.insecure = True
    config.request_payload = json.dumps({
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Test User",
                "biddingSignalsKeys": ["1234567890"],
                "userBiddingSignals": '{"age":30, "amount":5000}'
            }]
        },
        "seller": "example.com",
        "publisherName": "example.com"
    })
    
    client = SecureRequestClient(config)
    success = client.run()
    print(f"Result: {'Success' if success else 'Failed'}")
    
    # # Example 2: File-based Payload
    # print("\n=== Example 2: File-based Payload ===")
    # config = SecureRequestConfig()
    # config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    # config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    # config.insecure = True
    # config.request_payload = "sample_offer_request.json"  # Use existing file
    
    # client = SecureRequestClient(config)
    # success = client.run()
    # print(f"Result: {'Success' if success else 'Failed'}")
    
    # # Example 3: SSL Certificates
    # print("\n=== Example 3: SSL Certificates ===")
    # config = SecureRequestConfig()
    # config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    # config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    # config.insecure = False  # Enable SSL verification
    # config.ca_cert = "ca.crt"  # CA certificate
    # config.client_cert = "client.crt"  # Client certificate
    # config.client_key = "client.key"  # Client private key
    # config.request_payload = json.dumps({
    #     "client_type": "CLIENT_TYPE_BROWSER",
    #     "buyerInput": {
    #         "interestGroups": [{
    #             "name": "SSL Test",
    #             "biddingSignalsKeys": ["9876543210"],
    #             "userBiddingSignals": '{"ssl": "enabled"}'
    #         }]
    #     },
    #     "seller": "secure.com",
    #     "publisherName": "secure.com"
    # })
    
    # client = SecureRequestClient(config)
    # success = client.run()
    # print(f"Result: {'Success' if success else 'Failed'}")
    
    # # Example 4: Custom Headers
    # print("\n=== Example 4: Custom Headers ===")
    # config = SecureRequestConfig()
    # config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    # config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    # config.insecure = True
    # config.headers = {
    #     "Authorization": "Bearer your-token",
    #     "X-Custom-Header": "custom-value",
    #     "User-Agent": "SecureRequestClient/1.0"
    # }
    # config.request_payload = json.dumps({
    #     "client_type": "CLIENT_TYPE_BROWSER",
    #     "buyerInput": {
    #         "interestGroups": [{
    #             "name": "Custom Headers Test",
    #             "biddingSignalsKeys": ["5555555555"],
    #             "userBiddingSignals": '{"headers": "custom"}'
    #         }]
    #     },
    #     "seller": "headers.com",
    #     "publisherName": "headers.com"
    # })
    
    # client = SecureRequestClient(config)
    # success = client.run()
    # print(f"Result: {'Success' if success else 'Failed'}")
    
    # # Example 5: Retry Settings
    # print("\n=== Example 5: Retry Settings ===")
    # config = SecureRequestConfig()
    # config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    # config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    # config.insecure = True
    # config.retries = 3  # 3 retry attempts
    # config.timeout = 30  # 30 second timeout
    # config.request_payload = json.dumps({
    #     "client_type": "CLIENT_TYPE_BROWSER",
    #     "buyerInput": {
    #         "interestGroups": [{
    #             "name": "Retry Test",
    #             "biddingSignalsKeys": ["1111111111"],
    #             "userBiddingSignals": '{"retry": "enabled"}'
    #         }]
    #     },
    #     "seller": "retry.com",
    #     "publisherName": "retry.com"
    # })
    
    # client = SecureRequestClient(config)
    # success = client.run()
    # print(f"Result: {'Success' if success else 'Failed'}")
    
    # # Example 6: Verbose Output
    # print("\n=== Example 6: Verbose Output ===")
    # config = SecureRequestConfig()
    # config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    # config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    # config.insecure = True
    # config.enable_verbose = True  # Enable verbose output
    # config.request_payload = json.dumps({
    #     "client_type": "CLIENT_TYPE_BROWSER",
    #     "buyerInput": {
    #         "interestGroups": [{
    #             "name": "Verbose Test",
    #             "biddingSignalsKeys": ["9999999999"],
    #             "userBiddingSignals": '{"verbose": "enabled"}'
    #         }]
    #     },
    #     "seller": "verbose.com",
    #     "publisherName": "verbose.com"
    # })
    
    # client = SecureRequestClient(config)
    # success = client.run()
    # print(f"Result: {'Success' if success else 'Failed'}")
    
    # # Example 7: Step-by-step Usage
    # print("\n=== Example 7: Step-by-step Usage ===")
    # config = SecureRequestConfig()
    # config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    # config.offer_host = "http://4.213.211.238:51052/v1/getbids"
    # config.insecure = True
    # config.request_payload = json.dumps({
    #     "client_type": "CLIENT_TYPE_BROWSER",
    #     "buyerInput": {
    #         "interestGroups": [{
    #             "name": "Step by Step",
    #             "biddingSignalsKeys": ["7777777777"],
    #             "userBiddingSignals": '{"step": "by_step"}'
    #         }]
    #     },
    #     "seller": "step.com",
    #     "publisherName": "step.com"
    # })
    
    # client = SecureRequestClient(config)
    
    # try:
    #     # Step 1: Validate configuration
    #     print("1. Validating configuration...")
    #     if not config.validate():
    #         print("✗ Configuration validation failed")
    #         return
    #     print("✓ Configuration valid")
        
    #     # Step 2: Setup clients
    #     print("2. Setting up clients...")
    #     if not client.setup_kms_client():
    #         print("✗ KMS client setup failed")
    #         return
    #     if not client.setup_http_client():
    #         print("✗ HTTP client setup failed")
    #         return
    #     print("✓ Clients setup successful")
        
    #     # Step 3: Load request data
    #     print("3. Loading request data...")
    #     request_data = client.load_request_data()
    #     if request_data is None:
    #         print("✗ Failed to load request data")
    #         return
    #     print("✓ Request data loaded")
        
    #     # Step 4: Fetch public key
    #     print("4. Fetching public key...")
    #     public_key = client.fetch_public_key()
    #     if public_key is None:
    #         print("✗ Failed to fetch public key")
    #         return
    #     print("✓ Public key fetched")
        
    #     # Step 5: Process request
    #     print("5. Processing request...")
    #     result = client.process_single_request(request_data, public_key)
    #     if result is None:
    #         print("✗ Request processing failed")
    #         return
    #     print("✓ Request processed successfully")
    #     print(f"Response: {json.dumps(result, indent=2)}")
        
    # except Exception as e:
    #     print(f"✗ Error: {e}")


if __name__ == "__main__":
    main()