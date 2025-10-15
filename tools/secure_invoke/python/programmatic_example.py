#!/usr/bin/env python3
"""
Programmatic Example for SecureInvoke Tool

This script demonstrates how to use the SecureInvoke tool programmatically,
mirroring all the CLI functionalities without command-line arguments.

Usage:
    python3 programmatic_example.py
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secure_invoke import SecureInvokeTool, SecureInvokeConfig


def example_basic_usage():
    """Example 1: Basic usage with JSON payload."""
    print("=" * 60)
    print("EXAMPLE 1: Basic Usage with JSON Payload")
    print("=" * 60)
    
    # Create configuration
    config = SecureInvokeConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
    config.insecure = True  # Use insecure mode for testing
    config.enable_verbose = True
    
    # Direct JSON payload
    config.request_payload = json.dumps({
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Rajni Kausalya",
                "biddingSignalsKeys": ["9999999990"],
                "userBiddingSignals": '{"age":29, "average_amount":10000}'
            }]
        },
        "seller": "irctc.com",
        "publisherName": "irctc.com"
    })
    
    # Create and run the tool
    tool = SecureInvokeTool(config)
    success = tool.run()
    
    if success:
        print("✓ Request completed successfully")
    else:
        print("✗ Request failed")
    
    return success


def example_file_based_usage():
    """Example 2: File-based usage with JSON file."""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: File-based Usage")
    print("=" * 60)
    
    # Create configuration
    config = SecureInvokeConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
    config.insecure = True
    config.enable_verbose = False  # Clean output
    
    # Use existing JSON file
    config.request_payload = "get_bids_request.json"
    
    # Create and run the tool
    tool = SecureInvokeTool(config)
    success = tool.run()
    
    if success:
        print("✓ File-based request completed successfully")
    else:
        print("✗ File-based request failed")
    
    return success


def example_with_ssl_certificates():
    """Example 3: Usage with SSL certificates (secure mode)."""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: SSL Certificate Usage")
    print("=" * 60)
    
    # Create configuration with SSL certificates
    config = SecureInvokeConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
    config.insecure = False  # Secure mode
    config.ca_cert = "ca.crt"  # CA certificate
    config.client_cert = "client.crt"  # Client certificate
    config.client_key = "client.key"  # Client private key
    config.enable_verbose = True
    
    # JSON payload
    config.request_payload = json.dumps({
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Test Interest Group",
                "biddingSignalsKeys": ["1234567890"],
                "userBiddingSignals": '{"age":25, "average_amount":5000}'
            }]
        },
        "seller": "example.com",
        "publisherName": "example.com"
    })
    
    # Create and run the tool
    tool = SecureInvokeTool(config)
    success = tool.run()
    
    if success:
        print("✓ SSL-secured request completed successfully")
    else:
        print("✗ SSL-secured request failed")
    
    return success


def example_with_custom_headers():
    """Example 4: Usage with custom headers."""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Custom Headers Usage")
    print("=" * 60)
    
    # Create configuration with custom headers
    config = SecureInvokeConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
    config.insecure = True
    config.headers = {
        "Authorization": "Bearer test-token",
        "X-Custom-Header": "test-value",
        "User-Agent": "SecureInvoke-Programmatic/1.0"
    }
    config.enable_verbose = True
    
    # JSON payload
    config.request_payload = json.dumps({
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Custom Headers Test",
                "biddingSignalsKeys": ["9876543210"],
                "userBiddingSignals": '{"test": "custom_headers"}'
            }]
        },
        "seller": "test.com",
        "publisherName": "test.com"
    })
    
    # Create and run the tool
    tool = SecureInvokeTool(config)
    success = tool.run()
    
    if success:
        print("✓ Custom headers request completed successfully")
    else:
        print("✗ Custom headers request failed")
    
    return success


def example_with_retries():
    """Example 5: Usage with custom retry settings."""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Custom Retry Settings")
    print("=" * 60)
    
    # Create configuration with retry settings
    config = SecureInvokeConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
    config.insecure = True
    config.retries = 3  # 3 retry attempts
    config.enable_verbose = True
    
    # JSON payload
    config.request_payload = json.dumps({
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Retry Test",
                "biddingSignalsKeys": ["5555555555"],
                "userBiddingSignals": '{"retry": "test"}'
            }]
        },
        "seller": "retry.com",
        "publisherName": "retry.com"
    })
    
    # Create and run the tool
    tool = SecureInvokeTool(config)
    success = tool.run()
    
    if success:
        print("✓ Retry-enabled request completed successfully")
    else:
        print("✗ Retry-enabled request failed")
    
    return success


def example_step_by_step_usage():
    """Example 6: Step-by-step usage for advanced control."""
    print("\n" + "=" * 60)
    print("EXAMPLE 6: Step-by-step Usage")
    print("=" * 60)
    
    # Create configuration
    config = SecureInvokeConfig()
    config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
    config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
    config.insecure = True
    config.enable_verbose = True
    
    # JSON payload
    config.request_payload = json.dumps({
        "client_type": "CLIENT_TYPE_BROWSER",
        "buyerInput": {
            "interestGroups": [{
                "name": "Step by Step Test",
                "biddingSignalsKeys": ["1111111111"],
                "userBiddingSignals": '{"step": "by_step"}'
            }]
        },
        "seller": "step.com",
        "publisherName": "step.com"
    })
    
    # Create tool
    tool = SecureInvokeTool(config)
    
    try:
        # Step 1: Validate configuration
        print("Step 1: Validating configuration...")
        if not config.validate():
            print("✗ Configuration validation failed")
            return False
        print("✓ Configuration is valid")
        
        # Step 2: Setup KMS client
        print("\nStep 2: Setting up KMS client...")
        if not tool.setup_kms_client():
            print("✗ KMS client setup failed")
            return False
        print("✓ KMS client setup successful")
        
        # Step 3: Setup HTTP client
        print("\nStep 3: Setting up HTTP client...")
        if not tool.setup_http_client():
            print("✗ HTTP client setup failed")
            return False
        print("✓ HTTP client setup successful")
        
        # Step 4: Load request data
        print("\nStep 4: Loading request data...")
        request_data = tool.load_request_data()
        if request_data is None:
            print("✗ Failed to load request data")
            return False
        print("✓ Request data loaded successfully")
        
        # Step 5: Fetch public key
        print("\nStep 5: Fetching public key...")
        public_key = tool.fetch_public_key()
        if public_key is None:
            print("✗ Failed to fetch public key")
            return False
        print("✓ Public key fetched successfully")
        
        # Step 6: Process request
        print("\nStep 6: Processing request...")
        result = tool.process_single_request(request_data, public_key)
        if result is None:
            print("✗ Request processing failed")
            return False
        print("✓ Request processed successfully")
        print(f"Result: {json.dumps(result, indent=2)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error in step-by-step processing: {e}")
        return False


def example_error_handling():
    """Example 7: Error handling and validation."""
    print("\n" + "=" * 60)
    print("EXAMPLE 7: Error Handling")
    print("=" * 60)
    
    # Test 1: Missing required parameters
    print("Test 1: Missing required parameters")
    config = SecureInvokeConfig()
    # Don't set required parameters
    if not config.validate():
        print("✓ Correctly detected missing parameters")
    else:
        print("✗ Should have detected missing parameters")
    
    # Test 2: Invalid file path
    print("\nTest 2: Invalid file path")
    config = SecureInvokeConfig()
    config.kms_host = "https://test.example.com"
    config.buyer_host = "http://test.example.com"
    config.request_payload = "nonexistent_file.json"
    config.insecure = True
    
    if not config.validate():
        print("✓ Correctly detected invalid file path")
    else:
        print("✗ Should have detected invalid file path")
    
    # Test 3: SSL certificate requirements
    print("\nTest 3: SSL certificate requirements")
    config = SecureInvokeConfig()
    config.kms_host = "https://test.example.com"
    config.buyer_host = "http://test.example.com"
    config.request_payload = '{"test": "data"}'
    config.insecure = False  # Secure mode without certificates
    
    if not config.validate():
        print("✓ Correctly detected missing SSL certificates")
    else:
        print("✗ Should have detected missing SSL certificates")
    
    print("\n✓ Error handling tests completed")


def main():
    """Main function to run all examples."""
    print("SecureInvoke Programmatic Usage Examples")
    print("=" * 60)
    print("This script demonstrates programmatic usage of the SecureInvoke tool.")
    print("All examples mirror the CLI functionality but use Python code instead.")
    print()
    
    # Set up environment
    os.environ['LD_LIBRARY_PATH'] = './secure_invoke_crypto/lib:' + os.environ.get('LD_LIBRARY_PATH', '')
    
    # Run examples
    examples = [
        ("Basic Usage", example_basic_usage),
        ("File-based Usage", example_file_based_usage),
        ("SSL Certificates", example_with_ssl_certificates),
        ("Custom Headers", example_with_custom_headers),
        ("Retry Settings", example_with_retries),
        ("Step-by-step", example_step_by_step_usage),
        ("Error Handling", example_error_handling)
    ]
    
    results = []
    
    for name, example_func in examples:
        try:
            print(f"\nRunning {name} example...")
            result = example_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ {name} example failed with error: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    for name, success in results:
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{name:20} {status}")
    
    total_passed = sum(1 for _, success in results if success)
    total_examples = len(results)
    
    print(f"\nTotal: {total_passed}/{total_examples} examples passed")
    
    if total_passed == total_examples:
        print("🎉 All examples completed successfully!")
    else:
        print("⚠️  Some examples failed. Check the output above for details.")


if __name__ == "__main__":
    main()
