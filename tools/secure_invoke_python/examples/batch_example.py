#!/usr/bin/env python3
"""Batch processing example for secure invoke SDK."""

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
    client.fetch_keys()
    
    # Process batch
    print("\nProcessing batch requests...")
    summary = client.batch_invoke(
        batch_file='example_batch.jsonl',
        max_retries=3,
        max_concurrent=5,
        retry_delay_ms=500,
        success_log='batch_success.jsonl',
        failure_log='batch_failure.jsonl'
    )
    
    # Print summary
    print("\n" + "="*50)
    print("Batch Processing Summary")
    print("="*50)
    print(f"Total requests:  {summary['total']}")
    print(f"Successful:      {summary['successful']}")
    print(f"Failed:          {summary['failed']}")
    print(f"Success rate:    {summary['success_rate']:.2f}%")
    print("="*50)
    print("\nLogs written to:")
    print("  - batch_success.jsonl")
    print("  - batch_failure.jsonl")

if __name__ == '__main__':
    main()

