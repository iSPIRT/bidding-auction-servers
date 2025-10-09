"""Command-line interface for secure invoke."""

import argparse
import json
import logging
import sys
from pathlib import Path

from .api import SecureInvoke
from .utils.kms_client import KMSClient


def setup_logging(verbose: bool):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def cmd_invoke(args):
    """Handle invoke command."""
    setup_logging(args.verbose)
    
    # Create client
    client = SecureInvoke(
        kms_url=args.kms_url,
        bfe_host=args.host,
        client_ip=args.client_ip,
        insecure=args.insecure,
        verbose=args.verbose
    )
    
    # Fetch keys
    if args.public_key and args.key_id:
        # Use provided keys
        from .utils.kms_client import KMSClient
        keyset = KMSClient.create_keyset_from_base64(
            public_key_b64=args.public_key,
            key_id_hex=args.key_id,
            private_key_b64=args.private_key
        )
        client.set_keyset(keyset)
    else:
        # Fetch from KMS
        client.fetch_keys()
    
    # Load and send request
    try:
        response = client.invoke_from_file(
            args.input,
            enable_debug_reporting=args.enable_debug_reporting,
            enable_unlimited_egress=args.enable_unlimited_egress
        )
        
        # Output response
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(response, f, indent=2)
            print(f"Response written to {args.output}")
        else:
            print(json.dumps(response, indent=2))
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            raise
        sys.exit(1)


def cmd_encrypt(args):
    """Handle encrypt command."""
    setup_logging(args.verbose)
    
    # Create client
    client = SecureInvoke(
        kms_url=args.kms_url,
        bfe_host='dummy',  # Not used for encrypt-only
        client_ip=args.client_ip,
        insecure=args.insecure,
        verbose=args.verbose
    )
    
    # Fetch keys
    if args.public_key and args.key_id:
        # Use provided keys
        from .utils.kms_client import KMSClient
        keyset = KMSClient.create_keyset_from_base64(
            public_key_b64=args.public_key,
            key_id_hex=args.key_id,
            private_key_b64=args.private_key
        )
        client.set_keyset(keyset)
    else:
        # Fetch from KMS
        client.fetch_keys()
    
    # Load and encrypt request
    try:
        from .utils.payload import PayloadPackager
        request = PayloadPackager.load_json_request(args.input)
        
        encrypted_request = client.encrypt_only(
            request,
            enable_debug_reporting=args.enable_debug_reporting,
            enable_unlimited_egress=args.enable_unlimited_egress
        )
        
        # Output encrypted request
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(encrypted_request, f, indent=2)
            print(f"Encrypted request written to {args.output}")
        else:
            print(json.dumps(encrypted_request, indent=2))
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            raise
        sys.exit(1)


def cmd_batch(args):
    """Handle batch command."""
    setup_logging(args.verbose)
    
    # Create client
    client = SecureInvoke(
        kms_url=args.kms_url,
        bfe_host=args.host,
        client_ip=args.client_ip,
        insecure=args.insecure,
        verbose=args.verbose
    )
    
    # Fetch keys
    if args.public_key and args.key_id:
        # Use provided keys
        from .utils.kms_client import KMSClient
        keyset = KMSClient.create_keyset_from_base64(
            public_key_b64=args.public_key,
            key_id_hex=args.key_id,
            private_key_b64=args.private_key
        )
        client.set_keyset(keyset)
    else:
        # Fetch from KMS
        client.fetch_keys()
    
    # Process batch
    try:
        summary = client.batch_invoke(
            batch_file=args.input,
            max_retries=args.max_retries,
            max_concurrent=args.max_concurrent,
            retry_delay_ms=args.retry_delay_ms,
            success_log=args.success_log,
            failure_log=args.failure_log
        )
        
        print("\nBatch Processing Summary:")
        print(f"  Total requests: {summary['total']}")
        print(f"  Successful: {summary['successful']}")
        print(f"  Failed: {summary['failed']}")
        print(f"  Success rate: {summary['success_rate']:.2f}%")
        print(f"\nLogs written to:")
        print(f"  Success: {args.success_log}")
        print(f"  Failure: {args.failure_log}")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            raise
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Secure Invoke - Encrypt and send requests to BFE services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Invoke with KMS keys
  secure-invoke invoke --kms-url https://kms.example.com \\
      --host 4.187.223.221:51052 --input request.json --insecure

  # Encrypt only with provided keys
  secure-invoke encrypt --kms-url https://kms.example.com \\
      --input request.json --output encrypted.json

  # Batch processing
  secure-invoke batch --kms-url https://kms.example.com \\
      --host 4.187.223.221:51052 --input batch.jsonl \\
      --max-concurrent 10 --insecure
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    subparsers.required = True
    
    # Common arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        '--kms-url',
        required=True,
        help='KMS service URL (e.g., https://kms.example.com)'
    )
    parent_parser.add_argument(
        '--input',
        required=True,
        help='Path to input file (JSON or JSONL)'
    )
    parent_parser.add_argument(
        '--client-ip',
        default='0.0.0.0',
        help='Client IP address (default: 0.0.0.0)'
    )
    parent_parser.add_argument(
        '--insecure',
        action='store_true',
        help='Disable SSL verification (insecure)'
    )
    parent_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parent_parser.add_argument(
        '--public-key',
        help='Base64-encoded public key (if not fetching from KMS)'
    )
    parent_parser.add_argument(
        '--private-key',
        help='Base64-encoded private key (if not fetching from KMS)'
    )
    parent_parser.add_argument(
        '--key-id',
        help='Hex string key ID (if not fetching from KMS)'
    )
    parent_parser.add_argument(
        '--enable-debug-reporting',
        action='store_true',
        help='Enable debug reporting in request'
    )
    parent_parser.add_argument(
        '--enable-unlimited-egress',
        action='store_true',
        help='Enable unlimited egress in request'
    )
    
    # Invoke command
    invoke_parser = subparsers.add_parser(
        'invoke',
        parents=[parent_parser],
        help='Encrypt request and send to BFE'
    )
    invoke_parser.add_argument(
        '--host',
        required=True,
        help='BFE host address (e.g., 4.187.223.221:51052)'
    )
    invoke_parser.add_argument(
        '--output',
        help='Output file for response (default: stdout)'
    )
    invoke_parser.set_defaults(func=cmd_invoke)
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser(
        'encrypt',
        parents=[parent_parser],
        help='Only encrypt request without sending'
    )
    encrypt_parser.add_argument(
        '--output',
        help='Output file for encrypted request (default: stdout)'
    )
    encrypt_parser.set_defaults(func=cmd_encrypt)
    
    # Batch command
    batch_parser = subparsers.add_parser(
        'batch',
        parents=[parent_parser],
        help='Process multiple requests from JSONL file'
    )
    batch_parser.add_argument(
        '--host',
        required=True,
        help='BFE host address (e.g., 4.187.223.221:51052)'
    )
    batch_parser.add_argument(
        '--max-retries',
        type=int,
        default=3,
        help='Maximum retry attempts per request (default: 3)'
    )
    batch_parser.add_argument(
        '--max-concurrent',
        type=int,
        default=5,
        help='Maximum concurrent requests (default: 5)'
    )
    batch_parser.add_argument(
        '--retry-delay-ms',
        type=int,
        default=500,
        help='Delay between retries in milliseconds (default: 500)'
    )
    batch_parser.add_argument(
        '--success-log',
        default='success_log.jsonl',
        help='Path to success log file (default: success_log.jsonl)'
    )
    batch_parser.add_argument(
        '--failure-log',
        default='failure_log.jsonl',
        help='Path to failure log file (default: failure_log.jsonl)'
    )
    batch_parser.set_defaults(func=cmd_batch)
    
    # Parse and execute
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()

