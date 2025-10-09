# Secure Invoke - Python SDK

Python SDK for secure invoke operations with BFE (Buyer Front End) services. This package provides encryption, decryption, and communication capabilities using HPKE (Hybrid Public Key Encryption) with X25519, AES-256-GCM, and HKDF-SHA256.

## Features

- ✅ **KMS Integration**: Fetch encryption keys from KMS services
- ✅ **HPKE Encryption**: X25519 + AES-256-GCM + HKDF-SHA256
- ✅ **Protobuf Support**: Automatic serialization/deserialization
- ✅ **CLI Interface**: Command-line tool for easy usage
- ✅ **Programmatic API**: Python API for integration
- ✅ **Batch Processing**: Process multiple requests with retries and concurrency
- ✅ **Insecure Mode**: Testing support with SSL verification disabled

## Installation

### From Source

```bash
cd tools/secure_invoke_python
pip install -e .
```

### From PyPI (when published)

```bash
pip install secure-invoke
```

## Quick Start

### Command Line Usage

#### Single Request (Invoke)

```bash
secure-invoke invoke \
  --kms-url https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  --host 4.187.223.221:51052 \
  --input request.json \
  --insecure \
  --verbose
```

#### Encrypt Only

```bash
secure-invoke encrypt \
  --kms-url https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  --input request.json \
  --output encrypted.json
```

#### Batch Processing

```bash
secure-invoke batch \
  --kms-url https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  --host 4.187.223.221:51052 \
  --input batch_requests.jsonl \
  --max-concurrent 10 \
  --max-retries 3 \
  --insecure
```

### Programmatic Usage

#### Basic Example

```python
from secure_invoke import SecureInvoke

# Create client
client = SecureInvoke(
    kms_url='https://depa-inferencing-kms.centralindia.cloudapp.azure.com',
    bfe_host='4.187.223.221:51052',
    client_ip='192.168.1.1',
    insecure=True,  # For testing only
    verbose=True
)

# Fetch keys from KMS
client.fetch_keys()

# Send request
request = {
    "client_type": "CLIENT_TYPE_BROWSER",
    "buyerInput": {
        "interestGroups": [{
            "name": "Test Group",
            "biddingSignalsKeys": ["key1"],
            "userBiddingSignals": '{"age": 25}'
        }]
    },
    "seller": "example.com",
    "publisherName": "example.com"
}

response = client.invoke(request)
print(response)
```

#### Using Custom Keys

```python
from secure_invoke import SecureInvoke
from secure_invoke.utils import KMSClient

# Create keyset from base64-encoded keys
keyset = KMSClient.create_keyset_from_base64(
    public_key_b64='dZRQTjI+R0INCRjmULIWkMJiqFuHet7NMbtif5tlchY=',
    key_id_hex='15'
)

client = SecureInvoke(
    kms_url='dummy',  # Not used
    bfe_host='4.187.223.221:51052',
    insecure=True
)

client.set_keyset(keyset)

# Use client as normal
response = client.invoke(request)
```

#### Batch Processing

```python
from secure_invoke import SecureInvoke

client = SecureInvoke(
    kms_url='https://kms.example.com',
    bfe_host='4.187.223.221:51052',
    insecure=True
)

client.fetch_keys()

# Process batch from JSONL file
summary = client.batch_invoke(
    batch_file='batch_requests.jsonl',
    max_retries=3,
    max_concurrent=10,
    retry_delay_ms=500,
    success_log='success.jsonl',
    failure_log='failure.jsonl'
)

print(f"Total: {summary['total']}")
print(f"Successful: {summary['successful']}")
print(f"Failed: {summary['failed']}")
print(f"Success rate: {summary['success_rate']}%")
```

#### Encrypt Only (No Network Call)

```python
from secure_invoke import SecureInvoke

client = SecureInvoke(
    kms_url='https://kms.example.com',
    bfe_host='dummy',  # Not used
    insecure=True
)

client.fetch_keys()

# Only encrypt, don't send
encrypted_request = client.encrypt_only(request)

print(encrypted_request)
# Output: {'requestCiphertext': '...', 'keyId': '21'}
```

## Request Format

### Single Request (JSON)

```json
{
    "client_type": "CLIENT_TYPE_BROWSER",
    "buyerInput": {
        "interestGroups": [{
            "name": "Interest Group Name",
            "biddingSignalsKeys": ["9999999990"],
            "userBiddingSignals": "{\"age\":29, \"average_amount\":10000}"
        }]
    },
    "seller": "example.com",
    "publisherName": "example.com"
}
```

### Batch Request (JSONL)

Each line should be a JSON object with `id` and `request` fields:

```jsonl
{"id":1,"request":{"buyerInput":{"interestGroups":[{"name":"User1","biddingSignalsKeys":["key1"],"userBiddingSignals":"{}"}]},"seller":"example.com","publisherName":"example.com"}}
{"id":2,"request":{"buyerInput":{"interestGroups":[{"name":"User2","biddingSignalsKeys":["key2"],"userBiddingSignals":"{}"}]},"seller":"example.com","publisherName":"example.com"}}
```

## Architecture

The secure invoke process follows these steps:

### Encryption Flow (Request)

1. **JSON Parsing**: Parse input JSON request
2. **Protobuf Serialization**: Convert JSON to `GetBidsRawRequest` protobuf message
3. **HPKE Encryption**: Encrypt serialized proto using:
   - Key Encapsulation: X25519 (DHKEM)
   - AEAD: AES-256-GCM
   - KDF: HKDF-SHA256
4. **Base64 Encoding**: Encode encrypted data to base64
5. **JSON Packaging**: Create final request:
   ```json
   {
     "requestCiphertext": "base64_encrypted_data",
     "keyId": "21"
   }
   ```

### Decryption Flow (Response)

1. **Extract Ciphertext**: Get `responseCiphertext` from response
2. **Base64 Decoding**: Decode base64 to bytes
3. **HPKE Decryption**: Decrypt using HPKE with same parameters
4. **Protobuf Deserialization**: Parse `GetBidsRawResponse` proto
5. **JSON Conversion**: Convert proto to JSON dict

## Key Management

### KMS Key Fetching

Keys are fetched from KMS in the following format:

```json
{
  "keys": [{
    "key": "base64_encoded_public_key",
    "id": "hex_string_key_id"
  }]
}
```

The SDK transforms:
- `key`: base64 → bytes → hex
- `id`: hex string → decimal uint8

Example:
- Input: `id = "15"` (hex)
- Output: `key_id = 21` (decimal)

### Manual Key Configuration

You can also provide keys manually:

```python
from secure_invoke.utils import KMSClient

keyset = KMSClient.create_keyset_from_base64(
    public_key_b64='dZRQTjI+R0INCRjmULIWkMJiqFuHet7NMbtif5tlchY=',
    key_id_hex='15',
    private_key_b64='optional_private_key_base64'
)
```

## CLI Reference

### Global Options

- `--kms-url`: KMS service URL (required)
- `--input`: Path to input file (required)
- `--client-ip`: Client IP address (default: 0.0.0.0)
- `--insecure`: Disable SSL verification (for testing)
- `--verbose`: Enable verbose logging
- `--public-key`: Base64-encoded public key (optional)
- `--private-key`: Base64-encoded private key (optional)
- `--key-id`: Hex string key ID (optional)
- `--enable-debug-reporting`: Enable debug reporting
- `--enable-unlimited-egress`: Enable unlimited egress

### Commands

#### `invoke` - Send Request to BFE

```bash
secure-invoke invoke --host HOST [options]
```

Options:
- `--host`: BFE host address (required)
- `--output`: Output file for response (optional, default: stdout)

#### `encrypt` - Encrypt Only

```bash
secure-invoke encrypt [options]
```

Options:
- `--output`: Output file for encrypted request (optional, default: stdout)

#### `batch` - Batch Processing

```bash
secure-invoke batch --host HOST [options]
```

Options:
- `--host`: BFE host address (required)
- `--max-retries`: Maximum retry attempts (default: 3)
- `--max-concurrent`: Maximum concurrent requests (default: 5)
- `--retry-delay-ms`: Delay between retries in ms (default: 500)
- `--success-log`: Success log file path (default: success_log.jsonl)
- `--failure-log`: Failure log file path (default: failure_log.jsonl)

## Development

### Running Tests

```bash
cd tools/secure_invoke_python
python -m pytest tests/
```

### Building the Package

```bash
python -m build
```

### Installing in Development Mode

```bash
pip install -e .
```

## Comparison with C++ Implementation

This Python SDK maintains full compatibility with the C++ Docker-based implementation:

| Feature | C++ (Docker) | Python SDK |
|---------|--------------|------------|
| HPKE Algorithm | X25519 + AES-256-GCM + HKDF-SHA256 | ✅ Same |
| Key Format | base64 → hex, hex → decimal | ✅ Same |
| Protobuf | GetBidsRawRequest/Response | ✅ Same |
| KMS Integration | ✅ | ✅ |
| Batch Processing | ✅ | ✅ |
| CLI Interface | ✅ | ✅ |
| Programmatic API | ❌ | ✅ New |
| Deployment | Docker image | ✅ pip install |
| Latency | High (Docker startup) | ✅ Low (direct) |

## Troubleshooting

### SSL Certificate Errors

For testing environments, use `--insecure`:

```bash
secure-invoke invoke --insecure ...
```

### Protobuf Import Errors

Make sure to install the package properly to compile protos:

```bash
pip install -e .
```

### Key Format Issues

Ensure keys are base64-encoded and key IDs are hex strings:

```python
# Correct
public_key = 'dZRQTjI+R0INCRjmULIWkMJiqFuHet7NMbtif5tlchY='
key_id = '15'  # hex string

# Incorrect
key_id = 21  # Should be hex string '15', not decimal
```

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please ensure:

1. Code follows PEP 8 style guidelines
2. All tests pass
3. New features include tests and documentation
4. Commit messages are clear and descriptive

## Support

For issues and questions:
- GitHub Issues: [bidding-auction-servers](https://github.com/privacysandbox/bidding-auction-servers/issues)
- Documentation: See this README and inline code documentation

