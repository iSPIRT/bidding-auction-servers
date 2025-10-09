# Usage Guide

## Command Line Interface (CLI)

The secure-invoke CLI provides three main commands: `invoke`, `encrypt`, and `batch`.

### 1. Invoke Command

Send an encrypted request to BFE and get the decrypted response.

```bash
secure-invoke invoke \
  --kms-url https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  --host 4.187.223.221:51052 \
  --input examples/example_request.json \
  --client-ip 192.168.1.1 \
  --insecure \
  --verbose
```

**Options:**
- `--kms-url`: KMS service URL (required)
- `--host`: BFE host address (required)
- `--input`: Path to JSON request file (required)
- `--client-ip`: Client IP address (default: 0.0.0.0)
- `--output`: Output file for response (optional, default: stdout)
- `--insecure`: Disable SSL verification
- `--verbose`: Enable verbose logging
- `--enable-debug-reporting`: Enable debug reporting in request
- `--enable-unlimited-egress`: Enable unlimited egress in request

**Using custom keys instead of KMS:**

```bash
secure-invoke invoke \
  --public-key "dZRQTjI+R0INCRjmULIWkMJiqFuHet7NMbtif5tlchY=" \
  --key-id "15" \
  --host 4.187.223.221:51052 \
  --input request.json \
  --insecure
```

### 2. Encrypt Command

Only encrypt the request without sending it to BFE.

```bash
secure-invoke encrypt \
  --kms-url https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  --input examples/example_request.json \
  --output encrypted_request.json \
  --verbose
```

This produces an encrypted payload:

```json
{
  "requestCiphertext": "base64_encrypted_data...",
  "keyId": "21"
}
```

### 3. Batch Command

Process multiple requests from a JSONL file with retry logic and concurrency.

```bash
secure-invoke batch \
  --kms-url https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  --host 4.187.223.221:51052 \
  --input examples/example_batch.jsonl \
  --max-concurrent 10 \
  --max-retries 3 \
  --retry-delay-ms 500 \
  --success-log successful.jsonl \
  --failure-log failed.jsonl \
  --insecure \
  --verbose
```

**Batch Options:**
- `--max-concurrent`: Maximum concurrent requests (default: 5)
- `--max-retries`: Maximum retry attempts per request (default: 3)
- `--retry-delay-ms`: Delay between retries in milliseconds (default: 500)
- `--success-log`: Path to success log file (default: success_log.jsonl)
- `--failure-log`: Path to failure log file (default: failure_log.jsonl)

**Batch File Format:**

Each line should be a JSON object with `id` and `request` fields:

```jsonl
{"id":1,"request":{"buyerInput":{"interestGroups":[...]},"seller":"example.com","publisherName":"example.com"}}
{"id":2,"request":{"buyerInput":{"interestGroups":[...]},"seller":"example.com","publisherName":"example.com"}}
```

## Programmatic API

### Basic Usage

```python
from secure_invoke import SecureInvoke

# Create client
client = SecureInvoke(
    kms_url='https://depa-inferencing-kms.centralindia.cloudapp.azure.com',
    bfe_host='4.187.223.221:51052',
    client_ip='192.168.1.1',
    insecure=True,
    verbose=True
)

# Fetch keys from KMS
client.fetch_keys()

# Prepare request
request = {
    "client_type": "CLIENT_TYPE_BROWSER",
    "buyerInput": {
        "interestGroups": [{
            "name": "Test Group",
            "biddingSignalsKeys": ["key1"],
            "userBiddingSignals": '{"age": 29}'
        }]
    },
    "seller": "example.com",
    "publisherName": "example.com"
}

# Send request and get response
response = client.invoke(request)
print(response)
```

### Using Custom Keys

```python
from secure_invoke import SecureInvoke
from secure_invoke.utils import KMSClient

# Create keyset from base64 keys
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

# Use as normal
response = client.invoke(request)
```

### Encrypt Only

```python
# Only encrypt, don't send
encrypted_request = client.encrypt_only(request)

print(encrypted_request)
# Output: {
#   "requestCiphertext": "...",
#   "keyId": "21"
# }
```

### Batch Processing

```python
# Process batch with retry logic
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

### Load Request from File

```python
# Load and invoke from JSON file
response = client.invoke_from_file(
    'request.json',
    enable_debug_reporting=True,
    enable_unlimited_egress=False
)
```

### Advanced Usage: Direct Component Access

```python
from secure_invoke.utils import KMSClient, CryptoClient, PayloadPackager, BFEClient

# Direct KMS access
kms_client = KMSClient('https://kms.example.com', insecure=True)
keysets = kms_client.fetch_keys()
keyset = keysets[0]

# Direct crypto operations
crypto_client = CryptoClient(keyset)
plaintext = b"Hello, World!"
encrypted, enc = crypto_client.encrypt(plaintext)
decrypted = crypto_client.decrypt(encrypted)

# Direct payload packaging
packager = PayloadPackager(keyset)
packaged = packager.package_get_bids_request(request)

# Direct HTTP client
with BFEClient(host='4.187.223.221:51052', insecure=True) as bfe_client:
    response = bfe_client.send_request(packaged)

# Unpackage response
response_dict = packager.unpackage_get_bids_response(response)
```

## Request Format

### GetBidsRequest Structure

```json
{
    "client_type": "CLIENT_TYPE_BROWSER",  // or CLIENT_TYPE_ANDROID
    "buyerInput": {
        "interestGroups": [{
            "name": "Interest Group Name",
            "biddingSignalsKeys": ["key1", "key2"],
            "userBiddingSignals": "{\"age\": 29, \"interests\": [\"sports\"]}",
            "adRenderIds": ["ad1", "ad2"],
            "browserSignals": {
                "joinCount": 10,
                "bidCount": 5,
                "prevWins": "[]"
            }
        }]
    },
    "seller": "example.com",
    "publisherName": "example.com",
    "auctionSignals": "{}",
    "buyerSignals": "{}",
    "logContext": {
        "generationId": "uuid",
        "adtechDebugId": "debug-id"
    },
    "consentedDebugConfig": {
        "isConsented": true,
        "token": "token"
    }
}
```

### Response Structure

```json
{
    "bids": [{
        "adMetadata": "{}",
        "bid": 1.5,
        "render": "https://example.com/ad",
        "adComponents": [],
        "modelingSignals": 0,
        "bidCurrency": "USD",
        "adCost": "0.1",
        "interestGroupOrigin": 1.0
    }],
    "adScoringSignals": {
        "key1": "value1"
    }
}
```

## Error Handling

```python
from secure_invoke import SecureInvoke

client = SecureInvoke(
    kms_url='https://kms.example.com',
    bfe_host='4.187.223.221:51052',
    insecure=True
)

try:
    client.fetch_keys()
    response = client.invoke(request)
    print("Success:", response)
    
except RuntimeError as e:
    print(f"Request failed: {e}")
    
except ValueError as e:
    print(f"Invalid data: {e}")
    
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Best Practices

1. **Use Virtual Environments**: Always use a virtual environment to avoid dependency conflicts.

2. **Enable Verbose Logging for Debugging**: Use `verbose=True` during development.

3. **Cache Keys**: Fetch keys once and reuse the keyset for multiple requests.

4. **Handle Errors Gracefully**: Always wrap API calls in try-except blocks.

5. **Use Batch Processing**: For multiple requests, use batch processing with appropriate concurrency limits.

6. **SSL Verification**: Only use `insecure=True` for testing. In production, use proper SSL certificates.

7. **Monitor Resources**: When using batch processing with high concurrency, monitor system resources.

8. **Log Results**: Use success and failure logs for batch processing to track results.

## Examples

All examples are available in the `examples/` directory:

- `basic_usage.py` - Basic single request example
- `batch_example.py` - Batch processing example
- `encrypt_only.py` - Encrypt without sending
- `custom_keys.py` - Using custom keys instead of KMS

Run any example:

```bash
cd examples
python3 basic_usage.py
```

## Integration with Existing Code

### Django Integration

```python
# views.py
from django.http import JsonResponse
from secure_invoke import SecureInvoke

def get_bids(request):
    client = SecureInvoke(
        kms_url=settings.KMS_URL,
        bfe_host=settings.BFE_HOST,
        client_ip=request.META['REMOTE_ADDR'],
        insecure=settings.DEBUG
    )
    
    client.fetch_keys()
    
    bid_request = {
        "seller": request.POST.get('seller'),
        "publisherName": request.POST.get('publisher'),
        # ... other fields
    }
    
    response = client.invoke(bid_request)
    return JsonResponse(response)
```

### Flask Integration

```python
# app.py
from flask import Flask, request, jsonify
from secure_invoke import create_client

app = Flask(__name__)
client = create_client(
    kms_url=app.config['KMS_URL'],
    bfe_host=app.config['BFE_HOST'],
    insecure=app.config['DEBUG']
)
client.fetch_keys()

@app.route('/get-bids', methods=['POST'])
def get_bids():
    bid_request = request.json
    response = client.invoke(bid_request)
    return jsonify(response)
```

## Comparison with C++ Docker Version

| Feature | Python SDK | C++ Docker |
|---------|------------|------------|
| Installation | `pip install` | Docker pull |
| Startup Time | <100ms | ~2-3 seconds |
| Memory Usage | ~50MB | ~200MB |
| Programmatic API | ✅ Yes | ❌ No |
| CLI | ✅ Yes | ✅ Yes |
| Batch Processing | ✅ Yes | ✅ Yes |
| Custom Integration | ✅ Easy | ❌ Difficult |
| Hot Reload | ✅ Yes | ❌ No |
| Dependencies | Python packages | Docker |

The Python SDK is recommended for most use cases due to its flexibility, performance, and ease of integration.

