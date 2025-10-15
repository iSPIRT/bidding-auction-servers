# Quick Start Guide

Get up and running with SecureInvoke in 2 minutes.

## Setup

```bash
# 1. Navigate to project directory
cd bidding-auction-servers/tools/secure_invoke/python

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install the wheel
pip install secure_invoke_crypto-0.1.0-py3-none-any.whl

# 4. Extract shared libraries
python -m zipfile -e secure_invoke_crypto-0.1.0-py3-none-any.whl temp_extract
mkdir -p secure_invoke_crypto/lib
cp temp_extract/secure_invoke_crypto/lib/*.so secure_invoke_crypto/lib/
rm -rf temp_extract

# 5. Set up environment
export LD_LIBRARY_PATH=./secure_invoke_crypto/lib:$LD_LIBRARY_PATH
export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export BUYER_HOST=http://4.224.152.16:51052/v1/getbids
```

## CLI Usage

### Basic Commands

```bash
# Minimal test command
python3 secure_invoke.py --kms-host $KMS_HOST --buyer-host $BUYER_HOST --request-payload get_bids_request.json --insecure

# Using direct JSON
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"test","biddingSignalsKeys":["123"]}]},"seller":"test.com","publisherName":"test.com"}' \
  --insecure

# With verbose output
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --insecure \
  --enable-verbose
```

### SSL Certificate Usage

```bash
# With CA certificate
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --ca-cert ca.crt

# With client certificates
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --client-cert client.crt \
  --client-key client.key
```

### Custom Headers and Retries

```bash
# With custom headers
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --headers '{"Authorization":"Bearer token","X-Custom":"value"}' \
  --insecure

# With retry attempts
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --retries 3 \
  --insecure
```

## Programmatic Usage

### Quick Example

```python
from secure_invoke import SecureInvokeTool, SecureInvokeConfig

# Create configuration
config = SecureInvokeConfig()
config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
config.buyer_host = "http://4.224.152.16:51052/v1/getbids"
config.insecure = True
config.request_payload = '{"client_type":"CLIENT_TYPE_BROWSER",...}'

# Run the tool
tool = SecureInvokeTool(config)
success = tool.run()
```

### Run All Examples

```bash
# Comprehensive programmatic examples
python3 programmatic_example.py
```

## Testing

### Run Tests

```bash
# All tests
python3 tests/run_tests.py

# Specific test modules
python3 tests/run_tests.py test_config
python3 tests/run_tests.py test_http_client
python3 tests/run_tests.py test_kms_client
python3 tests/run_tests.py test_request_loading
python3 tests/run_tests.py test_crypto_operations
python3 tests/run_tests.py test_integration
```

### Test Results

```bash
# Expected output for working tests
python3 tests/run_tests.py test_config
# Ran 9 tests in 0.001s
# OK
```

## Sample Data

- **Request File**: `get_bids_request.json`
- **Programmatic Examples**: `programmatic_example.py`

## Common Issues

### SSL Certificate Errors
```bash
# Use insecure mode for testing
--insecure

# Or provide proper certificates
--ca-cert ca.crt --client-cert client.crt --client-key client.key
```

### Library Path Issues
```bash
# Ensure library path is set
export LD_LIBRARY_PATH=./secure_invoke_crypto/lib:$LD_LIBRARY_PATH
```

### Connection Errors
```bash
# Check host URLs
--kms-host https://your-kms-host.com
--buyer-host http://your-buyer-host.com:51052
```

## That's It!

You're ready to use SecureInvoke!

- **CLI**: Use `python3 secure_invoke.py --help` for all options
- **Programmatic**: See `programmatic_example.py` for comprehensive examples
- **Testing**: Run `python3 tests/run_tests.py` to verify everything works