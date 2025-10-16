# Quick Start Guide

Get up and running with Secure Request Client in 2 minutes.

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
mkdir -p secure_request_client/lib
cp temp_extract/secure_invoke_crypto/lib/*.so secure_request_client/lib/
rm -rf temp_extract

# 5. Set up environment
export LD_LIBRARY_PATH=./secure_request_client/lib:$LD_LIBRARY_PATH
export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export OFFER_HOST=http://4.213.211.238:51052/v1/getbids
```

## CLI Usage

### Basic Commands

```bash
# Minimal test command
python3 secure_request.py --kms-host $KMS_HOST --offer-host $OFFER_HOST --request-payload sample_offer_request.json --insecure

# Using direct JSON
python3 secure_request.py \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"test","biddingSignalsKeys":["123"]}]},"seller":"test.com","publisherName":"test.com"}' \
  --insecure

# With verbose output
python3 secure_request.py \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --insecure \
  --enable-verbose
```

### SSL Certificate Usage

```bash
# With CA certificate
python3 secure_request.py \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --ca-cert ca.crt

# With client certificates
python3 secure_request.py \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --client-cert client.crt \
  --client-key client.key
```

### Custom Headers and Retries

```bash
# With custom headers
  python3 secure_request.py \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --headers '{"Authorization":"Bearer token","X-Custom":"value"}' \
  --insecure

# With retry attempts
python3 secure_request.py \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --retries 3 \
  --insecure
```

## Programmatic Usage

### Quick Example

```python
from secure_request import SecureRequestClient, SecureRequestConfig

# Create configuration
config = SecureRequestConfig()
config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
config.offer_host = "http://4.213.211.238:51052/v1/getbids"
config.insecure = True
config.request_payload = '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"Rajni Kausalya","biddingSignalsKeys":["9999999990"],"userBiddingSignals":"{\\"age\\":29,\\"average_amount\\":10000}"}]},"seller":"irctc.com","publisherName":"irctc.com"}'

# Run the tool
client = SecureRequestClient(config)
success = client.run()
```

### Run the programmatic example script
```bash
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

- **Request File**: `sample_offer_request.json`

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
export LD_LIBRARY_PATH=./secure_request_client/lib:$LD_LIBRARY_PATH
```

### Connection Errors
```bash
# Check host URLs
--kms-host https://your-kms-host.com
--offer-host http://your-offer-host.com:51052
```

## That's It!

You're ready to use Secure Request Client!

- **CLI**: Use `python3 secure_request.py --help` for all options
- **Programmatic**: See `programmatic_example.py` for comprehensive examples
- **Testing**: Run `python3 tests/run_tests.py` to verify everything works