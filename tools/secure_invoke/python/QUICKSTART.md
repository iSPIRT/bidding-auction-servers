# Quick Start Guide

Get up and running with Secure Request Client in 2 minutes.

## Setup

```bash
# 1. Navigate to project directory
cd bidding-auction-servers/tools/secure_invoke/python

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install the package
pip install .  # or `pip install -e .` for development

# 4. Set up library path (automatically handled by the package)
export LD_LIBRARY_PATH=$(python -c "import secure_request_client; import os; print(os.path.join(os.path.dirname(secure_request_client.__file__), 'lib'))"):$LD_LIBRARY_PATH

# 5. Set up environment variables for KMS and Offer service hosts
export KMS_HOST=https://<kms_host_url>  # eg. export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export OFFER_HOST=http://<offer_host_ip>:<port>/v1/getbids  # eg. export OFFER_HOST=http://20.219.207.27:51052/v1/getbids

# 6. Test the installation
secure-request --help
```

## CLI Usage

### Basic Commands

```bash
# Minimal test command
secure-request --kms-host $KMS_HOST --offer-host $OFFER_HOST --request-payload sample_offer_request.json --insecure

# Using direct JSON
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"test","biddingSignalsKeys":["123"]}]},"seller":"test.com","publisherName":"test.com"}' \
  --insecure

# With verbose output
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --insecure \
  --enable-verbose
```

### SSL Certificate Usage

```bash
# With CA certificate
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --ca-cert ca.crt

# With client certificates
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --client-cert client.crt \
  --client-key client.key
```

### Custom Headers and Retries

```bash
# With custom headers
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --headers '{"Authorization":"Bearer token","X-Custom":"value"}' \
  --insecure

# With retry attempts
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --retries 3 \
  --insecure
```

## Programmatic Usage

### Basic Example

```python
from secure_request_client.cli import SecureRequestClient, SecureRequestConfig

# Create configuration
config = SecureRequestConfig()
config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
config.offer_host = "http://20.219.207.27:51052/v1/getbids"
config.insecure = True
config.request_payload = '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"Rajni Kausalya","biddingSignalsKeys":["9999999990"],"userBiddingSignals":"{\\"age\\":29,\\"average_amount\\":10000}"}]},"seller":"irctc.com","publisherName":"irctc.com"}'

# Run the tool
client = SecureRequestClient(config)
success = client.run()
```

### Advanced Configuration

```python
from secure_request_client.cli import SecureRequestClient, SecureRequestConfig
import json

# Create configuration with SSL certificates
config = SecureRequestConfig()
config.kms_host = "https://your-kms-host.com"
config.offer_host = "https://your-offer-host.com:51052"
config.request_payload = json.dumps({
    "client_type": "CLIENT_TYPE_BROWSER",
    "buyerInput": {
        "interestGroups": [{
            "name": "Travel Enthusiasts",
            "biddingSignalsKeys": ["1234567890"],
            "userBiddingSignals": '{"age": 28, "travel_frequency": "monthly"}'
        }]
    },
    "seller": "travel.example.com",
    "publisherName": "travel.example.com"
})

# SSL Configuration
config.ca_cert = "path/to/ca.crt"
config.client_cert = "path/to/client.crt"
config.client_key = "path/to/client.key"

# Custom headers and retry logic
config.headers = {"Authorization": "Bearer your-token", "X-Custom": "value"}
config.retries = 3
config.enable_verbose = True

# Run with error handling
try:
    client = SecureRequestClient(config)
    success = client.run()
    if success:
        print("Request completed successfully")
    else:
        print("Request failed")
except Exception as e:
    print(f"Error: {e}")
```

### File-based Payload

```python
from secure_request_client.cli import SecureRequestClient, SecureRequestConfig

# Load payload from file
with open('sample_offer_request.json', 'r') as f:
    payload = f.read()

config = SecureRequestConfig()
config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
config.offer_host = "http://20.219.207.27:51052/v1/getbids"
config.request_payload = payload
config.insecure = True

client = SecureRequestClient(config)
success = client.run()
```

### Run the programmatic example script
```bash
python3 programmatic_examples.py
```

## Testing

### Verify Installation

```bash
# Test the CLI command
secure-request --help

# Run programmatic examples to verify functionality
python3 programmatic_examples.py
```

## Sample Data

- **Request File**: `sample_offer_request.json`

## Troubleshooting

### Common Issues

#### SSL Certificate Errors
```bash
# Use insecure mode for testing
secure-request --insecure --kms-host $KMS_HOST --offer-host $OFFER_HOST --request-payload sample_offer_request.json

# Or provide proper certificates
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --ca-cert ca.crt \
  --client-cert client.crt \
  --client-key client.key
```

#### Library Path Issues
```bash
# Ensure library path is set correctly
export LD_LIBRARY_PATH=$(python -c "import secure_request_client; import os; print(os.path.join(os.path.dirname(secure_request_client.__file__), 'lib'))"):$LD_LIBRARY_PATH

# Verify libraries are accessible
ls -la $(python -c "import secure_request_client; import os; print(os.path.join(os.path.dirname(secure_request_client.__file__), 'lib'))")
```

#### Connection Errors
```bash
# Check host URLs and connectivity
ping your-kms-host.com
curl -k https://your-kms-host.com/health

# Verify offer host is reachable
curl -k http://your-offer-host.com:51052/health
```

#### JSON Payload Issues
```bash
# Validate JSON format
echo '{"test": "value"}' | python -m json.tool

# Check payload file exists and is readable
ls -la sample_offer_request.json
cat sample_offer_request.json | python -m json.tool
```

#### Permission Issues
```bash
# Ensure proper file permissions
chmod +x $(which secure-request)
chmod 644 sample_offer_request.json
chmod 600 client.key  # Private key should be readable only by owner
```

### Debug Mode

```bash
# Enable verbose output for debugging
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --insecure \
  --enable-verbose
```

### Environment Verification

```bash
# Check Python environment
python --version
pip list | grep secure-request

# Verify package installation
python -c "import secure_request_client; print(secure_request_client.__file__)"

# Test library loading
python -c "from secure_request_client.cli import SecureRequestClient; print('Import successful')"
```

## Project Structure

```
secure_invoke/python/
├── secure_request_client/           # Main package
│   ├── cli.py                      # CLI entry point and main client
│   ├── crypto.py                   # Cryptographic operations
│   ├── kms_client.py              # KMS client implementation
│   ├── http_client.py             # HTTP client for offer requests
│   ├── lib/                        # Shared libraries (.so files)
│   │   ├── libcddl.so
│   │   └── libsecure_invoke.so
│   └── __init__.py
├── programmatic_examples.py         # Programmatic usage examples
├── sample_offer_request.json      # Sample request payload
├── setup.py                       # Package setup and entry points
├── README.md                      # Detailed documentation
└── QUICKSTART.md                  # This quick start guide
```

## That's It!

You're ready to use Secure Request Client!

- **CLI**: Use `secure-request --help` for all options
- **Programmatic**: See `programmatic_examples.py` for comprehensive examples
- **Testing**: Run `python3 programmatic_examples.py` to verify functionality
- **Documentation**: Check `README.md` for detailed API documentation