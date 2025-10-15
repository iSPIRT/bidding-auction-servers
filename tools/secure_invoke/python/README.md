# SecureInvoke Tool

A Python tool for secure communication with Privacy Sandbox bidding and auction systems. Supports both CLI and programmatic usage.

## Quick Start

```bash
# 1. Set up environment
cd bidding-auction-servers/tools/secure_invoke/python
python3 -m venv venv
source venv/bin/activate

# 2. Install the wheel
pip install secure_invoke_crypto-0.1.0-py3-none-any.whl

# 3. Extract shared libraries
python -m zipfile -e secure_invoke_crypto-0.1.0-py3-none-any.whl temp_extract
mkdir -p secure_invoke_crypto/lib
cp temp_extract/secure_invoke_crypto/lib/*.so secure_invoke_crypto/lib/
rm -rf temp_extract

# 4. Set up environment
export LD_LIBRARY_PATH=./secure_invoke_crypto/lib:$LD_LIBRARY_PATH
export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export BUYER_HOST=http://4.224.152.16:51052/v1/getbids

# 5. Test minimal command
python3 secure_invoke.py --kms-host $KMS_HOST --buyer-host $BUYER_HOST --request-payload get_bids_request.json --insecure
```

## Features

- **CLI Interface**: Command-line tool with full parameter support
- **Programmatic API**: Python library for integration
- **SSL Support**: Certificate-based authentication
- **Flexible Input**: JSON files or direct JSON payloads
- **Retry Logic**: Configurable retry attempts
- **Verbose Mode**: Detailed debugging output

## Installation

```bash
# Navigate to the project directory
cd bidding-auction-servers/tools/secure_invoke/python

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the wheel package
pip install secure_invoke_crypto-0.1.0-py3-none-any.whl

# Extract shared libraries from the wheel
python -m zipfile -e secure_invoke_crypto-0.1.0-py3-none-any.whl temp_extract
mkdir -p secure_invoke_crypto/lib
cp temp_extract/secure_invoke_crypto/lib/*.so secure_invoke_crypto/lib/
rm -rf temp_extract

# Set library path
export LD_LIBRARY_PATH=./secure_invoke_crypto/lib:$LD_LIBRARY_PATH
```

## Usage

### CLI Usage

```bash
# Set up environment variables
export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export BUYER_HOST=http://4.224.152.16:51052/v1/getbids

# Basic usage (minimal test command)
python3 secure_invoke.py --kms-host $KMS_HOST --buyer-host $BUYER_HOST --request-payload get_bids_request.json --insecure

# With SSL certificates
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --ca-cert ca.crt \
  --client-cert client.crt \
  --client-key client.key

# With custom headers and retries
python3 secure_invoke.py \
  --kms-host $KMS_HOST \
  --buyer-host $BUYER_HOST \
  --request-payload get_bids_request.json \
  --headers '{"Authorization": "Bearer token"}' \
  --retries 3 \
  --enable-verbose
```

### Programmatic Usage

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

## Testing

```bash
# Run unit tests
python3 tests/run_tests.py

# Run specific test modules
python3 tests/run_tests.py test_config
python3 tests/run_tests.py test_http_client

# Run programmatic examples
python3 programmatic_example.py
```

## Project Structure

```
secure_invoke_python/
├── secure_invoke.py              # Main CLI tool
├── programmatic_example.py       # Programmatic usage examples
├── get_bids_request.json         # Sample request file
├── tests/                        # Unit tests
│   ├── test_config.py
│   ├── test_http_client.py
│   ├── test_kms_client.py
│   └── run_tests.py
└── secure_invoke_crypto/         # Crypto library
    ├── http_client.py
    ├── kms_client.py
    └── lib/                      # Shared libraries
```

## Configuration

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--kms-host` | KMS service host | `https://kms.example.com` |
| `--buyer-host` | Buyer service host | `http://buyer.example.com:51052` |
| `--request-payload` | JSON file or direct JSON | `request.json` or `'{"data":"value"}'` |
| `--insecure` | Disable SSL verification | Flag |
| `--ca-cert` | CA certificate file | `ca.crt` |
| `--client-cert` | Client certificate file | `client.crt` |
| `--client-key` | Client private key file | `client.key` |
| `--headers` | Custom HTTP headers | `'{"Auth":"token"}'` |
| `--retries` | Number of retry attempts | `3` |
| `--enable-verbose` | Enable verbose output | Flag |

## Examples

- **CLI Examples**: See `QUICKSTART.md`
- **Programmatic Examples**: Run `python3 programmatic_example.py`
- **Test Examples**: See `tests/` directory

## Troubleshooting

- **SSL Certificate Errors**: Use `--insecure` for testing or provide proper certificates
- **Library Path Issues**: Ensure `LD_LIBRARY_PATH` is set correctly
- **Connection Errors**: Check host URLs and network connectivity
- **JSON Parsing Errors**: Validate your JSON payload format