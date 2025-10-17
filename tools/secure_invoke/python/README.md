# Secure Request Client

A Python tool for secure communication with Privacy Sandbox offer request systems. Supports both CLI and programmatic usage.

## Quick Start

```bash
# 1. Navigate to the project directory
cd bidding-auction-servers/tools/secure_invoke/python

# 2. Create and activate your python virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Run the automated installation script inside your python virtual environment
./install.sh

# 4. Set up library path inside your python virtual environment
export LD_LIBRARY_PATH=./secure_request_client/lib:$LD_LIBRARY_PATH

# 5. Set up environment variables
export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export OFFER_HOST=http://20.219.207.27:51052/v1/getbids

# 6. Use the CLI command
secure-request --kms-host $KMS_HOST --offer-host $OFFER_HOST --request-payload sample_offer_request.json --insecure
```

## Features

- **CLI Interface**: Command-line tool with full parameter support
- **Programmatic API**: Python library for integration
- **SSL Support**: Certificate-based authentication
- **Flexible Input**: JSON files or direct JSON payloads
- **Retry Logic**: Configurable retry attempts
- **Verbose Mode**: Detailed debugging output

## Installation

### Quick Installation (Recommended)

```bash
# Navigate to the project directory
cd bidding-auction-servers/tools/secure_invoke/python

# Run the automated installation script
./install.sh
```

### Manual Installation

```bash
# Navigate to the project directory
cd bidding-auction-servers/tools/secure_invoke/python

# Install the wheel package (contains pre-built shared libraries)
pip install secure_invoke_crypto-0.1.0-py3-none-any.whl

# Extract shared libraries from the wheel
python -m zipfile -e secure_invoke_crypto-0.1.0-py3-none-any.whl temp_extract
mkdir -p secure_request_client/lib
cp temp_extract/secure_invoke_crypto/lib/*.so secure_request_client/lib/
rm -rf temp_extract

# Install the CLI tool
pip install -e .

# Set library path
export LD_LIBRARY_PATH=./secure_request_client/lib:$LD_LIBRARY_PATH
```

## Usage

### CLI Usage

```bash
# Set up environment variables
export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export OFFER_HOST=http://20.219.207.27:51052/v1/getbids

# Basic usage with the new CLI command
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --insecure

# With SSL certificates
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --ca-cert ca.crt \
  --client-cert client.crt \
  --client-key client.key

# With custom headers and retries
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
  --headers '{"Authorization": "Bearer token"}' \
  --retries 3 \
  --enable-verbose

# Show help
secure-request --help
```

### Programmatic Usage

```python
from secure_request import SecureRequestClient, SecureRequestConfig

config = SecureRequestConfig()
config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
config.offer_host = "http://4.213.211.238:51052/v1/getbids"
config.insecure = True
config.request_payload = '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"Rajni Kausalya","biddingSignalsKeys":["9999999990"],"userBiddingSignals":"{\\"age\\":29,\\"average_amount\\":10000}"}]},"seller":"irctc.com","publisherName":"irctc.com"}'

# Run the tool
client = SecureRequestClient(config)
success = client.run()
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
secure_invoke/python/
├── secure_request_client/         # Package with CLI and client modules
│   ├── cli.py                    # CLI entry point (merged functionality)
│   ├── crypto.py                 # Crypto functionality
│   ├── kms_client.py            # KMS client
│   ├── http_client.py           # HTTP client
│   └── lib/                      # Shared libraries (.so files)
├── programmatic_example.py       # Programmatic usage examples
├── sample_offer_request.json    # Sample request file
├── setup.py                     # Package setup
├── install.sh                   # Installation script
└── tests/                       # Unit tests
```

## Configuration

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--kms-host` | KMS service host | `https://kms.example.com` |
| `--offer-host` | Offer service host | `http://offer.example.com:51052` |
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