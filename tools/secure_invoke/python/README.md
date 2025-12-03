# Secure Request Client

A Python tool for secure communication with Privacy Sandbox offer request systems. Supports both CLI and programmatic usage.

## Quick Start

```bash
# 1. Navigate to the project directory
cd bidding-auction-servers/tools/secure_invoke/python

# 2. Create and activate your python virtual environment
python3 -m venv <venv_name> # e.g. python3 -m venv venv
source <venv_name>/bin/activate # e.g. source venv/bin/activate

# 3. Install the CLI tool
pip install secure_request-<version_number>-py3-none-any.whl  # (recommended) install directly from the wheel file released 
# alternatively, install from this directory
pip install .  # or `pip install -e .` for development

# 4. Set up library path inside your python virtual environment
export LD_LIBRARY_PATH=$(python -c "import secure_request_client; import os; print(os.path.join(os.path.dirname(secure_request_client.__file__), 'lib'))"):$LD_LIBRARY_PATH

# 5. Set up environment variables for KMS and Offer service hosts
export KMS_HOST=https://<kms_host_url>  # eg. export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com
export OFFER_HOST=http://<offer_host_ip>:<port>/v1/getbids  # eg. export OFFER_HOST=http://20.219.207.27:51052/v1/getbids

# 6. Test the CLI command
secure-request --help

secure-request --kms-host $KMS_HOST --offer-host $OFFER_HOST --request-payload sample_offer_request.json --insecure
```

## Features

- **CLI Interface**: Command-line tool with full parameter support
- **Programmatic API**: Python library for integration
- **SSL Support**: Certificate-based authentication
- **Flexible Input**: JSON files or direct JSON payloads
- **Retry Logic**: Configurable retry attempts
- **Verbose Mode**: Detailed debugging output


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

# Using direct JSON string
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"test","biddingSignalsKeys":["123"]}]},"seller":"test.com","publisherName":"test.com"}' \
  --insecure

# With client certificates
secure-request \
  --kms-host $KMS_HOST \
  --offer-host $OFFER_HOST \
  --request-payload sample_offer_request.json \
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
from secure_request_client.cli import SecureRequestClient, SecureRequestConfig

config = SecureRequestConfig()
config.kms_host = "https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
config.offer_host = "http://20.219.207.27:51052/v1/getbids"
config.insecure = True
config.request_payload = '{"client_type":"CLIENT_TYPE_BROWSER","buyerInput":{"interestGroups":[{"name":"Rajni Kausalya","biddingSignalsKeys":["9999999990"],"userBiddingSignals":"{\\"age\\":29,\\"average_amount\\":10000}"}]},"seller":"irctc.com","publisherName":"irctc.com"}'

# Run the tool
client = SecureRequestClient(config)
success = client.run()
```

## Testing

```bash
# Run the various examples (uncomment the examples you want to test) in programmatic_examples.py
python3 programmatic_examples.py
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
├── programmatic_examples.py       # Programmatic usage examples
├── sample_offer_request.json    # Sample request file
├── setup.py                     # Package setup
├── README.md                    # Detailed documentation
└── QUICKSTART.md                # Quick start guide
```

## Configuration

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--kms-host` | KMS service host (required) | `https://kms.example.com` |
| `--offer-host` | Offer service host (required) | `http://offer.example.com:51052` |
| `--request-payload` | JSON file or direct JSON (required) | `request.json` or `'{"data":"value"}'` |
| `--insecure` | Disable SSL verification | Flag |
| `--ca-cert` | CA certificate file (optional) | `ca.crt` |
| `--client-cert` | Client certificate file (required) | `client.crt` |
| `--client-key` | Client private key file (required) | `client.key` |
| `--headers` | Custom HTTP headers (optional) | `'{"Auth":"token"}'` |
| `--retries` | Number of retry attempts (optional) | `3` |
| `--enable-verbose` | Enable verbose output | Flag |

## Examples

- **CLI Examples**: See `QUICKSTART.md`
- **Programmatic Examples**: Run `python3 programmatic_examples.py`

## Troubleshooting

- **SSL Certificate Errors**: Use `--insecure` for testing or provide proper certificates
- **Library Path Issues**: Ensure `LD_LIBRARY_PATH` is set correctly
- **Connection Errors**: Check host URLs and network connectivity
- **JSON Parsing Errors**: Validate your JSON payload format
