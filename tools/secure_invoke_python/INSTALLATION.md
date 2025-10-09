# Installation Guide

## Quick Install

### From Source (Recommended for Development)

```bash
cd /root/bidding-auction-servers/tools/secure_invoke_python

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package in editable mode
pip install -e .
```

### From PyPI (When Published)

```bash
pip install secure-invoke
```

## Verification

After installation, verify the package is working:

```bash
# Check CLI is available
secure-invoke --help

# Run test suite
python3 test_basic.py
```

All tests should pass with output:
```
============================================================
Testing Secure Invoke Python SDK
============================================================
Testing imports...
✓ All imports successful

Testing proto compilation...
✓ Proto compilation successful

Testing keyset creation...
✓ Keyset created: key_id=21

Testing encryption...
✓ Encryption/decryption successful

Testing payload packaging...
✓ Payload packaging successful
  - Ciphertext length: 116 chars
  - Key ID: 64

============================================================
Test Summary
============================================================
Imports                        ✓ PASS
Proto Compilation              ✓ PASS
Keyset Creation                ✓ PASS
Encryption                     ✓ PASS
Payload Packaging              ✓ PASS
============================================================
Total: 5/5 tests passed

🎉 All tests passed!
```

## Dependencies

The package has the following dependencies (automatically installed):

- `pyhpke>=0.3.0` - HPKE encryption
- `requests>=2.31.0` - HTTP client
- `protobuf>=4.23.0` - Protocol Buffers
- `grpcio>=1.54.0` - gRPC support
- `grpcio-tools>=1.54.0` - Proto compilation tools
- `cryptography>=41.0.0` - Cryptographic primitives

## System Requirements

- Python 3.8 or higher
- Linux, macOS, or Windows
- Internet connection (for KMS access)

## Troubleshooting

### Proto Compilation Errors

If you see proto compilation errors during installation:

```bash
# Manually compile protos
cd secure_invoke/protos
python3 -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. *.proto

# Fix imports
sed -i 's/^import /from . import /' *_pb2*.py
```

### Import Errors

If you get import errors:

```bash
# Reinstall in editable mode
pip uninstall secure-invoke
pip install -e .
```

### SSL Certificate Errors

For testing with self-signed certificates, use the `--insecure` flag:

```bash
secure-invoke invoke --insecure ...
```

## Development Setup

For development, install additional tools:

```bash
pip install pytest black flake8 mypy
```

Run linters:

```bash
black secure_invoke/
flake8 secure_invoke/
mypy secure_invoke/
```

## Docker Alternative

If you prefer using the existing Docker image:

```bash
docker run --rm --network host \
  -v /root/bidding-auction-servers:/data \
  -e TARGET_SERVICE=bfe \
  -e BUYER_HOST=4.187.179.194:51052 \
  -e KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com \
  -e REQUEST_PATH=/data/get_bids_request.json \
  -e OPERATION=invoke \
  -e INSECURE=true \
  -e ENABLE_VERBOSE=true \
  ispirt.azurecr.io/depa-inferencing/tools/secure_invoke:4.8.0.2
```

However, the Python SDK offers:
- ✅ Faster startup (no Docker overhead)
- ✅ Better integration with Python code
- ✅ Easier to customize and extend
- ✅ Simpler installation process

