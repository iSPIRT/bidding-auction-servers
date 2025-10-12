# SecureInvoke Crypto Python Package

This package provides Python bindings for the SecureInvoke cryptographic library used in Privacy Sandbox bidding and auction systems.

## Installation

### From Source

1. Make sure you have the required build tools:
   ```bash
   pip install build setuptools wheel
   ```

2. Prepare the package directory:
   ```bash
   cd python/
   chmod 755 secure_invoke_crypto/lib
   cd secure_invoke_crypto/lib && rm -rf *
   cd ../..
   ```

3. Build and install the package:
   ```bash
   pip install .
   ```

   Or for development:
   ```bash
   pip install -e .
   ```

### What happens during installation

The `setup.py` automatically:
1. Uses Bazel to build the C++ shared library (`libsecure_invoke.so`)
2. Copies the built library and dependencies to the package
3. Installs the Python bindings

**Important**: Before installing this package, you must first build the main bidding-auction-servers repository to generate `libcddl.so`, as it has dependencies on dataplane modules:

```bash
# From the repository root
./production/packaging/build_and_test_all_in_docker --service-path buyer_frontend_service --service-path bidding_service  --instance local --platform gcp --build-flavor non_prod --gcp-skip-image-upload --no-tests --no-precommit 
```

This ensures `libcddl.so` is available at `bazel-bin/external/cddl_lib/libcddl.so` for the Python package to copy.

No additional build scripts are needed!

## Usage

```python
from secure_invoke_crypto import BiddingCryptoClient

# Initialize client with public_key & key_id
client = BiddingCryptoClient(
    public_key="your_base64_public_key", 
    key_id="your_key_id" /*"64"*/
)

# Encrypt a bid request
bid_request = {
    "client_type": "CLIENT_TYPE_BROWSER",
    "buyerInput": {
        "interestGroups": [...]
    },
    # ... your bid request data
}

result = client.encrypt_bid_request(bid_request)

# Send result.encrypted_data to your server via HTTP
# ...encrypted_data = result.encrypted_data


# Decrypt the server response
decrypted = client.decrypt_bid_response(
    server_response_ciphertext, 
    result.secret
)
```

## Testing

Set up the library path first:
```bash
export LD_LIBRARY_PATH=./secure_invoke_crypto/lib:$LD_LIBRARY_PATH
```

### Sample Python Test Script

Run the Python end-to-end test:
```bash
PYTHONPATH=. python3 secure_invoke_crypto/tests/test_encrypt_http.py
```

Or encrypt-only mode:
```bash
PYTHONPATH=. python3 secure_invoke_crypto/tests/test_encrypt_http.py --encrypt-only
```

### Sample C++ Test code

1. Compile the C++ test:
   ```bash
   g++ -o test_encrypt_http secure_invoke_crypto/tests/test_encrypt_http.cpp \
       -L./secure_invoke_crypto/lib -lsecure_invoke -lcddl -lcurl \
       -I./secure_invoke_crypto/src -Wl,-rpath,./secure_invoke_crypto/lib
   ```

2. Run the C++ test:
   ```bash
   ./test_encrypt_http
   ```
   
   Or encrypt-only mode:
   ```bash
   ./test_encrypt_http --encrypt-only
   ```

## Package Contents

- `secure_invoke_crypto/crypto.py` - Main Python API
- `secure_invoke_crypto/src/` - C++ source files
- `secure_invoke_crypto/lib/` - Built shared libraries (after installation)
- `secure_invoke_crypto/tests/` - Test files

## Requirements

- Python 3.8+
- Linux (with Bazel build tools)
- requests library for HTTP functionality

## Building Wheel Package

To create a distributable wheel file:

1. Install wheel package:
   ```bash
   pip install wheel
   ```

2. Clean and create distribution directory:
   ```bash
   rm -rf dist
   mkdir -p dist
   ```

3. Build the wheel:
   ```bash
   python setup.py bdist_wheel --dist-dir dist
   ```

This will create a `.whl` file in the `dist/` directory that can be installed with `pip install dist/*.whl` or distributed to other systems.
