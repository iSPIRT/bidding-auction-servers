#!/bin/bash

# Installation script for secure-request CLI tool
set -e

echo "Installing secure-request CLI tool..."

# Navigate to the project directory
cd "$(dirname "$0")"

# Install the wheel package first (contains pre-built shared libraries)
echo "Installing secure_invoke_crypto wheel package (contains pre-built .so files)..."
pip install secure_invoke_crypto-0.1.0-py3-none-any.whl

# Extract shared libraries from the wheel
echo "Extracting shared libraries from wheel..."
python -m zipfile -e secure_invoke_crypto-0.1.0-py3-none-any.whl temp_extract
mkdir -p secure_request_client/lib
cp temp_extract/secure_invoke_crypto/lib/*.so secure_request_client/lib/
rm -rf temp_extract

# Install the CLI tool in development mode
echo "Installing secure-request CLI tool..."
pip install -e .

echo "Installation complete!"
echo ""
echo "To use the CLI tool:"
echo "1. Set the library path: export LD_LIBRARY_PATH=./secure_request_client/lib:\$LD_LIBRARY_PATH"
echo "2. Run: secure-request --help"
echo ""
echo "Example usage:"
echo "export KMS_HOST=https://depa-inferencing-kms.centralindia.cloudapp.azure.com"
echo "export OFFER_HOST=http://20.219.207.27:51052/v1/getbids"
echo "secure-request --kms-host \$KMS_HOST --offer-host \$OFFER_HOST --request-payload sample_offer_request.json --insecure"
