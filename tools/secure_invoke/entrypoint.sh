#!/bin/bassh
set -e

# This script converts environment variables to command-line arguments
# for the secure_invoke binary

# Required parameters
ARGS=""

# Add target service
if [ -n "${TARGET_SERVICE}" ]; then
  ARGS="$ARGS -target_service=${TARGET_SERVICE}"
fi

# Add host address
if [ -n "${BUYER_HOST}" ]; then
  ARGS="$ARGS -host_addr=${BUYER_HOST}"
fi

# Add public key and key ID fetching logic if KMS_HOST is provided
if [ -n "${KMS_HOST}" ]; then
  echo "Fetching public key from KMS_HOST: ${KMS_HOST}"
  # Call curl to get key information
  LIVE_KEYS=$(curl -s -k ${KMS_HOST}/listpubkeys)
  if [ $? -eq 0 ] && [ -n "$LIVE_KEYS" ]; then
    # Extract public key and key ID using jq if available
    if command -v jq >/dev/null 2>&1; then
      PUBLIC_KEY=$(echo $LIVE_KEYS | jq -r '.keys[0].key')
      KEY_ID=$(echo $LIVE_KEYS | jq -r '.keys[0].id')
      echo "Successfully fetched key ID: ${KEY_ID}"
    else
      # Fallback method if jq is not available
      # This is simplified and may need adjustment based on actual response format
      PUBLIC_KEY=$(echo $LIVE_KEYS | grep -o '"key":"[^"]*"' | head -1 | cut -d'"' -f4)
      KEY_ID=$(echo $LIVE_KEYS | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
      echo "Extracted key ID using grep: ${KEY_ID}"
    fi
    
    # Add extracted values to arguments if they exist
    if [ -n "$PUBLIC_KEY" ] && [ -n "$KEY_ID" ]; then
      ARGS="$ARGS -public_key=${PUBLIC_KEY} -key_id=${KEY_ID}"
    else
      echo "Warning: Could not extract public key or key ID from KMS response"
    fi
  else
    echo "Warning: Failed to fetch public keys from ${KMS_HOST}"
  fi

  # Also add KMS host as an argument if needed by the binary
  #ARGS="$ARGS -kms_host=${KMS_HOST}"
fi

# Add request path 
if [ -n "${REQUEST_PATH}" ]; then
  ARGS="$ARGS -input_file=/${REQUEST_PATH}"
fi

# Add operation type if needed
if [ -n "${OPERATION}" ]; then
  ARGS="$ARGS -op=${OPERATION}"
fi

# Add fixed client IP (could be configurable as well)
ARGS="$ARGS -client_ip=127.0.0.1"

# Add insecure flag when accessing local services
ARGS="$ARGS -insecure"

# Set number of retries if specified
if [ -n "${RETRIES}" ]; then
  i=1
  while [ $i -le ${RETRIES} ]; do
    echo "Running attempt $i of ${RETRIES}..."
    # Execute the command with all arguments
    echo "Executing: /secure_invoke/invoke $ARGS $@"
    exec /secure_invoke/invoke $ARGS "$@"
    # Add a small delay between retries
    [ $i -lt ${RETRIES} ] && sleep 1
i=$((i + 1))
  done
else
  # No retries, just run once
  echo "Executing: /secure_invoke/invoke $ARGS $@"
  exec /secure_invoke/invoke $ARGS "$@"
fi