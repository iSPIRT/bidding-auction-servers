#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
  ARGS="$ARGS -input_file=${REQUEST_PATH}"
fi

# Add fixed client IP (could be configurable as well)
ARGS="$ARGS -client_ip=127.0.0.1"

# Add insecure flag when accessing local services
if [ -n "${INSECURE}" ] && [ "${INSECURE}" = "true" ] ; then
  ARGS="$ARGS -insecure=${INSECURE}"
fi

# Add additional headers if provided
if [ -n "${HEADERS}" ]; then
  ARGS="$ARGS -headers=${HEADERS}"
fi

# Add cacert, client_cert, and client_key if they are set
if [ -n "${CLIENT_KEY}" ]; then
  ARGS="$ARGS -client_key=${CLIENT_KEY}"
fi
if [ -n "${CLIENT_CERT}" ]; then
  ARGS="$ARGS -client_cert=${CLIENT_CERT}"
fi
if [ -n "${CA_CERT}" ]; then
  ARGS="$ARGS -ca_cert=${CA_CERT}"
fi
# echo "Arguments to be passed to secure_invoke: $ARGS"
echo "print all args here: $ARGS"

if [ -n "${ENABLE_VERBOSE}" ]; then
  # If ENABLE_CURL_DEBUG is set, add the debug flag
  ARGS="$ARGS -enable_verbose=${ENABLE_VERBOSE}"
fi

# Add operation type if needed
if [ -n "${OPERATION}" ]; then
  ARGS="$ARGS -op=${OPERATION}"
fi
# If operation is batch_invoke, handle batch processing
if [ "${OPERATION}" = "batch_invoke" ]; then

  ARGS="$ARGS -batch_file=${REQUEST_PATH}"
  # Extract directory from BATCH_FILE to store success and failure logs
  BATCH_FILE_DIR=$(dirname "${REQUEST_PATH}")
  ARGS="$ARGS -max_concurrent_requests=${MAX_CONCURRENT_REQUESTS:-5}"
  ARGS="$ARGS -max_retries=${MAX_RETRIES:-3}"
  ARGS="$ARGS -retry_delay_ms=${RETRY_DELAY_MS:-500}"
  # Set paths for success and failure logs
  ARGS="$ARGS -failure_log_path=${BATCH_FILE_DIR}/failure_log.jsonl"
  ARGS="$ARGS -success_log_path=${BATCH_FILE_DIR}/success_log.jsonl"
  echo "Failure log path: ${BATCH_FILE_DIR}/failure_log.jsonl"
  echo "Success log path: ${BATCH_FILE_DIR}/success_log.jsonl"
  echo "Executing: /secure_invoke/invoke $ARGS $@"
  exec /secure_invoke/invoke $ARGS "$@"
# Single request handling
else
  # Set number of retries if provided
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
fi
