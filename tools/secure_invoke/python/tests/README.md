# SecureInvoke Unit Tests

This directory contains comprehensive unit tests for the SecureRequestClient tool, organized by component.

## Test Structure

### `test_config.py`
Tests for configuration validation and parameter handling:
- Valid configuration with file and JSON payloads
- Missing required parameters
- SSL certificate requirements
- File path detection logic

### `test_kms_client.py`
Tests for KMS (Key Management Service) client functionality:
- Client initialization with various parameters
- Public key fetching and validation
- Error handling (connection, timeout, HTTP errors)
- Key normalization and validation

### `test_http_client.py`
Tests for HTTP client functionality:
- Client initialization with SSL configuration
- Bid request sending with retry logic
- Key ID handling in headers
- Error handling and response processing

### `test_request_loading.py`
Tests for request data loading:
- JSON file loading
- JSONL file loading (first line only)
- Direct JSON payload parsing
- Wrapped request handling
- File path detection logic

### `test_crypto_operations.py`
Tests for cryptographic operations:
- Request encryption and response decryption
- Request data validation
- Error handling for crypto operations

### `test_integration.py`
Integration tests for the complete pipeline:
- Full end-to-end workflow
- Component interaction testing
- Error propagation testing
- Success and failure scenarios

## Running Tests

### Run All Tests
```bash
cd bidding-auction-servers/tools/secure_invoke/python
python3 tests/run_tests.py
```

### Run Specific Test Module
```bash
python3 tests/run_tests.py test_config
python3 tests/run_tests.py test_kms_client
python3 tests/run_tests.py test_http_client
python3 tests/run_tests.py test_request_loading
python3 tests/run_tests.py test_crypto_operations
python3 tests/run_tests.py test_integration
```

### Run Individual Test Files
```bash
python3 tests/test_config.py
python3 tests/test_kms_client.py
python3 tests/test_http_client.py
python3 tests/test_request_loading.py
python3 tests/test_crypto_operations.py
python3 tests/test_integration.py
```

## Test Coverage

The tests cover:

1. **Configuration Management**
   - Parameter validation
   - SSL certificate requirements
   - File vs JSON payload detection

2. **KMS Integration**
   - Public key fetching
   - Error handling
   - Key validation

3. **HTTP Communication**
   - Request sending with retries
   - SSL configuration
   - Response handling

4. **Data Processing**
   - Request loading from files and JSON
   - Data validation
   - Format conversion

5. **Cryptographic Operations**
   - Encryption/decryption
   - Data validation
   - Error handling

6. **End-to-End Pipeline**
   - Complete workflow testing
   - Component integration
   - Error propagation

## Mocking Strategy

The tests use extensive mocking to:
- Isolate components for unit testing
- Simulate external service responses
- Test error conditions without external dependencies
- Ensure fast test execution

## Dependencies

The tests require:
- `unittest` (built-in)
- `unittest.mock` (built-in)
- `tempfile` (built-in)
- `json` (built-in)
- `os`, `sys` (built-in)

No external testing frameworks are required.
