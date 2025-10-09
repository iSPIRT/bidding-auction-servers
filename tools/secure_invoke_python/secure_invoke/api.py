"""Main API for secure invoke operations."""

import json
import logging
from typing import Dict, Any, Optional, List

from .utils.kms_client import KMSClient, HpkeKeyset
from .utils.payload import PayloadPackager
from .utils.http_client import BFEClient
from .utils.batch import BatchProcessor, BatchLogger


logger = logging.getLogger(__name__)


class SecureInvoke:
    """
    Main API for secure invoke operations.
    
    This class provides both single request and batch processing capabilities
    for interacting with BFE (Buyer Front End) services.
    """
    
    def __init__(
        self,
        kms_url: str,
        bfe_host: str,
        client_ip: str = '0.0.0.0',
        insecure: bool = False,
        verbose: bool = False
    ):
        """
        Initialize SecureInvoke client.
        
        Args:
            kms_url: KMS service URL for key fetching
            bfe_host: BFE host address (e.g., "4.187.223.221:51052")
            client_ip: Client IP address
            insecure: Disable SSL verification
            verbose: Enable verbose logging
        """
        self.kms_url = kms_url
        self.bfe_host = bfe_host
        self.client_ip = client_ip
        self.insecure = insecure
        self.verbose = verbose
        
        # Will be set after fetching keys
        self.keyset: Optional[HpkeKeyset] = None
        self.packager: Optional[PayloadPackager] = None
        
        # Configure logging
        if verbose:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
    
    def fetch_keys(self, key_index: int = 0) -> HpkeKeyset:
        """
        Fetch encryption keys from KMS.
        
        Args:
            key_index: Index of key to use (default: 0, first key)
            
        Returns:
            HpkeKeyset
        """
        logger.info(f"Fetching keys from KMS: {self.kms_url}")
        
        kms_client = KMSClient(self.kms_url, insecure=self.insecure)
        keysets = kms_client.fetch_keys()
        
        if not keysets:
            raise RuntimeError("No keys returned from KMS")
        
        if key_index >= len(keysets):
            raise ValueError(
                f"Key index {key_index} out of range (available: {len(keysets)})"
            )
        
        self.keyset = keysets[key_index]
        self.packager = PayloadPackager(self.keyset)
        
        logger.info(f"Using key with ID: {self.keyset.key_id}")
        return self.keyset
    
    def set_keyset(self, keyset: HpkeKeyset):
        """
        Manually set keyset instead of fetching from KMS.
        
        Args:
            keyset: HpkeKeyset to use
        """
        self.keyset = keyset
        self.packager = PayloadPackager(keyset)
        logger.info(f"Using manually set key with ID: {keyset.key_id}")
    
    def invoke(
        self,
        request: Dict[str, Any],
        enable_debug_reporting: bool = False,
        enable_unlimited_egress: bool = False
    ) -> Dict[str, Any]:
        """
        Send a single encrypted request to BFE and return decrypted response.
        
        Args:
            request: Request payload as dict
            enable_debug_reporting: Enable debug reporting
            enable_unlimited_egress: Enable unlimited egress
            
        Returns:
            Decrypted response as dict
        """
        if not self.keyset or not self.packager:
            raise RuntimeError("Keys not set. Call fetch_keys() first.")
        
        logger.info("Starting secure invoke operation")
        
        # Package request
        logger.info("Packaging request...")
        packaged_request = self.packager.package_get_bids_request(
            request,
            enable_debug_reporting=enable_debug_reporting,
            enable_unlimited_egress=enable_unlimited_egress
        )
        
        # Send request
        logger.info("Sending request to BFE...")
        with BFEClient(
            host=self.bfe_host,
            client_ip=self.client_ip,
            insecure=self.insecure,
            verbose=self.verbose
        ) as client:
            response_json = client.send_request(packaged_request)
        
        # Unpackage response
        logger.info("Unpackaging response...")
        response = self.packager.unpackage_get_bids_response(response_json)
        
        logger.info("Secure invoke operation completed successfully")
        return response
    
    def invoke_from_file(
        self,
        file_path: str,
        enable_debug_reporting: bool = False,
        enable_unlimited_egress: bool = False
    ) -> Dict[str, Any]:
        """
        Send request from JSON file.
        
        Args:
            file_path: Path to JSON request file
            enable_debug_reporting: Enable debug reporting
            enable_unlimited_egress: Enable unlimited egress
            
        Returns:
            Decrypted response as dict
        """
        logger.info(f"Loading request from {file_path}")
        request = PayloadPackager.load_json_request(file_path)
        
        return self.invoke(
            request,
            enable_debug_reporting=enable_debug_reporting,
            enable_unlimited_egress=enable_unlimited_egress
        )
    
    def encrypt_only(
        self,
        request: Dict[str, Any],
        enable_debug_reporting: bool = False,
        enable_unlimited_egress: bool = False
    ) -> Dict[str, Any]:
        """
        Only encrypt request without sending to BFE.
        
        Args:
            request: Request payload as dict
            enable_debug_reporting: Enable debug reporting
            enable_unlimited_egress: Enable unlimited egress
            
        Returns:
            Packaged request with requestCiphertext and keyId
        """
        if not self.keyset or not self.packager:
            raise RuntimeError("Keys not set. Call fetch_keys() first.")
        
        return self.packager.package_get_bids_request(
            request,
            enable_debug_reporting=enable_debug_reporting,
            enable_unlimited_egress=enable_unlimited_egress
        )
    
    def batch_invoke(
        self,
        batch_file: str,
        max_retries: int = 3,
        max_concurrent: int = 5,
        retry_delay_ms: int = 500,
        success_log: str = 'success_log.jsonl',
        failure_log: str = 'failure_log.jsonl'
    ) -> Dict[str, Any]:
        """
        Process multiple requests from JSONL file.
        
        Args:
            batch_file: Path to JSONL file with batch requests
            max_retries: Maximum retry attempts per request
            max_concurrent: Maximum concurrent requests
            retry_delay_ms: Delay between retries in milliseconds
            success_log: Path to success log file
            failure_log: Path to failure log file
            
        Returns:
            Summary statistics
        """
        if not self.keyset:
            raise RuntimeError("Keys not set. Call fetch_keys() first.")
        
        logger.info(f"Starting batch processing from {batch_file}")
        
        # Create batch processor
        processor = BatchProcessor(
            keyset=self.keyset,
            host=self.bfe_host,
            max_retries=max_retries,
            max_concurrent=max_concurrent,
            retry_delay_ms=retry_delay_ms,
            client_ip=self.client_ip,
            insecure=self.insecure,
            verbose=self.verbose
        )
        
        # Create logger
        batch_logger = BatchLogger(success_log, failure_log)
        
        # Process batch
        summary = processor.process_batch(
            batch_file=batch_file,
            success_callback=batch_logger.log_success,
            failure_callback=batch_logger.log_failure
        )
        
        logger.info(f"Batch results logged to {success_log} and {failure_log}")
        return summary


def create_client(
    kms_url: str,
    bfe_host: str,
    client_ip: str = '0.0.0.0',
    insecure: bool = False,
    verbose: bool = False
) -> SecureInvoke:
    """
    Factory function to create a SecureInvoke client.
    
    Args:
        kms_url: KMS service URL
        bfe_host: BFE host address
        client_ip: Client IP address
        insecure: Disable SSL verification
        verbose: Enable verbose logging
        
    Returns:
        SecureInvoke client
    """
    return SecureInvoke(
        kms_url=kms_url,
        bfe_host=bfe_host,
        client_ip=client_ip,
        insecure=insecure,
        verbose=verbose
    )

