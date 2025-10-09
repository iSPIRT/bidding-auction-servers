"""Batch processing for multiple requests."""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict

from .kms_client import HpkeKeyset
from .payload import PayloadPackager
from .http_client import BFEClient


logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Result of a batch request."""
    request_id: Any
    success: bool
    attempts: int
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class BatchProcessor:
    """Process multiple requests in batch with retries and concurrency."""
    
    def __init__(
        self,
        keyset: HpkeKeyset,
        host: str,
        max_retries: int = 3,
        max_concurrent: int = 5,
        retry_delay_ms: int = 500,
        client_ip: str = '0.0.0.0',
        insecure: bool = False,
        verbose: bool = False
    ):
        """
        Initialize batch processor.
        
        Args:
            keyset: HpkeKeyset for encryption
            host: BFE host address
            max_retries: Maximum retry attempts per request
            max_concurrent: Maximum concurrent requests
            retry_delay_ms: Delay between retries in milliseconds
            client_ip: Client IP for requests
            insecure: Disable SSL verification
            verbose: Enable verbose logging
        """
        self.keyset = keyset
        self.host = host
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self.retry_delay_ms = retry_delay_ms
        self.client_ip = client_ip
        self.insecure = insecure
        self.verbose = verbose
        
        self.packager = PayloadPackager(keyset)
        self.results = []
    
    def process_batch(
        self,
        batch_file: str,
        success_callback: Optional[Callable[[BatchResult], None]] = None,
        failure_callback: Optional[Callable[[BatchResult], None]] = None
    ) -> Dict[str, Any]:
        """
        Process batch requests from JSONL file.
        
        Args:
            batch_file: Path to JSONL file with batch requests
            success_callback: Callback for successful requests
            failure_callback: Callback for failed requests
            
        Returns:
            Summary statistics
        """
        logger.info(f"Starting batch processing from {batch_file}")
        logger.info(
            f"Config: max_retries={self.max_retries}, "
            f"max_concurrent={self.max_concurrent}, "
            f"retry_delay={self.retry_delay_ms}ms"
        )
        
        # Load batch requests
        requests = list(self.packager.load_jsonl_batch(batch_file))
        total_requests = len(requests)
        
        if total_requests == 0:
            logger.warning("No valid requests found in batch file")
            return {
                'total': 0,
                'successful': 0,
                'failed': 0,
                'success_rate': 0.0
            }
        
        logger.info(f"Loaded {total_requests} requests")
        
        # Process requests concurrently
        successful = 0
        failed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            # Submit all requests
            future_to_id = {
                executor.submit(
                    self._process_single_request,
                    request_id,
                    request_json
                ): request_id
                for request_id, request_json in requests
            }
            
            # Process completed requests
            for future in as_completed(future_to_id):
                result = future.result()
                
                if result.success:
                    successful += 1
                    logger.info(
                        f"Request {result.request_id} succeeded "
                        f"(attempts: {result.attempts})"
                    )
                    if success_callback:
                        success_callback(result)
                else:
                    failed += 1
                    logger.error(
                        f"Request {result.request_id} failed: {result.error} "
                        f"(attempts: {result.attempts})"
                    )
                    if failure_callback:
                        failure_callback(result)
                
                # Log progress
                completed = successful + failed
                logger.info(
                    f"Progress: {completed}/{total_requests} "
                    f"({successful} success, {failed} failed)"
                )
        
        # Calculate statistics
        success_rate = (successful / total_requests * 100) if total_requests > 0 else 0
        
        summary = {
            'total': total_requests,
            'successful': successful,
            'failed': failed,
            'success_rate': success_rate
        }
        
        logger.info(f"Batch processing complete: {summary}")
        return summary
    
    def _process_single_request(
        self,
        request_id: Any,
        request_json: Dict[str, Any]
    ) -> BatchResult:
        """
        Process a single request with retries.
        
        Args:
            request_id: Request identifier
            request_json: Request payload
            
        Returns:
            BatchResult
        """
        attempts = 0
        last_error = None
        
        for attempt in range(1, self.max_retries + 1):
            attempts = attempt
            
            try:
                # Package request
                packaged_request = self.packager.package_get_bids_request(
                    request_json
                )
                
                # Send request
                with BFEClient(
                    host=self.host,
                    client_ip=self.client_ip,
                    insecure=self.insecure,
                    verbose=self.verbose
                ) as client:
                    response_json = client.send_request(packaged_request)
                
                # Unpackage response
                response = self.packager.unpackage_get_bids_response(response_json)
                
                return BatchResult(
                    request_id=request_id,
                    success=True,
                    attempts=attempts,
                    response=response
                )
            
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"Request {request_id} attempt {attempt} failed: {e}"
                )
                
                # Retry with delay (except on last attempt)
                if attempt < self.max_retries:
                    delay_sec = self.retry_delay_ms / 1000.0
                    time.sleep(delay_sec)
        
        # All attempts failed
        return BatchResult(
            request_id=request_id,
            success=False,
            attempts=attempts,
            error=last_error
        )


class BatchLogger:
    """Logger for batch results to JSONL files."""
    
    def __init__(self, success_log: str, failure_log: str):
        """
        Initialize batch logger.
        
        Args:
            success_log: Path to success log file
            failure_log: Path to failure log file
        """
        self.success_log = success_log
        self.failure_log = failure_log
    
    def log_success(self, result: BatchResult):
        """Log successful result."""
        self._append_jsonl(self.success_log, {
            'id': result.request_id,
            'attempts': result.attempts,
            'response': result.response
        })
    
    def log_failure(self, result: BatchResult):
        """Log failed result."""
        self._append_jsonl(self.failure_log, {
            'id': result.request_id,
            'attempts': result.attempts,
            'error': result.error
        })
    
    @staticmethod
    def _append_jsonl(file_path: str, data: Dict[str, Any]):
        """Append a JSON line to file."""
        with open(file_path, 'a') as f:
            f.write(json.dumps(data) + '\n')

