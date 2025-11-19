"""
Scanner Instance Manager

Optimized manager for ZAP scanner instances with connection pooling,
context management, and efficient resource usage for concurrent scans.

Key improvements:
1. Connection pooling - Reuses persistent ZAP connection
2. Context isolation - Each scan gets its own ZAP context
3. Concurrent scan support - Thread-safe for multiple workers
4. Resource efficiency - No unnecessary start/stop cycles
"""

from typing import Optional, Dict
from threading import Lock
import time
from app.services.zap_scanner import ZAPScanner
from app.utils.logger import logger
from zapv2 import ZAPv2
from app.core.config import ZAPConfig


class ScannerInstanceManager:
    """
    Manages ZAP scanner connections with efficient resource pooling.

    Architecture:
    - Single persistent ZAP connection pool
    - Per-scan context isolation for concurrent operations
    - Thread-safe with lock protection
    - Automatic health checking and reconnection
    """

    _instance: Optional["ScannerInstanceManager"] = None
    _lock = Lock()

    def __init__(self):
        """Initialize the scanner manager with connection pool"""
        self._zap_client: Optional[ZAPv2] = None
        self._scanner: Optional[ZAPScanner] = None
        self._connection_lock = Lock()
        self._scan_contexts: Dict[int, str] = {}  # scan_id -> context_name
        self._last_health_check = 0
        self._health_check_interval = 30  # seconds
        self._initialized = False

    @classmethod
    def get_instance(cls) -> "ScannerInstanceManager":
        """Get singleton instance with thread safety"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _validate_api_key(self) -> None:
        """
        SECURITY: Validate that ZAP API key is properly configured.
        Prevents running ZAP without authentication which would expose it as a public proxy.
        """
        api_key = ZAPConfig.ZAP_API_KEY

        # Check if API key is set
        if not api_key:
            raise ValueError(
                "SECURITY ERROR: ZAP_API_KEY is not set. "
                "Running ZAP without an API key exposes it as a public proxy for attackers. "
                "Please set ZAP_API_KEY in your environment configuration."
            )

        # Check for common insecure defaults
        insecure_keys = ["changeme", "password", "test", "admin", "12345", "default"]
        if api_key.lower() in insecure_keys:
            raise ValueError(
                f"SECURITY ERROR: ZAP_API_KEY is set to an insecure default value '{api_key}'. "
                "Please use a strong, unique API key (at least 32 characters recommended)."
            )

        # Warn if key is too short
        if len(api_key) < 16:
            logger.warning(
                f"SECURITY WARNING: ZAP_API_KEY is short ({len(api_key)} characters). "
                "Consider using a longer key (32+ characters) for better security."
            )

        logger.debug("ZAP API key validation passed")

    def _verify_api_key_required(self) -> None:
        """
        SECURITY: Verify that ZAP actually requires API key authentication.
        Tests if an invalid API key is rejected, confirming auth is enabled.
        """
        try:
            # Try to connect with an invalid API key
            test_client = ZAPv2(
                apikey="invalid_test_key_should_fail",
                proxies={
                    "http": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                    "https": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                }
            )

            # Try to access ZAP with invalid key
            test_client.core.version

            # If we get here, ZAP accepted an invalid key - SECURITY RISK!
            logger.error(
                "SECURITY CRITICAL: ZAP instance is accepting requests without valid API key! "
                "This means your ZAP instance is running without authentication and can be "
                "exploited as a public proxy. Please restart ZAP with API key enforcement enabled."
            )
            raise RuntimeError(
                "ZAP instance is running without API key authentication. "
                "This is a critical security vulnerability."
            )

        except Exception as e:
            # If we get an error, that's good - it means auth is working
            error_msg = str(e).lower()
            if "unauthorized" in error_msg or "api key" in error_msg or "403" in error_msg:
                logger.debug("ZAP API key authentication verified - invalid key was rejected")
            else:
                # Different error - might be connection issue, log but continue
                logger.debug(f"ZAP authentication check completed with error: {e}")
                # Don't raise - the main connection with valid key already worked

    def _ensure_connection(self) -> ZAPv2:
        """
        Ensure ZAP connection is healthy and return client.
        Implements connection pooling with health checks.
        """
        current_time = time.time()

        # Check if we need to verify connection health
        if (self._zap_client is not None and
            current_time - self._last_health_check < self._health_check_interval):
            return self._zap_client

        with self._connection_lock:
            try:
                # SECURITY: Validate API key before attempting connection
                self._validate_api_key()

                # Try to reuse existing connection
                if self._zap_client is not None:
                    try:
                        # Health check
                        self._zap_client.core.version
                        self._last_health_check = current_time
                        logger.debug("ZAP connection health check passed")
                        return self._zap_client
                    except Exception as e:
                        logger.warning(f"ZAP connection health check failed: {e}. Reconnecting...")
                        self._zap_client = None

                # Create new connection
                logger.info(f"Establishing new ZAP connection to {ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}")
                self._zap_client = ZAPv2(
                    apikey=ZAPConfig.ZAP_API_KEY,
                    proxies={
                        "http": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                        "https": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                    }
                )

                # Verify connection
                version = self._zap_client.core.version
                logger.info(f"Successfully connected to ZAP version {version}")

                # SECURITY: Verify that API key authentication is actually enforced
                self._verify_api_key_required()

                self._last_health_check = current_time
                self._initialized = True

                return self._zap_client

            except Exception as e:
                logger.error(f"Failed to establish ZAP connection: {e}")
                self._zap_client = None
                raise RuntimeError(f"Cannot connect to ZAP instance: {e}")

    def get_scanner(self, scan_id: int) -> ZAPScanner:
        """
        Get an optimized scanner instance for a specific scan.

        This creates a scanner that:
        1. Reuses the persistent ZAP connection
        2. Sets up isolated context for this scan
        3. Doesn't restart ZAP unnecessarily

        Args:
            scan_id: Unique identifier for the scan

        Returns:
            Configured ZAPScanner instance
        """
        # Ensure we have a healthy connection
        zap_client = self._ensure_connection()

        # Create scanner with pre-initialized connection
        scanner = ZAPScanner(
            zap_host=ZAPConfig.ZAP_HOST,
            zap_port=ZAPConfig.ZAP_PORT,
            zap_api_key=ZAPConfig.ZAP_API_KEY,
            use_docker=False,  # Always false - we use persistent instance
        )

        # Inject the pooled connection (bypasses start_zap_instance)
        scanner.zap = zap_client
        scanner._scanner_manager_initialized = True

        # Create isolated context for this scan
        context_name = self._create_scan_context(scan_id, zap_client)
        scanner._scan_context = context_name

        logger.info(f"Scanner ready for scan {scan_id} with context '{context_name}'")
        return scanner

    def _create_scan_context(self, scan_id: int, zap_client: ZAPv2) -> str:
        """
        Create an isolated ZAP context for a scan.
        This prevents cross-scan interference in concurrent operations.
        """
        context_name = f"scan_{scan_id}_{int(time.time())}"

        try:
            # Create new context
            zap_client.context.new_context(context_name)
            self._scan_contexts[scan_id] = context_name
            logger.debug(f"Created ZAP context '{context_name}' for scan {scan_id}")
            return context_name
        except Exception as e:
            logger.warning(f"Failed to create ZAP context: {e}. Continuing without context.")
            return ""

    def cleanup_scan_context(self, scan_id: int):
        """
        Clean up the ZAP context for a completed scan.
        Call this after scan completes to free resources.
        """
        context_name = self._scan_contexts.pop(scan_id, None)
        if context_name and self._zap_client:
            try:
                self._zap_client.context.remove_context(context_name)
                logger.debug(f"Removed ZAP context '{context_name}' for scan {scan_id}")
            except Exception as e:
                logger.warning(f"Failed to remove ZAP context: {e}")

    def reset_connection(self):
        """
        Force reset the ZAP connection.
        Use this for error recovery or when ZAP instance is restarted.
        """
        with self._connection_lock:
            logger.info("Resetting ZAP connection pool")
            self._zap_client = None
            self._last_health_check = 0
            self._initialized = False

            # Clean up all contexts
            for scan_id in list(self._scan_contexts.keys()):
                self.cleanup_scan_context(scan_id)

    def get_connection_status(self) -> Dict:
        """Get current connection pool status for monitoring"""
        return {
            "initialized": self._initialized,
            "connected": self._zap_client is not None,
            "last_health_check": self._last_health_check,
            "active_contexts": len(self._scan_contexts),
            "scan_contexts": list(self._scan_contexts.values()),
        }


# Expose the singleton instance
scanner_manager = ScannerInstanceManager.get_instance()
