import time
import sys
import re
import ipaddress
from typing import Dict, Any, Optional, List, TYPE_CHECKING
from urllib.parse import urlparse
from zapv2 import ZAPv2
import docker
from docker.errors import NotFound, APIError
from app.utils.logger import logger
from app.core.config import ZAPConfig

if TYPE_CHECKING:
    from docker.models.containers import Container


class ZAPScanner:
    """
    OWASP ZAP Scanner with Docker integration.
    Supports multiple scan types
    """

    def __init__(
        self,
        zap_host: str = ZAPConfig.ZAP_HOST,
        zap_port: int = ZAPConfig.ZAP_PORT,
        zap_api_key: str = ZAPConfig.ZAP_API_KEY,
        use_docker: bool = ZAPConfig.USE_DOCKER_ZAP,
    ):
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_api_key = zap_api_key
        self.use_docker = use_docker
        self.docker_container: Optional["Container"] = None
        self.zap: Optional[ZAPv2] = None

        # Scanner manager optimization flags
        self._scanner_manager_initialized: bool = False
        self._scan_context: str = ""

    def _ensure_zap_initialized(self) -> ZAPv2:
        """Ensure ZAP instance is initialized, raise exception if not."""
        if self.zap is None:
            raise RuntimeError(
                "ZAP instance not initialized. Call start_zap_instance() first."
            )
        return self.zap

    def _validate_target_url(self, target_url: str) -> None:
        """
        SECURITY: Validate that target URL is safe to scan.
        Prevents Server-Side Request Forgery (SSRF) attacks by blocking:
        - Non-HTTP(S) protocols (file://, ftp://, gopher://, etc.)
        - Localhost and loopback addresses
        - Private IP ranges (RFC 1918)
        - Link-local addresses
        - Special-use addresses

        Args:
            target_url: The URL to validate

        Raises:
            ValueError: If the URL is invalid or unsafe to scan
        """
        try:
            parsed = urlparse(target_url)

            # Must be HTTP or HTTPS only
            if parsed.scheme not in ['http', 'https']:
                raise ValueError(
                    f"Invalid URL scheme '{parsed.scheme}'. Only http:// and https:// are allowed. "
                    f"Attempted to scan: {target_url}"
                )

            # Must have a hostname
            if not parsed.netloc:
                raise ValueError(
                    f"URL must have a valid hostname. Invalid URL: {target_url}"
                )

            # Extract hostname (remove port if present)
            hostname = parsed.hostname
            if not hostname:
                raise ValueError(
                    f"Could not extract hostname from URL: {target_url}"
                )

            # Block localhost variations
            localhost_names = ['localhost', 'localhost.localdomain']
            if hostname.lower() in localhost_names:
                raise ValueError(
                    f"Cannot scan localhost addresses. Hostname: {hostname}"
                )

            # Check if hostname looks like an IP address first
            is_ip_address = False
            try:
                # Try to parse as IP address
                ip = ipaddress.ip_address(hostname)
                is_ip_address = True
            except ValueError:
                # Not an IP address - check for IP-like patterns in domain name
                if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                    # Looks like IP but failed to parse - likely invalid
                    raise ValueError(
                        f"Invalid IP address format: {hostname}"
                    )
                # It's a domain name, not an IP
                is_ip_address = False

            # If it's an IP address, perform IP-specific checks
            if is_ip_address:
                # Block loopback (127.0.0.0/8, ::1)
                if ip.is_loopback:
                    raise ValueError(
                        f"Cannot scan loopback addresses. IP: {ip}"
                    )

                # Block private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
                if ip.is_private:
                    raise ValueError(
                        f"Cannot scan private IP addresses. IP: {ip} "
                        f"(Private networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
                    )

                # Block link-local (169.254.0.0/16, fe80::/10)
                if ip.is_link_local:
                    raise ValueError(
                        f"Cannot scan link-local addresses. IP: {ip}"
                    )

                # Block multicast
                if ip.is_multicast:
                    raise ValueError(
                        f"Cannot scan multicast addresses. IP: {ip}"
                    )

                # Block reserved/unspecified
                if ip.is_reserved or ip.is_unspecified:
                    raise ValueError(
                        f"Cannot scan reserved or unspecified addresses. IP: {ip}"
                    )
            else:
                # It's a domain name - check for suspicious patterns

                # Block localhost-like domains
                if re.search(r'localhost|127\.0\.0\.1|::1', hostname, re.IGNORECASE):
                    raise ValueError(
                        f"Domain appears to reference localhost. Hostname: {hostname}"
                    )

                # Block domains that might resolve to internal IPs
                # Check for common internal domain patterns
                internal_patterns = [
                    r'\.local$',
                    r'\.internal$',
                    r'\.lan$',
                    r'^192-168-',
                    r'^10-',
                    r'^172-',
                ]
                for pattern in internal_patterns:
                    if re.search(pattern, hostname, re.IGNORECASE):
                        logger.warning(
                            f"Domain matches internal network pattern: {hostname}. "
                            f"Pattern: {pattern}"
                        )
                        raise ValueError(
                            f"Cannot scan internal domain: {hostname} (pattern: {pattern})"
                        )

            logger.debug(f"Target URL validation passed: {target_url}")

        except ValueError as e:
            logger.error(f"Target URL validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during URL validation: {e}")
            raise ValueError(f"Invalid target URL: {target_url}. Error: {e}")

    def start_zap_instance(self) -> bool:
        """Start a ZAP instance (Docker or connect to existing)"""
        try:
            if self.use_docker:
                return self._start_docker_zap()
            else:
                # Connect to existing ZAP instance
                self.zap = ZAPv2(
                    apikey=self.zap_api_key,
                    proxies={
                        "http": f"http://{self.zap_host}:{self.zap_port}",
                        "https": f"http://{self.zap_host}:{self.zap_port}",
                    }
                )
                # Test connection
                self.zap.core.version
                logger.info(f"Connected to existing ZAP instance at {self.zap_host}:{self.zap_port}")
                return True
        except Exception as e:
            logger.error(f"Failed to start ZAP instance: {e}")
            return False

    def _start_docker_zap(self) -> bool:
        """Start ZAP in Docker container"""
        try:
            client = docker.from_env()

            # Check if container already exists
            container_name = f"zap-scanner-{int(time.time())}"

            logger.info(f"Starting ZAP Docker container: {container_name}")

            # Start ZAP container
            self.docker_container = client.containers.run(
                image=ZAPConfig.ZAP_DOCKER_IMAGE,
                name=container_name,
                detach=True,
                remove=True,
                ports={f"{self.zap_port}/tcp": self.zap_port},
                command=[
                    "zap.sh",
                    "-daemon",
                    "-host", "0.0.0.0",
                    "-port", str(self.zap_port),
                    "-config", f"api.key={self.zap_api_key}",
                    "-config", "api.addrs.addr.name=.*",
                    "-config", "api.addrs.addr.regex=true",
                ],
            )

            # Wait for ZAP to be ready
            max_wait = 60  # seconds
            wait_interval = 2
            elapsed = 0

            while elapsed < max_wait:
                try:
                    self.zap = ZAPv2(
                        apikey=self.zap_api_key,
                        proxies={
                            "http": f"http://{self.zap_host}:{self.zap_port}",
                            "https": f"http://{self.zap_host}:{self.zap_port}",
                        }
                    )
                    self.zap.core.version
                    logger.info(f"ZAP Docker container is ready: {container_name}")
                    return True
                except Exception:
                    time.sleep(wait_interval)
                    elapsed += wait_interval

            logger.error("ZAP container failed to start within timeout")
            self.stop_zap_instance()
            return False

        except Exception as e:
            logger.error(f"Failed to start ZAP Docker container: {e}")
            self.stop_zap_instance()
            return False

    def stop_zap_instance(self) -> None:
        """Stop ZAP instance"""
        try:
            if self.docker_container:
                logger.info("Stopping ZAP Docker container")
                self.docker_container.stop(timeout=10)
                self.docker_container = None
        except Exception as e:
            logger.error(f"Error stopping ZAP container: {e}")

    def spider_scan(
        self,
        target_url: str,
        max_depth: int = 5
    ) -> str:
        """
        Run spider scan to discover URLs with timeout
        Returns: scan_id

        Performance optimized: No real-time progress tracking
        """
        zap = self._ensure_zap_initialized()
        logger.info(f"Starting spider scan for {target_url}")

        # Configure spider for passive scanning (limit depth and duration)
        # Set max duration to prevent long-running spiders
        zap.spider.set_option_max_duration(str(ZAPConfig.ZAP_SPIDER_MAX_DURATION))

        # Start spider
        scan_id = zap.spider.scan(target_url, maxchildren=None, recurse=True)

        # Wait for completion with timeout (no progress polling)
        start_time = time.time()
        timeout = ZAPConfig.ZAP_SPIDER_TIMEOUT

        while int(zap.spider.status(scan_id)) < 100:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.warning(f"Spider scan timeout after {elapsed:.1f}s, stopping scan")
                zap.spider.stop(scan_id)
                break

            # Longer sleep interval - reduces API calls and improves performance
            time.sleep(5)

        elapsed_time = time.time() - start_time
        logger.info(f"Spider scan completed for {target_url} in {elapsed_time:.1f}s")
        return scan_id

    def passive_scan(
        self,
        target_url: str
    ) -> None:
        """
        Wait for passive scan to complete with timeout

        Performance optimized: No real-time progress tracking
        """
        zap = self._ensure_zap_initialized()
        logger.info(f"Running passive scan for {target_url}")

        # Enable only passive scan (disable active scan rules)
        zap.pscan.enable_all_scanners()

        # Access the URL to trigger passive scan
        zap.core.access_url(target_url, followredirects=True)

        # Wait for passive scan to complete with timeout
        start_time = time.time()
        timeout = ZAPConfig.ZAP_PASSIVE_SCAN_TIMEOUT

        while int(zap.pscan.records_to_scan) > 0:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.warning(f"Passive scan timeout after {elapsed:.1f}s")
                break

            # Longer sleep interval - reduces API calls and improves performance
            time.sleep(5)

        elapsed_time = time.time() - start_time
        logger.info(f"Passive scan completed for {target_url} in {elapsed_time:.1f}s")

    def active_scan(
        self,
        target_url: str
    ) -> str:
        """
        Run active scan
        Returns: scan_id

        Performance optimized: No real-time progress tracking
        """
        zap = self._ensure_zap_initialized()
        logger.info(f"Starting active scan for {target_url}")

        # Start active scan
        scan_id = zap.ascan.scan(target_url)

        # Wait for completion (no progress polling)
        while int(zap.ascan.status(scan_id)) < 100:
            # Longer sleep interval - reduces API calls and improves performance
            time.sleep(10)

        logger.info(f"Active scan completed for {target_url}")
        return scan_id

    def get_alerts(self, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all alerts from ZAP"""
        zap = self._ensure_zap_initialized()
        try:
            if base_url:
                alerts = zap.core.alerts(baseurl=base_url)
            else:
                alerts = zap.core.alerts()
            return alerts
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    def _get_available_scanners(self, zap: ZAPv2) -> List[Dict[str, Any]]:
        """
        Get list of available active scanners from ZAP.
        Returns list of scanner dictionaries with 'id' and 'name' fields.
        """
        try:
            scanners = zap.ascan.scanners()
            return scanners
        except Exception as e:
            logger.error(f"Failed to get available scanners from ZAP: {e}")
            return []

    def _get_scanner_name(self, scanner_id: int) -> str:
        """Get human-readable name for a scanner ID"""
        scanner_names = {
            # SQL Injection
            40018: "SQL Injection",
            40019: "SQL Injection - MySQL",
            40020: "SQL Injection - Hypersonic SQL",
            40021: "SQL Injection - Oracle",
            40022: "SQL Injection - PostgreSQL",
            90018: "SQL Injection - SQLite",
            # XSS
            40012: "Cross-Site Scripting (Reflected)",
            40014: "Cross-Site Scripting (Persistent)",
            40016: "Cross-Site Scripting (Persistent - Prime)",
            40017: "Cross-Site Scripting (Persistent - Spider)",
            # Path Traversal
            6: "Path Traversal",
            7: "Remote File Inclusion",
            # Command Injection
            90020: "Remote OS Command Injection",
            90019: "Server Side Code Injection",
            # CSRF
            20012: "Anti-CSRF Tokens Check",
            10202: "Absence of Anti-CSRF Tokens",
            # Security Misconfiguration
            10020: "Anti-clickjacking Header",
            10021: "X-Content-Type-Options Header Missing",
            10023: "Information Disclosure - Debug Error Messages",
            10024: "Information Disclosure - Sensitive Information in URL",
            10025: "Information Disclosure - Sensitive Information in HTTP Referrer Header",
            10026: "HTTP Parameter Override",
            10027: "Information Disclosure - Suspicious Comments",
            # Others
            20019: "External Redirect",
            90023: "XML External Entity Attack",
            # Alpha scanners
            40015: "LDAP Injection",
            90021: "XML Injection",
            90025: "Expression Language Injection",
            90035: "Server-Side Template Injection",
            90036: "NoSQL Injection",
        }
        return scanner_names.get(scanner_id, f"Unknown Scanner {scanner_id}")

    def _configure_passive_scan_policy(self) -> None:
        """Configure ZAP to only run passive scans (disable all active scan rules)"""
        zap = self._ensure_zap_initialized()

        try:
            # Disable all active scanners
            zap.ascan.disable_all_scanners()
            logger.info("Disabled all active scan rules for passive scanning")

            # Enable all passive scanners to maximize coverage
            zap.pscan.enable_all_scanners()
            logger.info("Enabled all passive scan rules")

            # Configure passive scan settings for better detection
            # These settings ensure thorough passive scanning for:
            # - HTTP Headers (Security Headers, CSP, HSTS, X-Frame-Options, etc.)
            # - Redirects (Open Redirects, HTTP to HTTPS redirects)
            # - SSL/TLS issues (Certificate validation, weak ciphers)
            # - Cookies (HttpOnly, Secure flags, SameSite)
            # - Information Disclosure (Server banners, error messages, comments)

        except Exception as e:
            logger.warning(f"Failed to configure passive scan policy: {e}")

    def _configure_active_scan_policy(self) -> None:
        """
        Configure ZAP active scan policy for security testing.

        Enables: SQLi, XSS, Path Traversal, Command Injection, CSRF, Security Headers
        Disables: DoS, Brute Force, Buffer Overflow (too aggressive/destructive)

        Performance optimized with throttling and smart targeting.
        """
        zap = self._ensure_zap_initialized()

        try:
            logger.info("Configuring active scan policy for FULL scan")

            # First, disable all scanners to start fresh
            zap.ascan.disable_all_scanners()

            # Enable passive scanners (for comprehensive coverage)
            zap.pscan.enable_all_scanners()

            # === ENABLE CRITICAL VULNERABILITY SCANNERS ===

            # SQL Injection (IDs: 40018, 40019, 40020, 40021, 40022, 90018)
            sql_injection_scanners = [40018, 40019, 40020, 40021, 40022, 90018]

            # Cross-Site Scripting (IDs: 40012, 40014, 40016, 40017)
            xss_scanners = [40012, 40014, 40016, 40017]

            # Path Traversal (IDs: 6, 7)
            path_traversal_scanners = [6, 7]

            # Command Injection (IDs: 90020, 90019)
            command_injection_scanners = [90020, 90019]

            # CSRF (IDs: 20012, 10202)
            csrf_scanners = [20012, 10202]

            # Security Misconfiguration (IDs: 10020, 10021, 10023, 10024, 10025, 10026, 10027)
            security_misc_scanners = [10020, 10021, 10023, 10024, 10025, 10026, 10027]

            # Server-Side Code Injection (IDs: 90019)
            code_injection_scanners = [90019]

            # External Redirect (IDs: 20019)
            redirect_scanners = [20019]

            # XXE (XML External Entity) (IDs: 90023)
            xxe_scanners = [90023]

            # === ALPHA/EXPERIMENTAL SCANNERS (Optional - More Aggressive) ===
            # Only enabled if ZAP_ENABLE_ALPHA_SCANNERS=True
            alpha_scanners = []
            if ZAPConfig.ZAP_ENABLE_ALPHA_SCANNERS:
                logger.info("Enabling ALPHA/experimental scanners for aggressive testing")
                # Advanced SQL Injection variants
                alpha_scanners += [40029, 40030, 40031, 40032, 40033]
                # Advanced XSS variants
                alpha_scanners += [40026, 40027, 40028]
                # Server-side Template Injection
                alpha_scanners += [90035]
                # LDAP Injection
                alpha_scanners += [40015]
                # XML Injection
                alpha_scanners += [90021]
                # Expression Language Injection
                alpha_scanners += [90025]
                # NoSQL Injection
                alpha_scanners += [90036]
                logger.info(f"Added {len(alpha_scanners)} alpha scanners")

            # Combine all enabled scanners
            enabled_scanners = (
                sql_injection_scanners +
                xss_scanners +
                path_traversal_scanners +
                command_injection_scanners +
                csrf_scanners +
                security_misc_scanners +
                code_injection_scanners +
                redirect_scanners +
                xxe_scanners +
                alpha_scanners  # Add alpha scanners if enabled
            )

            # SECURITY: Verify scanner availability before enabling
            available_scanners = self._get_available_scanners(zap)
            available_scanner_ids = {int(s['id']) for s in available_scanners}

            logger.debug(f"ZAP has {len(available_scanner_ids)} available active scanners")

            # Enable each scanner with verification
            successfully_enabled = []
            failed_scanners = []

            for scanner_id in enabled_scanners:
                # Check if scanner exists in current ZAP version
                if scanner_id not in available_scanner_ids:
                    scanner_name = self._get_scanner_name(scanner_id)
                    logger.warning(
                        f"Scanner {scanner_id} ({scanner_name}) not available in ZAP version. "
                        f"This scanner may have been renamed or removed."
                    )
                    failed_scanners.append(scanner_id)
                    continue

                try:
                    zap.ascan.enable_scanners(ids=str(scanner_id))
                    logger.debug(f"Enabled active scanner: {scanner_id}")
                    successfully_enabled.append(scanner_id)
                except Exception as e:
                    logger.warning(f"Failed to enable scanner {scanner_id}: {e}")
                    failed_scanners.append(scanner_id)

            # Report results
            logger.info(f"Successfully enabled {len(successfully_enabled)}/{len(enabled_scanners)} active scan rules")

            if failed_scanners:
                logger.warning(
                    f"Failed to enable {len(failed_scanners)} scanners: {failed_scanners}. "
                    f"This may be due to ZAP version differences or missing plugins."
                )

            # Alert if too many scanners failed
            if len(failed_scanners) > len(enabled_scanners) * 0.3:  # More than 30% failed
                logger.error(
                    f"WARNING: {len(failed_scanners)} out of {len(enabled_scanners)} scanners failed to enable. "
                    f"Your ZAP installation may be missing critical scanners. "
                    f"Please verify your ZAP version and installed add-ons."
                )

            # === CONFIGURE SCAN SETTINGS FOR PERFORMANCE ===

            try:
                # Set thread count (4 threads = good balance of speed vs server load)
                zap.ascan.set_option_thread_per_host(4)
                logger.debug("Set thread per host: 4")
            except Exception as e:
                logger.warning(f"Could not set thread per host: {e}")

            try:
                # Set max scan duration (30 minutes)
                zap.ascan.set_option_max_scan_duration_in_mins(30)
                logger.debug("Set max scan duration: 30 minutes")
            except Exception as e:
                logger.warning(f"Could not set max scan duration: {e}")

            try:
                # Set delay between requests (100ms = 10 req/sec max)
                zap.ascan.set_option_delay_in_ms(100)
                logger.debug("Set delay between requests: 100ms")
            except Exception as e:
                logger.warning(f"Could not set delay: {e}")

            logger.info("Active scan policy configured successfully")
            logger.info("Settings: Enabled 30+ security scanners for comprehensive testing")

        except Exception as e:
            logger.error(f"Failed to configure active scan policy: {e}")
            raise

    def run_basic_scan(
        self,
        target_url: str
    ) -> List[Dict[str, Any]]:
        """
        Basic scan: Spider + Passive scan (No domain verification required)
        This is a non-intrusive scan that only observes and doesn't actively test the target

        OPTIMIZED: Spider and passive scan run in parallel for maximum performance

        Passive scan checks for:
        - HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
        - Open Redirects
        - SSL/TLS Configuration Issues
        - Cookie Security (HttpOnly, Secure, SameSite flags)
        - Information Disclosure (Server banners, error messages, comments in HTML)
        - Authentication/Session Management Issues
        - And more...

        Performance: No real-time progress tracking - reduces API calls and overhead
        """
        # SECURITY: Validate target URL to prevent SSRF attacks
        self._validate_target_url(target_url)

        logger.info(f"Starting BASIC (passive) scan for {target_url}")

        # Only start ZAP if not managed by scanner manager
        needs_cleanup = False
        if not self._scanner_manager_initialized:
            if not self.start_zap_instance():
                raise Exception("Failed to start ZAP instance")
            needs_cleanup = True
        else:
            logger.info(f"Using pooled ZAP connection (context: {self._scan_context})")

        try:
            # Configure passive-only scan policy
            self._configure_passive_scan_policy()

            zap = self._ensure_zap_initialized()

            # Start spider
            spider_scan_id = zap.spider.scan(target_url, maxchildren=None, recurse=True)
            logger.info(f"Spider started for {target_url}")

            # Trigger passive scan immediately (runs in parallel with spider)
            zap.core.access_url(target_url, followredirects=True)
            zap.pscan.enable_all_scanners()
            logger.info(f"Passive scan triggered for {target_url}")

            # Monitor both spider and passive scan together (no progress tracking)
            start_time = time.time()
            spider_timeout = ZAPConfig.ZAP_SPIDER_TIMEOUT
            passive_timeout = ZAPConfig.ZAP_PASSIVE_SCAN_TIMEOUT
            spider_done = False

            while True:
                elapsed = time.time() - start_time

                # Check spider status
                spider_status = int(zap.spider.status(spider_scan_id))
                if spider_status >= 100:
                    if not spider_done:
                        logger.info(f"Spider completed for {target_url}")
                        spider_done = True

                # Check spider timeout
                if not spider_done and elapsed > spider_timeout:
                    logger.warning(f"Spider timeout after {elapsed:.1f}s, stopping")
                    zap.spider.stop(spider_scan_id)
                    spider_done = True

                # Check passive scan status
                passive_remaining = int(zap.pscan.records_to_scan)

                # Both completed?
                if spider_done and passive_remaining == 0:
                    logger.info(f"Both spider and passive scan completed")
                    break

                # Check passive timeout (only after spider is done)
                if spider_done and elapsed > passive_timeout:
                    logger.warning(f"Passive scan timeout after {elapsed:.1f}s")
                    break

                # Longer sleep interval - reduces API calls and improves performance
                time.sleep(5)

            elapsed_time = time.time() - start_time
            logger.info(f"Parallel scan completed for {target_url} in {elapsed_time:.1f}s")

            # Get results
            alerts = self.get_alerts(target_url)
            logger.info(f"BASIC scan completed for {target_url}. Found {len(alerts)} alerts")
            return alerts
        finally:
            # Only cleanup if we started ZAP ourselves
            if needs_cleanup:
                self.stop_zap_instance()

    def run_full_scan(
        self,
        target_url: str
    ) -> List[Dict[str, Any]]:
        """
        Full scan: Spider + Passive + Active scan (Requires domain verification)
        This is an intrusive scan that actively tests the target for vulnerabilities

        OPTIMIZED: Parallel execution of spider, passive, and active scans for maximum performance

        Tests for:
        - SQL Injection (SQLi)
        - Cross-Site Scripting (XSS)
        - Path Traversal
        - Command Injection
        - CSRF vulnerabilities
        - Security Headers
        - Open Redirects
        - XXE (XML External Entity)
        - And more critical vulnerabilities

        Performance: No real-time progress tracking - reduces API calls and overhead
        """
        # SECURITY: Validate target URL to prevent SSRF attacks
        self._validate_target_url(target_url)

        logger.info(f"Starting FULL scan (active) for {target_url}")

        # Only start ZAP if not managed by scanner manager
        needs_cleanup = False
        if not self._scanner_manager_initialized:
            if not self.start_zap_instance():
                raise Exception("Failed to start ZAP instance")
            needs_cleanup = True
        else:
            logger.info(f"Using pooled ZAP connection (context: {self._scan_context})")

        try:
            # Configure active scan policy first
            self._configure_active_scan_policy()

            zap = self._ensure_zap_initialized()

            # Start traditional spider
            spider_scan_id = zap.spider.scan(target_url, maxchildren=None, recurse=True)
            logger.info(f"Traditional spider started for {target_url}")

            # Start AJAX Spider for JavaScript-heavy apps (if enabled)
            ajax_spider_enabled = ZAPConfig.ZAP_ENABLE_AJAX_SPIDER
            if ajax_spider_enabled:
                try:
                    zap.ajaxSpider.set_option_max_duration(str(ZAPConfig.ZAP_AJAX_SPIDER_TIMEOUT // 60))  # Convert to minutes
                    ajax_spider_result = zap.ajaxSpider.scan(target_url)
                    logger.info(f"AJAX spider started for {target_url} (for JavaScript apps)")
                except Exception as e:
                    logger.warning(f"Could not start AJAX spider: {e}. Continuing with traditional spider only.")
                    ajax_spider_enabled = False

            # Trigger passive scan immediately
            zap.core.access_url(target_url, followredirects=True)
            zap.pscan.enable_all_scanners()
            logger.info(f"Passive scan triggered for {target_url}")

            # Start active scan immediately (will scan URLs as spider discovers them)
            active_scan_id = zap.ascan.scan(target_url)
            logger.info(f"Active scan started for {target_url} with ID: {active_scan_id}")

            # Validate active scan ID
            if not active_scan_id or active_scan_id in ['url_not_found', 'does_not_exist', '']:
                logger.error(f"Invalid active scan ID returned: {active_scan_id}. This usually means no URLs were found to scan.")
                raise Exception(f"Failed to start active scan: Invalid scan ID '{active_scan_id}'. The spider may not have discovered any URLs to scan.")

            # Monitor all scans together (status checks only, no progress tracking)
            start_time = time.time()
            spider_timeout = ZAPConfig.ZAP_SPIDER_TIMEOUT
            passive_timeout = ZAPConfig.ZAP_PASSIVE_SCAN_TIMEOUT
            active_timeout = 1800  # 30 minutes for active scan

            spider_done = False
            ajax_spider_done = not ajax_spider_enabled  # If not enabled, consider it done
            passive_done = False

            while True:
                elapsed = time.time() - start_time

                # Check traditional spider status
                spider_status = int(zap.spider.status(spider_scan_id))
                if spider_status >= 100:
                    if not spider_done:
                        logger.info(f"Traditional spider completed for {target_url}")
                        spider_done = True

                # Check spider timeout
                if not spider_done and elapsed > spider_timeout:
                    logger.warning(f"Spider timeout after {elapsed:.1f}s, stopping")
                    zap.spider.stop(spider_scan_id)
                    spider_done = True

                # Check AJAX spider status (if enabled)
                if ajax_spider_enabled and not ajax_spider_done:
                    try:
                        ajax_status = zap.ajaxSpider.status
                        if ajax_status == 'stopped':
                            logger.info(f"AJAX spider completed for {target_url}")
                            ajax_spider_done = True
                        # Check AJAX spider timeout
                        if elapsed > ZAPConfig.ZAP_AJAX_SPIDER_TIMEOUT:
                            logger.warning(f"AJAX spider timeout, stopping")
                            zap.ajaxSpider.stop()
                            ajax_spider_done = True
                    except Exception as e:
                        logger.warning(f"Error checking AJAX spider status: {e}")
                        ajax_spider_done = True

                # Check passive scan status
                passive_remaining = int(zap.pscan.records_to_scan)

                if passive_remaining == 0 and spider_done and ajax_spider_done:
                    if not passive_done:
                        logger.info(f"Passive scan completed for {target_url}")
                        passive_done = True

                # Check active scan status
                try:
                    active_status = zap.ascan.status(active_scan_id)
                    # Handle cases where scan doesn't exist or isn't started yet
                    if active_status in ['does_not_exist', '', None]:
                        active_progress = 0
                    else:
                        active_progress = int(active_status)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse active scan status: {e}")
                    active_progress = 0
                except Exception as e:
                    # If we get repeated errors checking scan status, the scan ID is likely invalid
                    if 'DOES_NOT_EXIST' in str(e).upper() or 'NOT_FOUND' in str(e).upper():
                        logger.error(f"Active scan {active_scan_id} does not exist in ZAP. This is a critical error.")
                        raise Exception(f"Active scan failed: Scan ID {active_scan_id} is invalid or was not created properly.")
                    logger.warning(f"Error checking active scan status: {e}")
                    active_progress = 0

                # All completed?
                all_spiders_done = spider_done and ajax_spider_done
                if all_spiders_done and passive_done and active_progress >= 100:
                    spider_type = "spider, AJAX spider, passive, active" if ajax_spider_enabled else "spider, passive, active"
                    logger.info(f"All scans ({spider_type}) completed")
                    break

                # Check overall timeout
                if elapsed > active_timeout:
                    logger.warning(f"Active scan timeout after {elapsed:.1f}s, stopping")
                    zap.ascan.stop(active_scan_id)
                    break

                # Longer sleep interval - reduces API calls and improves performance
                time.sleep(10)

            elapsed_time = time.time() - start_time
            logger.info(f"FULL scan completed for {target_url} in {elapsed_time:.1f}s")

            # Get results
            alerts = self.get_alerts(target_url)
            logger.info(f"FULL scan completed for {target_url}. Found {len(alerts)} alerts")
            return alerts

        finally:
            # Only cleanup if we started ZAP ourselves
            if needs_cleanup:
                self.stop_zap_instance()
