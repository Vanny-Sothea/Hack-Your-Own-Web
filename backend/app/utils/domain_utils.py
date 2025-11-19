"""
Domain utility functions for URL parsing and domain verification
"""
from urllib.parse import urlparse
from typing import Optional
from app.utils.logger import logger


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract the domain (hostname) from a URL.

    Args:
        url: Full URL (e.g., "https://example.com/path?query=1")

    Returns:
        Domain without protocol or path (e.g., "example.com")
        None if URL is invalid

    Examples:
        >>> extract_domain_from_url("https://example.com/test")
        'example.com'
        >>> extract_domain_from_url("http://sub.example.com:8080/path")
        'sub.example.com'
        >>> extract_domain_from_url("https://192.168.1.1/admin")
        '192.168.1.1'
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            logger.warning(f"Could not extract domain from URL: {url}")
            return None

        # Remove 'www.' prefix if present for consistency
        if domain.startswith('www.'):
            domain = domain[4:]

        return domain.lower()

    except Exception as e:
        logger.error(f"Error parsing URL {url}: {e}")
        return None


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name for consistent comparison.

    Args:
        domain: Domain name (e.g., "WWW.Example.COM")

    Returns:
        Normalized domain (e.g., "example.com")

    Examples:
        >>> normalize_domain("WWW.Example.COM")
        'example.com'
        >>> normalize_domain("  Sub.Example.com  ")
        'sub.example.com'
    """
    # Strip whitespace and convert to lowercase
    domain = domain.strip().lower()

    # Remove 'www.' prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]

    # Remove protocol if accidentally included
    if '://' in domain:
        domain = domain.split('://', 1)[1]

    # Remove path if accidentally included
    if '/' in domain:
        domain = domain.split('/', 1)[0]

    # Remove port if included
    if ':' in domain:
        domain = domain.split(':', 1)[0]

    return domain


def is_subdomain_of(subdomain: str, parent_domain: str) -> bool:
    """
    Check if subdomain is a subdomain of parent_domain.

    Args:
        subdomain: Potential subdomain (e.g., "api.example.com")
        parent_domain: Parent domain (e.g., "example.com")

    Returns:
        True if subdomain is a subdomain of parent_domain

    Examples:
        >>> is_subdomain_of("api.example.com", "example.com")
        True
        >>> is_subdomain_of("example.com", "example.com")
        True
        >>> is_subdomain_of("other.com", "example.com")
        False
    """
    subdomain = normalize_domain(subdomain)
    parent_domain = normalize_domain(parent_domain)

    # Exact match
    if subdomain == parent_domain:
        return True

    # Check if subdomain ends with parent domain
    return subdomain.endswith('.' + parent_domain)
