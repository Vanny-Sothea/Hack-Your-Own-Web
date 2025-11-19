"""
Anonymous Scanner Service

Provides anonymous basic security scanning without authentication or database persistence.
Results are returned directly in the HTTP response.

Key features:
- No authentication required
- No database storage
- Synchronous execution (user waits for results)
- Basic scan only (spider + passive scan)
- Uses existing ZAPScanner infrastructure
"""

import time
from datetime import datetime
from typing import Dict, Any, List
from app.services.scanner_manager import scanner_manager
from app.utils.logger import logger
from app.models.scan import RiskLevel


class AnonymousScannerService:
    """Service for performing anonymous scans without DB persistence"""
    
    # MVP Categories - Match your 4 main vulnerability types
    # Based on actual OWASP ZAP alert names
    MVP_CATEGORIES = {
        "sql_injection": {
            "name": "SQL Injection (SQLi)",
            "keywords": [
                "sql injection",
                "sql",
                "database",
                "sqli",
                "mysql",
                "postgresql",
                "oracle",
                "mssql",
                "sqlite"
            ]
        },
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "keywords": [
                "cross site scripting",
                "cross-site scripting",
                "xss",
                "reflected xss",
                "stored xss",
                "dom xss",
                "dom-based xss"
            ]
        },
        "security_headers": {
            "name": "Security Headers",
            "keywords": [
                # General header keywords
                "header",
                "missing header",
                # Specific security headers
                "content-security-policy",
                "content security policy",
                "csp",
                "strict-transport-security",
                "hsts",
                "x-frame-options",
                "x-content-type-options",
                "clickjacking",
                "anti-clickjacking",
                "x-xss-protection",
                "referrer-policy",
                "permissions-policy",
                "feature-policy",
                # Cookie-related headers
                "secure flag",
                "httponly",
                "samesite",
                "cookie"
            ]
        },
        "open_redirect": {
            "name": "Open Redirects",
            "keywords": [
                "open redirect",
                "url redirect",
                "external redirect",
                "unvalidated redirect"
            ]
        }
    }
    
    @staticmethod
    def _categorize_by_mvp(alert: Dict[str, Any]) -> str:
        """
        Categorize alert into MVP category based on alert name
        
        Args:
            alert: Alert dictionary from ZAP (must have 'alert' field)
            
        Returns:
            MVP category key or "other"
        """
        # ZAP uses 'alert' field for alert name
        alert_name = alert.get("alert", "").lower()
        
        if not alert_name:
            logger.warning(f"Alert missing 'alert' field: {alert}")
            return "other"
        
        # Check each MVP category
        for category_key, category_info in AnonymousScannerService.MVP_CATEGORIES.items():
            keywords = category_info["keywords"]
            for keyword in keywords:
                if keyword.lower() in alert_name:
                    logger.debug(f"Alert '{alert_name}' matched category '{category_key}' via keyword '{keyword}'")
                    return category_key
        
        # No match found
        logger.debug(f"Alert '{alert_name}' did not match any MVP category, classified as 'other'")
        return "other"
    
    @staticmethod
    def _categorize_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Categorize alerts by risk level
        
        Args:
            alerts: List of alert dictionaries from ZAP
            
        Returns:
            Dictionary with counts for each risk level
        """
        risk_counts = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        for alert in alerts:
            risk = alert.get("risk", "").lower()
            
            # Map ZAP risk levels to our enum
            if risk in ["high", "3"]:
                risk_counts["high"] += 1
            elif risk in ["medium", "2"]:
                risk_counts["medium"] += 1
            elif risk in ["low", "1"]:
                risk_counts["low"] += 1
            else:
                risk_counts["informational"] += 1
        
        return risk_counts
    
    @staticmethod
    def _categorize_by_mvp_groups(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Categorize and filter alerts by MVP categories (4 main vulnerability types)
        
        Args:
            alerts: List of alert dictionaries from ZAP
            
        Returns:
            Dictionary with categorized alerts and pass/fail status
        """
        mvp_results = {}
        
        # Initialize categories
        for category_key, category_info in AnonymousScannerService.MVP_CATEGORIES.items():
            mvp_results[category_key] = {
                "name": category_info["name"],
                "passed": True,  # Assume passed until we find issues
                "total_issues": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "issues": []
            }
        
        # Also track "other" category
        mvp_results["other"] = {
            "name": "Other Security Issues",
            "passed": True,
            "total_issues": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "issues": []
        }
        
        # Log sample of alerts for debugging
        if alerts:
            logger.info(f"Categorizing {len(alerts)} alerts from ZAP scanner")
            # Log first alert structure for verification
            sample_alert = alerts[0]
            logger.debug(f"Sample ZAP alert structure: {list(sample_alert.keys())}")
            logger.debug(f"Sample alert name: {sample_alert.get('alert', 'N/A')}")
        
        # Categorize each alert
        for alert in alerts:
            # Validate alert has required fields
            if not isinstance(alert, dict):
                logger.warning(f"Invalid alert format (not a dict): {type(alert)}")
                continue
            
            if "alert" not in alert:
                logger.warning(f"Alert missing 'alert' field, keys present: {list(alert.keys())}")
                continue
            
            category = AnonymousScannerService._categorize_by_mvp(alert)
            normalized = AnonymousScannerService._normalize_alert(alert)
            
            # Add to category
            mvp_results[category]["issues"].append(normalized)
            mvp_results[category]["total_issues"] += 1
            mvp_results[category]["passed"] = False  # Found an issue
            
            # Count by risk level
            risk = normalized["risk_level"]
            if risk == "high":
                mvp_results[category]["high_risk"] += 1
            elif risk == "medium":
                mvp_results[category]["medium_risk"] += 1
            elif risk == "low":
                mvp_results[category]["low_risk"] += 1
        
        # Log categorization summary
        logger.info("MVP Categorization Summary:")
        for category_key, category_data in mvp_results.items():
            if category_data["total_issues"] > 0:
                logger.info(
                    f"  {category_data['name']}: {category_data['total_issues']} issues "
                    f"(H:{category_data['high_risk']}, M:{category_data['medium_risk']}, L:{category_data['low_risk']})"
                )
        
        return mvp_results
    
    @staticmethod
    def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize ZAP alert format to our response format
        
        Args:
            alert: Raw alert from ZAP
            
        Returns:
            Normalized alert dictionary
        """
        # Map ZAP risk levels to our enum values
        risk_mapping = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "informational",
            "3": "high",
            "2": "medium",
            "1": "low",
            "0": "informational"
        }
        
        risk = alert.get("risk", "Informational")
        normalized_risk = risk_mapping.get(risk, "informational")
        
        return {
            "alert_name": alert.get("alert", "Unknown Alert"),
            "risk_level": normalized_risk,
            "confidence": alert.get("confidence", "Medium"),
            "description": alert.get("description"),
            "solution": alert.get("solution"),
            "reference": alert.get("reference"),
            "cwe_id": alert.get("cweid"),
            "wasc_id": alert.get("wascid"),
            "url": alert.get("url", ""),
            "method": alert.get("method"),
            "param": alert.get("param"),
            "attack": alert.get("attack"),
            "evidence": alert.get("evidence"),
            "other_info": alert.get("other")
        }
    
    @staticmethod
    async def run_anonymous_scan(target_url: str) -> Dict[str, Any]:
        """
        Run an anonymous basic scan without database persistence
        
        This performs a basic (passive) security scan and returns results directly.
        No authentication or database storage required.
        
        Args:
            target_url: The URL to scan
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            Exception: If scan fails
        """
        logger.info(f"Starting anonymous scan for {target_url}")
        start_time = time.time()
        
        try:
            # Get scanner instance from pool (no scan_id needed for anonymous)
            # We'll use a temporary scan_id for context isolation
            temp_scan_id = int(time.time() * 1000)  # Use timestamp as unique ID
            scanner = scanner_manager.get_scanner(temp_scan_id)
            
            # Run basic scan (spider + passive)
            alerts = scanner.run_basic_scan(target_url)
            
            # Clean up the temporary context
            scanner_manager.cleanup_scan_context(temp_scan_id)
            
            # Calculate scan duration
            scan_duration = time.time() - start_time
            
            # Categorize alerts
            risk_counts = AnonymousScannerService._categorize_alerts(alerts)
            
            # Normalize alerts to our response format
            normalized_alerts = [
                AnonymousScannerService._normalize_alert(alert) 
                for alert in alerts
            ]
            
            # Categorize by MVP (4 main vulnerability types)
            mvp_categories = AnonymousScannerService._categorize_by_mvp_groups(alerts)
            
            # Build response
            result = {
                "target_url": target_url,
                "scan_type": "basic",
                "scan_duration_seconds": round(scan_duration, 2),
                "total_alerts": len(alerts),
                "high_risk_count": risk_counts["high"],
                "medium_risk_count": risk_counts["medium"],
                "low_risk_count": risk_counts["low"],
                "info_count": risk_counts["informational"],
                "alerts": normalized_alerts,
                "mvp_categories": mvp_categories,  # 4 MVP vulnerability categories
                "completed_at": datetime.utcnow().isoformat() + "Z"
            }
            
            logger.info(
                f"Anonymous scan completed for {target_url}. "
                f"Found {len(alerts)} alerts in {scan_duration:.2f}s"
            )
            
            return result
            
        except Exception as e:
            scan_duration = time.time() - start_time
            logger.error(f"Anonymous scan failed for {target_url}: {e}")
            
            # Return error result
            return {
                "target_url": target_url,
                "scan_type": "basic",
                "scan_duration_seconds": round(scan_duration, 2),
                "total_alerts": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "info_count": 0,
                "alerts": [],
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat() + "Z"
            }
