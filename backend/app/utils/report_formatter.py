"""
Report Formatter for ZAP Scan Results
Generates OWASP ZAP-compatible reports in JSON
"""
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, cast
from app.models.scan import Scan, ScanAlert, RiskLevel
from app.utils.logger import logger


class ZAPReportFormatter:
    """Formats scan results into ZAP-compatible JSON and text report formats"""

    @staticmethod
    def format_scan_to_json(scan: Scan, alerts: List[ScanAlert]) -> Dict[str, Any]:
        """
        Convert scan and alerts to ZAP JSON format

        Args:
            scan: Scan database model instance
            alerts: List of ScanAlert instances

        Returns:
            Dictionary in ZAP JSON report format
        """
        logger.info(f"Formatting scan {scan.id} to JSON report with {len(alerts)} alerts")

        # Extract domain and port from target URL
        from urllib.parse import urlparse
        parsed_url = urlparse(str(scan.target_url))
        domain = parsed_url.hostname or "unknown"
        port = str(parsed_url.port or (443 if parsed_url.scheme == 'https' else 80))
        ssl = "true" if parsed_url.scheme == 'https' else "false"

        # Get actual ZAP version
        zap_version = ZAPReportFormatter._get_zap_version()

        # Group alerts by their properties (to match ZAP format)
        grouped_alerts = ZAPReportFormatter._group_alerts(alerts)

        # Build the report structure
        report = {
            "@programName": "ZAP",
            "@version": zap_version,
            "@generated": ZAPReportFormatter._format_datetime(
                cast(datetime, scan.completed_at) if scan.completed_at is not None else datetime.utcnow()
            ),
            "site": [
                {
                    "@name": str(scan.target_url),
                    "@host": domain,
                    "@port": port,
                    "@ssl": ssl,
                    "alerts": grouped_alerts
                }
            ]
        }

        logger.info(f"Successfully formatted scan {scan.id} to JSON report")
        return report

    @staticmethod
    def _group_alerts(alerts: List[ScanAlert]) -> List[Dict[str, Any]]:
        """
        Group alerts by alert name and risk level (matching ZAP format)
        Each unique alert type becomes one entry with multiple instances
        """
        # Group by (alert_name, risk_level, confidence)
        alert_groups: Dict[tuple, List[ScanAlert]] = {}

        for alert in alerts:
            key = (alert.alert_name, alert.risk_level.value, alert.confidence)
            if key not in alert_groups:
                alert_groups[key] = []
            alert_groups[key].append(alert)

        # Convert groups to ZAP format
        formatted_alerts = []

        for (alert_name, risk_level, confidence), alert_list in alert_groups.items():
            # Use the first alert for main details (they're all the same type)
            first_alert = alert_list[0]

            # Map risk level to ZAP numeric codes
            risk_code = ZAPReportFormatter._get_risk_code(risk_level)

            # Create instances list (one per URL/param combination)
            instances = []
            for alert in alert_list:
                instance = {
                    "uri": alert.url or "",
                    "method": alert.method or "GET",
                    "param": alert.param or "",
                    "attack": alert.attack or "",
                    "evidence": alert.evidence or "",
                    "otherinfo": alert.other_info or "",
                    # Note: requestHeader and responseHeader are not stored in DB
                    # These would require storing raw HTTP data which is not practical
                    # Most ZAP reports don't include these for all instances
                    "requestHeader": "",
                    "requestBody": "",
                    "responseHeader": "",
                    "responseBody": ""
                }
                instances.append(instance)

            # Build alert entry (ZAP standard format)
            formatted_alert = {
                "pluginid": first_alert.cwe_id or "0",
                "alertRef": f"{first_alert.cwe_id or '0'}-{len(instances)}",
                "alert": alert_name,
                "name": alert_name,
                "riskcode": risk_code,
                "confidence": ZAPReportFormatter._get_confidence_code(confidence),
                "riskdesc": ZAPReportFormatter._get_risk_desc(risk_level, confidence),
                "desc": f"<p>{first_alert.description or 'No description available'}</p>",
                "instances": instances,
                "count": str(len(instances)),
                "solution": f"<p>{first_alert.solution or 'No solution available'}</p>",
                "otherinfo": first_alert.other_info or "",
                "reference": first_alert.reference or "",
                "cweid": first_alert.cwe_id or "0",
                "wascid": first_alert.wasc_id or "0",
                "sourceid": "3",
                # Additional frontend-friendly fields
                "tags": cast(dict, first_alert.alert_tags) if first_alert.alert_tags is not None else {}
            }

            formatted_alerts.append(formatted_alert)

        # Sort by risk level (high to low) then by alert name
        risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
        formatted_alerts.sort(
            key=lambda x: (risk_order.get(x["riskdesc"].split()[0].lower(), 4), x["alert"])
        )

        return formatted_alerts

    @staticmethod
    def _get_risk_code(risk_level: str) -> str:
        """Convert risk level string to ZAP numeric code"""
        mapping = {
            "high": "3",
            "medium": "2",
            "low": "1",
            "informational": "0"
        }
        return mapping.get(risk_level.lower(), "0")

    @staticmethod
    def _get_confidence_code(confidence: str) -> str:
        """Convert confidence string to ZAP numeric code"""
        confidence_lower = confidence.lower()
        if "high" in confidence_lower:
            return "3"
        elif "medium" in confidence_lower:
            return "2"
        elif "low" in confidence_lower:
            return "1"
        else:
            return "2"  # Default to medium

    @staticmethod
    def _get_risk_desc(risk_level: str, confidence: str) -> str:
        """Generate risk description string (e.g., 'Medium (High)')"""
        risk_map = {
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Informational"
        }

        conf_map = {
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "1": "Low",
            "2": "Medium",
            "3": "High"
        }

        risk_str = risk_map.get(risk_level.lower(), "Informational")
        conf_str = conf_map.get(confidence.lower(), confidence)

        return f"{risk_str} ({conf_str})"

    @staticmethod
    def _format_datetime(dt: datetime) -> str:
        """Format datetime to ZAP format: 'Tue, 21 Oct 2025 14:43:38'"""
        return dt.strftime("%a, %d %b %Y %H:%M:%S")

    @staticmethod
    def format_scan_to_frontend_json(scan: Scan, alerts: List[ScanAlert]) -> Dict[str, Any]:
        """
        Convert scan to frontend-friendly JSON format

        This format is optimized for:
        - Easy parsing by frontend frameworks (React, Vue, etc.)
        - Quick filtering and sorting
        - Dashboard visualizations
        - User-friendly display

        Args:
            scan: Scan database model instance
            alerts: List of ScanAlert instances

        Returns:
            Dictionary optimized for frontend consumption
        """
        from urllib.parse import urlparse

        logger.info(f"Formatting scan {scan.id} to frontend-friendly JSON")

        parsed_url = urlparse(str(scan.target_url))

        # Group alerts for easy frontend consumption
        alert_groups = ZAPReportFormatter._group_alerts_by_risk(alerts)

        # Format alerts in a clean structure
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                "id": alert.id,
                "name": alert.alert_name,
                "riskLevel": alert.risk_level.value,
                "confidence": alert.confidence,
                "url": alert.url,
                "method": alert.method or "GET",
                "param": alert.param,
                "attack": alert.attack,
                "evidence": alert.evidence,
                "description": alert.description,
                "solution": alert.solution,
                "reference": alert.reference,
                "cweId": alert.cwe_id,
                "wascId": alert.wasc_id,
                "otherInfo": alert.other_info,
                "tags": alert.alert_tags,
                "createdAt": cast(datetime, alert.created_at).isoformat() if alert.created_at is not None else None
            })

        # Build comprehensive report
        report = {
            "scan": {
                "id": scan.id,
                "targetUrl": str(scan.target_url),
                "scanType": scan.scan_type.value,
                "status": scan.status.value,
                "startedAt": cast(datetime, scan.started_at).isoformat() if scan.started_at is not None else None,
                "completedAt": cast(datetime, scan.completed_at).isoformat() if scan.completed_at is not None else None,
                "duration": None
            },
            "summary": {
                "totalAlerts": scan.total_alerts,
                "highRisk": scan.high_risk_count,
                "mediumRisk": scan.medium_risk_count,
                "lowRisk": scan.low_risk_count,
                "informational": scan.info_count,
                "uniqueUrls": len(set(alert.url for alert in alerts))
            },
            "site": {
                "host": parsed_url.hostname or "unknown",
                "port": parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
                "protocol": parsed_url.scheme,
                "ssl": parsed_url.scheme == 'https'
            },
            "alerts": formatted_alerts,
            "alertsByRisk": {
                "high": [a for a in formatted_alerts if a["riskLevel"] == "high"],
                "medium": [a for a in formatted_alerts if a["riskLevel"] == "medium"],
                "low": [a for a in formatted_alerts if a["riskLevel"] == "low"],
                "informational": [a for a in formatted_alerts if a["riskLevel"] == "informational"]
            },
            "generatedAt": datetime.utcnow().isoformat(),
            "reportVersion": "1.0"
        }

        # Calculate duration if available
        if scan.started_at is not None and scan.completed_at is not None:
            duration = (cast(datetime, scan.completed_at) - cast(datetime, scan.started_at)).total_seconds()
            report["scan"]["duration"] = f"{int(duration)} seconds"

        logger.info(f"Successfully formatted scan {scan.id} to frontend-friendly JSON")
        return report

    @staticmethod
    def _group_alerts_by_risk(alerts: List[ScanAlert]) -> Dict[str, Dict[str, List[ScanAlert]]]:
        """
        Group alerts by risk level and alert name

        Returns:
            Dict with structure: {risk_level: {alert_name: [alerts]}}
        """
        grouped: Dict[str, Dict[str, List[ScanAlert]]] = {
            "high": {},
            "medium": {},
            "low": {},
            "informational": {}
        }

        for alert in alerts:
            risk = str(alert.risk_level.value)
            name = str(alert.alert_name)

            if name not in grouped[risk]:
                grouped[risk][name] = []
            grouped[risk][name].append(alert)

        return grouped

    @staticmethod
    def format_scan_to_categorized_report(
        scan: Scan, 
        alerts: List[ScanAlert],
        include_details: bool = True,
        max_issues_per_category: int = 100
    ) -> Dict[str, Any]:
        """
        Convert scan to categorized report with pass/fail status for each vulnerability type

        This format provides clear pass/fail indicators for:
        - SQL Injection (SQLi) - FULL scan only (active testing)
        - Cross-Site Scripting (XSS) - FULL scan only (active testing)
        - Security Headers - Both BASIC and FULL scans (passive testing)
        - Open Redirects - Both BASIC and FULL scans (passive testing)

        Args:
            scan: Scan database model instance
            alerts: List of ScanAlert instances
            include_details: Include full issue details in response (default: True)
            max_issues_per_category: Maximum number of issues per category (default: 100)

        Returns:
            Dictionary with categorized vulnerabilities and pass/fail status
        """
        from urllib.parse import urlparse
        from app.models.scan import ScanType

        logger.info(
            f"Formatting scan {scan.id} to categorized report with pass/fail status "
            f"(include_details={include_details}, max_issues={max_issues_per_category})"
        )

        parsed_url = urlparse(str(scan.target_url))
        # Convert scan_type to actual value to avoid SQLAlchemy ColumnElement boolean issues
        is_full_scan = str(scan.scan_type.value if hasattr(scan.scan_type, 'value') else scan.scan_type) == ScanType.FULL.value

        # Define vulnerability categories with their associated CWE IDs and alert patterns
        # Note: requires_active indicates if this test requires FULL scan (active testing)
        vuln_categories = {
            "sqli": {
                "name": "SQL Injection",
                "description": "Tests for SQL Injection vulnerabilities that could allow attackers to manipulate database queries",
                "requires_active": True,  # Only tested in FULL scans
                "cwe_ids": ["89"],
                "alert_patterns": [
                    "sql injection",
                    "sql",
                    "database",
                    "blind sql"
                ],
                "alerts": []
            },
            "xss": {
                "name": "Cross-Site Scripting (XSS)",
                "description": "Tests for XSS vulnerabilities that could allow attackers to inject malicious scripts",
                "requires_active": True,  # Only tested in FULL scans
                "cwe_ids": ["79", "80"],
                "alert_patterns": [
                    "cross site scripting",
                    "xss",
                    "cross-site scripting",
                    "script injection"
                ],
                "alerts": []
            },
            "headers": {
                "name": "Security Headers",
                "description": "Checks for missing or misconfigured security headers that protect against various attacks",
                "requires_active": False,  # Tested in both BASIC and FULL scans
                "cwe_ids": ["16", "693", "1021"],
                "alert_patterns": [
                    "header",
                    "content security policy",
                    "csp",
                    "x-frame-options",
                    "x-content-type-options",
                    "strict-transport-security",
                    "hsts",
                    "x-xss-protection",
                    "permissions policy",
                    "referrer-policy"
                ],
                "alerts": []
            },
            "redirects": {
                "name": "Open Redirects",
                "description": "Tests for open redirect vulnerabilities that could be used in phishing attacks",
                "requires_active": False,  # Tested in both BASIC and FULL scans
                "cwe_ids": ["601"],
                "alert_patterns": [
                    "redirect",
                    "open redirect",
                    "unvalidated redirect"
                ],
                "alerts": []
            }
        }

        # Categorize alerts
        uncategorized_alerts = []

        for alert in alerts:
            alert_name_lower = alert.alert_name.lower()
            alert_cwe = alert.cwe_id or ""
            categorized = False

            for category_key, category in vuln_categories.items():
                # Check if alert matches by CWE ID
                if alert_cwe in category["cwe_ids"]:
                    category["alerts"].append(alert)
                    categorized = True
                    break

                # Check if alert matches by name pattern
                for pattern in category["alert_patterns"]:
                    if pattern in alert_name_lower:
                        category["alerts"].append(alert)
                        categorized = True
                        break

                if categorized:
                    break

            if not categorized:
                uncategorized_alerts.append(alert)

        # Build categorized results
        vulnerability_tests = {}

        for category_key, category in vuln_categories.items():
            requires_active = category["requires_active"]
            category_alerts = category["alerts"]

            # Check if this test was actually performed
            # Active tests (SQLi, XSS) require FULL scan
            if requires_active and not is_full_scan:
                # Test was not performed - mark as "not_tested"
                vulnerability_tests[category_key] = {
                    "testName": category["name"],
                    "description": category["description"],
                    "status": "not_tested",
                    "passed": None,
                    "tested": False,
                    "reason": "This test requires a FULL scan (active testing). Run a FULL scan to test for this vulnerability.",
                    "totalIssues": 0,
                    "highRisk": 0,
                    "mediumRisk": 0,
                    "lowRisk": 0,
                    "informational": 0,
                    "issues": []
                }
                continue

            # Test was performed - analyze results
            # Determine pass/fail status
            # For headers: fail if ANY issues found (missing or misconfigured)
            # For SQLi, XSS, Redirects: fail if HIGH or MEDIUM risk issues found
            if category_key == "headers":
                # Any header issue is a concern
                has_issues = len(category_alerts) > 0
                high_risk_count = sum(1 for a in category_alerts if a.risk_level.value == "high")
                medium_risk_count = sum(1 for a in category_alerts if a.risk_level.value == "medium")
                low_risk_count = sum(1 for a in category_alerts if a.risk_level.value == "low")
                info_count = sum(1 for a in category_alerts if a.risk_level.value == "informational")

                # Headers: Consider low/informational as warnings, medium/high as failures
                passed = high_risk_count == 0 and medium_risk_count == 0
                status = "passed" if passed else "failed"

            else:
                # SQLi, XSS, Redirects: fail on high or medium risk
                high_risk_alerts = [a for a in category_alerts if a.risk_level.value == "high"]
                medium_risk_alerts = [a for a in category_alerts if a.risk_level.value == "medium"]

                high_risk_count = len(high_risk_alerts)
                medium_risk_count = len(medium_risk_alerts)
                low_risk_count = sum(1 for a in category_alerts if a.risk_level.value == "low")
                info_count = sum(1 for a in category_alerts if a.risk_level.value == "informational")

                passed = high_risk_count == 0 and medium_risk_count == 0
                status = "passed" if passed else "failed"

            # Format alerts for this category
            formatted_alerts = []
            total_alerts_in_category = len(category_alerts)
            alerts_to_include = category_alerts[:max_issues_per_category] if include_details else []
            
            if include_details:
                for alert in alerts_to_include:
                    formatted_alert = {
                        "id": alert.id,
                        "name": alert.alert_name,
                        "riskLevel": alert.risk_level.value,
                        "confidence": alert.confidence,
                        "url": alert.url,
                        "method": alert.method or "GET",
                        "param": alert.param,
                        "cweId": alert.cwe_id,
                        "wascId": alert.wasc_id
                    }
                    # Add full details (can be large)
                    formatted_alert.update({
                        "attack": alert.attack,
                        "evidence": alert.evidence,
                        "description": alert.description,
                        "solution": alert.solution,
                        "reference": alert.reference,
                        "otherInfo": alert.other_info,
                        "createdAt": cast(datetime, alert.created_at).isoformat() if alert.created_at is not None else None
                    })
                    formatted_alerts.append(formatted_alert)

            test_result = {
                "testName": category["name"],
                "description": category["description"],
                "status": status,
                "passed": passed,
                "tested": True,
                "totalIssues": total_alerts_in_category,
                "highRisk": high_risk_count,
                "mediumRisk": medium_risk_count,
                "lowRisk": low_risk_count,
                "informational": info_count
            }
            
            if include_details:
                test_result["issues"] = formatted_alerts
                if total_alerts_in_category > max_issues_per_category:
                    test_result["issuesTruncated"] = True
                    test_result["issuesShown"] = len(formatted_alerts)
                    test_result["issuesTotal"] = total_alerts_in_category
            
            vulnerability_tests[category_key] = test_result

        # Format other/uncategorized alerts
        other_alerts = []
        other_high = 0
        other_medium = 0
        other_low = 0
        other_info = 0
        
        # Count risk levels first
        for alert in uncategorized_alerts:
            risk = alert.risk_level.value
            if risk == "high":
                other_high += 1
            elif risk == "medium":
                other_medium += 1
            elif risk == "low":
                other_low += 1
            else:
                other_info += 1
        
        # Format alerts if details requested
        total_other_alerts = len(uncategorized_alerts)
        other_alerts_to_include = uncategorized_alerts[:max_issues_per_category] if include_details else []
        
        if include_details:
            for alert in other_alerts_to_include:
                formatted_alert = {
                    "id": alert.id,
                    "name": alert.alert_name,
                    "riskLevel": alert.risk_level.value,
                    "confidence": alert.confidence,
                    "url": alert.url,
                    "method": alert.method or "GET",
                    "param": alert.param,
                    "cweId": alert.cwe_id,
                    "wascId": alert.wasc_id
                }
                # Add full details
                formatted_alert.update({
                    "attack": alert.attack,
                    "evidence": alert.evidence,
                    "description": alert.description,
                    "solution": alert.solution,
                    "reference": alert.reference,
                    "otherInfo": alert.other_info,
                    "createdAt": cast(datetime, alert.created_at).isoformat() if alert.created_at is not None else None
                })
                other_alerts.append(formatted_alert)

        # Calculate overall status (only consider tests that were actually performed)
        tested_results = [test for test in vulnerability_tests.values() if test.get("tested", True)]
        all_tests_passed = all(test["passed"] for test in tested_results if test["passed"] is not None)
        critical_failures = sum(test["highRisk"] for test in vulnerability_tests.values())

        # Build comprehensive report
        report = {
            "scan": {
                "id": scan.id,
                "targetUrl": str(scan.target_url),
                "scanType": scan.scan_type.value,
                "status": scan.status.value,
                "startedAt": cast(datetime, scan.started_at).isoformat() if scan.started_at is not None else None,
                "completedAt": cast(datetime, scan.completed_at).isoformat() if scan.completed_at is not None else None,
                "duration": None
            },
            "overallStatus": {
                "passed": all_tests_passed,
                "status": "passed" if all_tests_passed else "failed",
                "criticalIssues": critical_failures,
                "message": "All security tests passed! Your website is secure." if all_tests_passed
                          else f"Security issues detected! Found {critical_failures} critical vulnerabilities."
            },
            "summary": {
                "totalAlerts": scan.total_alerts,
                "highRisk": scan.high_risk_count,
                "mediumRisk": scan.medium_risk_count,
                "lowRisk": scan.low_risk_count,
                "informational": scan.info_count,
                "uniqueUrls": len(set(alert.url for alert in alerts))
            },
            "vulnerabilityTests": vulnerability_tests,
            "otherVulnerabilities": {
                "totalIssues": total_other_alerts,
                "highRisk": other_high,
                "mediumRisk": other_medium,
                "lowRisk": other_low,
                "informational": other_info,
                **({"issues": other_alerts} if include_details else {}),
                **({"issuesTruncated": True, "issuesShown": len(other_alerts), "issuesTotal": total_other_alerts} 
                   if include_details and total_other_alerts > max_issues_per_category else {})
            },
            "site": {
                "host": parsed_url.hostname or "unknown",
                "port": parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
                "protocol": parsed_url.scheme,
                "ssl": parsed_url.scheme == 'https'
            },
            "generatedAt": datetime.utcnow().isoformat(),
            "reportVersion": "2.0"
        }

        # Calculate duration if available
        if scan.started_at is not None and scan.completed_at is not None:
            duration = (cast(datetime, scan.completed_at) - cast(datetime, scan.started_at)).total_seconds()
            report["scan"]["duration"] = f"{int(duration)} seconds"

        logger.info(f"Successfully formatted scan {scan.id} to categorized report")
        return report

    @staticmethod
    def _get_zap_version() -> str:
        """
        Get the actual ZAP version from the running instance.
        Falls back to a default version if connection fails.
        """
        try:
            from zapv2 import ZAPv2
            from app.core.config import ZAPConfig

            zap_client = ZAPv2(
                apikey=ZAPConfig.ZAP_API_KEY,
                proxies={
                    "http": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                    "https": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                }
            )
            version = zap_client.core.version
            logger.debug(f"Retrieved ZAP version: {version}")
            return version
        except Exception as e:
            logger.warning(f"Failed to get ZAP version, using default: {e}")
            return "2.16.1"  # Fallback version
