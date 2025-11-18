from fastapi import APIRouter, status, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from app.core.db import get_session
from app.schemas.scan import (
    BasicScanCreate,
    FullScanCreate,
    ScanResponse,
    ScanDetailResponse,
    ScanFullDetailResponse,
    ScanListResponse,
    ScanStatsResponse,
    AnonymousScanCreate,
    AnonymousScanResponse,
)
from app.schemas.site import ValidDomainSchema
from app.models.scan import ScanStatus, ScanType
from app.models.user import User
from app.crud.scan import (
    create_basic_scan_crud,
    create_full_scan_crud,
    get_scan_by_id_crud,
    get_user_scans_crud,
    delete_scan_crud,
    cancel_scan_crud,
    get_scan_stats_crud,
    get_scan_report_json_crud,
    get_scan_report_frontend_json_crud,
    get_scan_report_categorized_crud,
)
from app.middleware.auth_middleware import get_current_user
from app.middleware.site_middleware import verify_site_ownership
from app.services.anonymous_scanner import AnonymousScannerService
from fastapi.responses import JSONResponse, Response
import json


router = APIRouter()


@router.post("/anonymous", status_code=status.HTTP_200_OK, response_model=AnonymousScanResponse)
async def create_anonymous_scan(data: AnonymousScanCreate):
    """
    Run an anonymous basic security scan (NO AUTHENTICATION REQUIRED)

    This endpoint allows anyone to perform a basic security scan without creating an account.
    Perfect for landing pages where users want to try the scanner before signing up.

    **Features:**
    - No authentication required
    - No signup needed
    - Results returned immediately (synchronous)
    - No data stored in database
    - Basic scan only (Spider + Passive)

    **What it scans for:**
    - HTTP Security Headers (CSP, HSTS, X-Frame-Options, etc.)
    - SSL/TLS Configuration Issues
    - Cookie Security (HttpOnly, Secure, SameSite flags)
    - Information Disclosure (Server banners, error messages, comments)
    - Open Redirects
    - Authentication/Session Management Issues
    - And more passive vulnerabilities

    **Limitations:**
    - Basic scan only (no active testing)
    - No scan history (results not saved)
    - May take 30-90 seconds to complete
    - Single scan at a time per request

    **Note:** For advanced features like active scanning, scan history, and reports,
    please create an account and use the authenticated endpoints.

    - **target_url**: The URL to scan (must be http:// or https://)

    Returns:
    - **200**: Scan completed successfully with results
    - **400**: Invalid URL format or scan error
    - **500**: Internal server error
    """
    try:
        # Run the scan (this will block until complete)
        scan_result = await AnonymousScannerService.run_anonymous_scan(str(data.target_url))
        
        # Check if scan had errors
        if "error" in scan_result:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": f"Scan failed: {scan_result['error']}",
                    "scan_data": scan_result
                }
            )
        
        # Return successful result
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Scan completed successfully",
                "scan_data": scan_result
            }
        )
        
    except Exception as e:
        # Log the error
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Anonymous scan endpoint error: {e}")
        
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "Internal server error occurred during scan",
                "scan_data": {
                    "target_url": str(data.target_url),
                    "error": str(e)
                }
            }
        )


@router.post("/basic", status_code=status.HTTP_201_CREATED)
async def create_basic_scan(
    data: BasicScanCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Create a basic security scan (Spider + Passive scan)

    Basic scans are non-invasive and do NOT require domain verification.
    They perform:
    - Spider crawling to discover pages
    - Passive vulnerability detection (no attacks)

    - **target_url**: The URL to scan (must be http:// or https://)

    Returns:
    - **201**: Scan created and queued successfully
    - **400**: Invalid URL format
    - **401**: Unauthorized
    - **429**: Too many concurrent scans
    - **500**: Internal server error
    """
    return await create_basic_scan_crud(data, user.id, session)  # type: ignore[arg-type]


@router.post("/full", status_code=status.HTTP_201_CREATED)
async def create_full_scan(
    data: FullScanCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Create a full security scan (Spider + Passive + Active scan)

    Full scans perform active security testing and REQUIRE domain verification.
    They perform:
    - Spider crawling to discover pages
    - Passive vulnerability detection
    - Active vulnerability scanning (attacks)

    **IMPORTANT**: You must verify domain ownership before running a full scan.
    Use the /sites endpoints to register and verify your domain.

    - **target_url**: The URL to scan (must be http:// or https://)

    Returns:
    - **201**: Scan created and queued successfully
    - **400**: Invalid URL format
    - **401**: Unauthorized
    - **403**: Domain not verified or not owned by user
    - **429**: Too many concurrent scans
    - **500**: Internal server error
    """
    from app.utils.domain_utils import extract_domain_from_url
    
    # Extract domain from target URL
    domain_str = extract_domain_from_url(str(data.target_url))
    if not domain_str:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "Invalid URL format. Could not extract domain."
            }
        )
    
    # Create domain schema for verification
    domain = ValidDomainSchema(domain=domain_str)
    
    # Verify domain ownership (checks DB + DNS)
    await verify_site_ownership(domain, user, session)
    
    return await create_full_scan_crud(data, user.id, session)  # type: ignore[arg-type]


@router.get("/", response_model=ScanListResponse)
async def get_scans(
    status_filter: Optional[ScanStatus] = Query(None, alias="status"),
    scan_type: Optional[ScanType] = Query(None, alias="type"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Get all scans for the authenticated user

    - **status**: Filter by scan status (optional)
    - **type**: Filter by scan type (optional)
    - **page**: Page number (default: 1)
    - **page_size**: Number of results per page (default: 20, max: 100)
    """
    scans, total = await get_user_scans_crud(
        user.id, session, status_filter, scan_type, page, page_size  # type: ignore[arg-type]
    )

    return ScanListResponse(
        scans=[ScanResponse.model_validate(scan) for scan in scans],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/stats", response_model=ScanStatsResponse)
async def get_scan_stats(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Get scan statistics for the authenticated user

    Returns summary of:
    - Total scans by status
    - Total vulnerabilities found
    - Vulnerabilities by risk level
    """
    stats = await get_scan_stats_crud(user.id, session)  # type: ignore[arg-type]
    return ScanStatsResponse(**stats)


@router.get("/{scan_id}")
async def get_scan(
    scan_id: int,
    detailed: bool = Query(False, description="Include full alert details (default: false for summary only)"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Get detailed information about a specific scan including alerts

    - **scan_id**: The ID of the scan
    - **detailed**: If true, returns full alert details. If false (default), returns summary alerts only.

    Default response includes lightweight alert summaries (id, alert_name, risk_level, confidence, url, method, cwe_id, created_at).
    Use detailed=true to get full alert information including description, solution, references, etc.
    """
    scan = await get_scan_by_id_crud(scan_id, user.id, session, include_alerts=True)  # type: ignore[arg-type]

    if not scan:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Scan not found"}
        )

    if detailed:
        return ScanFullDetailResponse.model_validate(scan)
    else:
        return ScanDetailResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(
    scan_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Delete a scan and all its alerts

    - **scan_id**: The ID of the scan
    - Cannot delete scans that are currently in progress (cancel first)
    """
    return await delete_scan_crud(scan_id, user.id, session)  # type: ignore[arg-type]


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    scan_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Cancel a running or pending scan

    - **scan_id**: The ID of the scan
    - Only pending or in-progress scans can be cancelled
    """
    return await cancel_scan_crud(scan_id, user.id, session)  # type: ignore[arg-type]


@router.get("/{scan_id}/report/json")
async def get_scan_report_json(
    scan_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Download scan report in ZAP JSON format

    - **scan_id**: The ID of the scan
    - Returns a JSON file in OWASP ZAP report format
    - Only available for completed scans
    - Works for both BASIC and FULL scan types

    The JSON format includes:
    - Program metadata (ZAP version, timestamp)
    - Site information (target URL, host, port, SSL)
    - Detailed alerts with instances (vulnerabilities found)
    - Risk levels, confidence ratings, CWE/WASC IDs
    - Full descriptions, solutions, and references
    """
    report = await get_scan_report_json_crud(scan_id, user.id, session)  # type: ignore[arg-type]

    if not report:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Scan not found or not completed"}
        )

    # Return as downloadable JSON file
    json_str = json.dumps(report, indent=2)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}_report.json"
        }
    )


@router.get("/{scan_id}/report/frontend")
async def get_scan_report_frontend(
    scan_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Get scan report in frontend-optimized JSON format (RECOMMENDED for Web UIs)

    - **scan_id**: The ID of the scan
    - Returns JSON optimized for frontend frameworks (React, Vue, Angular)
    - Only available for completed scans
    - Works for both BASIC and FULL scan types

    This format is HIGHLY RECOMMENDED for frontend developers because it provides:
    - Clean, camelCase field names (JavaScript convention)
    - Pre-grouped alerts by risk level
    - Summary statistics ready for dashboards
    - ISO datetime formats
    - Flat alert structure (no complex nesting)
    - Easy filtering and sorting support
    - All data needed for visualization in one response

    Use this instead of /report/json if you're building a web frontend!
    """
    report = await get_scan_report_frontend_json_crud(scan_id, user.id, session)  # type: ignore[arg-type]

    if not report:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Scan not found or not completed"}
        )

    # Return as JSON (can be downloaded or consumed directly)
    return JSONResponse(content=report)


@router.get("/{scan_id}/report/categorized")
async def get_scan_report_categorized(
    scan_id: int,
    include_details: bool = True,
    max_issues_per_category: int = 100,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """
    Get scan report with categorized vulnerabilities and pass/fail status (BEST for Users)

    - **scan_id**: The ID of the scan
    - **include_details**: Include full issue details (default: true). Set to false for summary only.
    - **max_issues_per_category**: Maximum issues to return per category (default: 100, max: 1000)
    - Returns JSON with clear pass/fail status for each vulnerability type
    - Only available for completed scans
    - Works for both BASIC and FULL scan types

    This format is HIGHLY RECOMMENDED for users who want to:
    - Quickly understand if their website passed or failed security tests
    - See clear categorization of vulnerabilities:
      * SQL Injection (SQLi)
      * Cross-Site Scripting (XSS)
      * Security Headers
      * Open Redirects
    - Get actionable security insights with risk levels
    - Understand overall security posture at a glance

    Each vulnerability test shows:
    - Pass/Fail status
    - Number of issues (high/medium/low/informational)
    - Detailed list of specific vulnerabilities found (if include_details=true)
    - Solutions and references for remediation

    **Performance Tips:**
    - For large reports in Swagger UI, use include_details=false to avoid browser crashes
    - Use max_issues_per_category to limit response size
    - For full details, download the report directly via API client

    Perfect for security dashboards and reporting!
    """
    # Validate max_issues_per_category
    if max_issues_per_category > 1000:
        max_issues_per_category = 1000
    elif max_issues_per_category < 1:
        max_issues_per_category = 1

    report = await get_scan_report_categorized_crud(
        scan_id, user.id, session, 
        include_details=include_details,
        max_issues_per_category=max_issues_per_category
    )  # type: ignore[arg-type]

    if not report:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Scan not found or not completed"}
        )

    # Return as JSON
    return JSONResponse(content=report)


scan_router = router
