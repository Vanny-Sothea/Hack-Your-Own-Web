from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi.responses import JSONResponse
from app.models.scan import Scan, ScanAlert, ScanStatus, ScanType
from app.schemas.scan import BasicScanCreate, FullScanCreate, ScanUpdate
from app.utils.logger import logger
from app.tasks.scan_tasks import run_scan as run_scan_task


async def create_basic_scan_crud(
    data: BasicScanCreate,
    user_id: int,
    session: AsyncSession
) -> JSONResponse:
    """Create a new basic scan (passive only, no domain verification required)"""
    logger.info(f"Basic scan creation endpoint hit for user {user_id}")

    try:
        # Check concurrent scan limit (max 5 active scans per user)
        active_scans_query = select(func.count()).select_from(Scan).where(
            and_(
                Scan.user_id == user_id,
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.IN_PROGRESS.value])
            )
        )
        active_scans_result = await session.execute(active_scans_query)
        active_scans_count = active_scans_result.scalar() or 0

        if active_scans_count >= 5:
            logger.warning(f"User {user_id} has reached max concurrent scans limit ({active_scans_count}/5)")
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "message": "Maximum concurrent scans limit reached (5). Please wait for existing scans to complete."
                }
            )

        # Create scan record with BASIC type
        scan = Scan(
            user_id=user_id,
            target_url=str(data.target_url),
            scan_type=ScanType.BASIC,
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # Queue scan task
        task = run_scan_task.apply_async(
            kwargs={"scan_id": scan.id, "target_url": str(data.target_url)}
        )

        # Update scan with task ID
        scan.celery_task_id = task.id
        session.add(scan)
        await session.commit()

        logger.info(f"Basic scan {scan.id} created and queued successfully with task {task.id}")

        return JSONResponse(
            status_code=201,
            content={
                "success": True,
                "message": "Basic scan created and queued successfully",
                "data": {
                    "scan_id": scan.id,
                    "task_id": task.id,
                    "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
                    "scan_type": scan.scan_type.value if hasattr(scan.scan_type, 'value') else scan.scan_type
                }
            }
        )

    except Exception as e:
        logger.error(f"Error creating basic scan: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def create_full_scan_crud(
    data: FullScanCreate,
    user_id: int,
    session: AsyncSession
) -> JSONResponse:
    """Create a new full scan (active scan, domain verification handled by middleware)"""
    logger.info(f"Full scan creation endpoint hit for user {user_id}")

    try:
        # NOTE: Domain verification (DB + DNS checks) is handled by 
        # verify_site_ownership middleware in the API endpoint.
        
        # Check concurrent scan limit (max 5 active scans per user)
        active_scans_query = select(func.count()).select_from(Scan).where(
            and_(
                Scan.user_id == user_id,
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.IN_PROGRESS.value])
            )
        )
        active_scans_result = await session.execute(active_scans_query)
        active_scans_count = active_scans_result.scalar() or 0

        if active_scans_count >= 5:
            logger.warning(f"User {user_id} has reached max concurrent scans limit ({active_scans_count}/5)")
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "message": "Maximum concurrent scans limit reached (5). Please wait for existing scans to complete."
                }
            )

        # Create scan record with FULL type
        scan = Scan(
            user_id=user_id,
            target_url=str(data.target_url),
            scan_type=ScanType.FULL,
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # Queue scan task
        task = run_scan_task.apply_async(
            kwargs={"scan_id": scan.id, "target_url": str(data.target_url)}
        )

        # Update scan with task ID
        scan.celery_task_id = task.id
        session.add(scan)
        await session.commit()

        logger.info(f"Full scan {scan.id} created and queued successfully with task {task.id}")

        return JSONResponse(
            status_code=201,
            content={
                "success": True,
                "message": "Full scan created and queued successfully",
                "data": {
                    "scan_id": scan.id,
                    "task_id": task.id,
                    "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
                    "scan_type": scan.scan_type.value if hasattr(scan.scan_type, 'value') else scan.scan_type
                }
            }
        )

    except Exception as e:
        logger.error(f"Error creating full scan: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def get_scan_by_id_crud(
    scan_id: int,
    user_id: int,
    session: AsyncSession,
    include_alerts: bool = False
) -> Optional[Scan]:
    """Get scan by ID (with user ownership check)"""
    logger.info(f"Fetching scan {scan_id} for user {user_id}")

    try:
        query = select(Scan).where(
            and_(Scan.id == scan_id, Scan.user_id == user_id)
        )

        # Eagerly load alerts if requested
        if include_alerts:
            # Scan.alerts is a RelationshipProperty, but Pylance sees it as List[ScanAlert]
            query = query.options(selectinload(Scan.alerts))  # type: ignore[arg-type]

        result = await session.execute(query)
        scan = result.scalar_one_or_none()

        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return None

        if scan and include_alerts:
            logger.info(f"Loaded {len(scan.alerts)} alerts for scan {scan_id}")

        return scan

    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        return None


async def get_user_scans_crud(
    user_id: int,
    session: AsyncSession,
    status: Optional[ScanStatus] = None,
    scan_type: Optional[ScanType] = None,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[Scan], int]:
    """Get all scans for a user with pagination and filtering"""
    logger.info(f"Fetching scans for user {user_id} (page {page}, size {page_size})")

    try:
        # Build query
        query = select(Scan).where(Scan.user_id == user_id)

        if status:
            query = query.where(Scan.status == status)
            logger.info(f"Filtering by status: {status}")
        if scan_type:
            query = query.where(Scan.scan_type == scan_type)
            logger.info(f"Filtering by scan type: {scan_type}")

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await session.execute(count_query)
        total = total_result.scalar()

        # Apply pagination and ordering
        query = query.order_by(desc(Scan.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await session.execute(query)
        scans = list(result.scalars().all())

        logger.info(f"Retrieved {len(scans)} scans (total: {total or 0})")
        return scans, total or 0

    except Exception as e:
        logger.error(f"Error getting user scans: {e}")
        return [], 0


async def update_scan_crud(
    scan_id: int,
    user_id: int,
    data: ScanUpdate,
    session: AsyncSession
) -> JSONResponse:
    """Update scan details"""
    logger.info(f"Update scan endpoint hit for scan {scan_id}")

    try:
        scan = await get_scan_by_id_crud(scan_id, user_id, session)
        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "Scan not found"}
            )

        # Update fields
        if data.status is not None:
            scan.status = data.status  # type: ignore[assignment]
        if data.progress_percentage is not None:
            scan.progress_percentage = data.progress_percentage  # type: ignore[assignment]
        if data.current_step is not None:
            scan.current_step = data.current_step  # type: ignore[assignment]
        if data.error_message is not None:
            scan.error_message = data.error_message  # type: ignore[assignment]

        scan.updated_at = datetime.utcnow()  # type: ignore[assignment]
        session.add(scan)
        await session.commit()

        logger.info(f"Scan {scan_id} updated successfully")
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Scan updated successfully"
            }
        )

    except Exception as e:
        logger.error(f"Error updating scan {scan_id}: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def delete_scan_crud(
    scan_id: int,
    user_id: int,
    session: AsyncSession
) -> JSONResponse:
    """Delete a scan and its alerts"""
    logger.info(f"Delete scan endpoint hit for scan {scan_id}")

    try:
        scan = await get_scan_by_id_crud(scan_id, user_id, session)
        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "Scan not found"}
            )

        # Cannot delete in-progress scans
        if scan.status == ScanStatus.IN_PROGRESS:  # type: ignore[comparison-overlap]
            logger.warning(f"Attempt to delete in-progress scan {scan_id}")
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": "Cannot delete scan in progress. Cancel it first"
                }
            )

        await session.delete(scan)
        await session.commit()

        logger.info(f"Scan {scan_id} deleted successfully")

        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Scan deleted successfully"
            }
        )

    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def cancel_scan_crud(
    scan_id: int,
    user_id: int,
    session: AsyncSession
) -> JSONResponse:
    """Cancel a running scan"""
    logger.info(f"Cancel scan endpoint hit for scan {scan_id}")

    from app.tasks.scan_tasks import cancel_scan as cancel_scan_task

    try:
        scan = await get_scan_by_id_crud(scan_id, user_id, session)
        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "Scan not found"}
            )

        if scan.status not in [ScanStatus.PENDING, ScanStatus.IN_PROGRESS]:
            logger.warning(f"Attempt to cancel scan {scan_id} with status {scan.status}")
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": f"Scan is {scan.status} and cannot be cancelled"
                }
            )

        # Queue cancellation task
        cancel_scan_task.apply_async(kwargs={"scan_id": scan_id})

        logger.info(f"Scan {scan_id} cancellation requested successfully")
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Scan cancellation requested"
            }
        )

    except Exception as e:
        logger.error(f"Error cancelling scan {scan_id}: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def get_scan_stats_crud(
    user_id: int,
    session: AsyncSession
) -> dict:
    """Get scan statistics for a user"""
    logger.info(f"Fetching scan statistics for user {user_id}")

    try:
        # Total scans
        total_query = select(func.count()).select_from(Scan).where(Scan.user_id == user_id)
        total_result = await session.execute(total_query)
        total_scans = total_result.scalar()

        # Scans by status
        status_counts = {}
        for status in ScanStatus:
            count_query = select(func.count()).select_from(Scan).where(
                and_(Scan.user_id == user_id, Scan.status == status)
            )
            count_result = await session.execute(count_query)
            status_counts[status.value] = count_result.scalar()

        # Vulnerability counts (from completed scans)
        vuln_query = select(
            func.sum(Scan.total_alerts),
            func.sum(Scan.high_risk_count),
            func.sum(Scan.medium_risk_count),
            func.sum(Scan.low_risk_count),
        ).where(
            and_(
                Scan.user_id == user_id,
                Scan.status == ScanStatus.COMPLETED
            )
        )
        vuln_result = await session.execute(vuln_query)
        vuln_data = vuln_result.one()

        stats = {
            "total_scans": total_scans or 0,
            "pending_scans": status_counts.get(ScanStatus.PENDING.value, 0),
            "in_progress_scans": status_counts.get(ScanStatus.IN_PROGRESS.value, 0),
            "completed_scans": status_counts.get(ScanStatus.COMPLETED.value, 0),
            "failed_scans": status_counts.get(ScanStatus.FAILED.value, 0),
            "total_vulnerabilities": vuln_data[0] or 0,
            "high_risk_vulnerabilities": vuln_data[1] or 0,
            "medium_risk_vulnerabilities": vuln_data[2] or 0,
            "low_risk_vulnerabilities": vuln_data[3] or 0,
        }

        logger.info(f"Successfully retrieved stats for user {user_id}")
        return stats

    except Exception as e:
        logger.error(f"Error getting scan stats for user {user_id}: {e}")
        return {
            "total_scans": 0,
            "pending_scans": 0,
            "in_progress_scans": 0,
            "completed_scans": 0,
            "failed_scans": 0,
            "total_vulnerabilities": 0,
            "high_risk_vulnerabilities": 0,
            "medium_risk_vulnerabilities": 0,
            "low_risk_vulnerabilities": 0,
        }


async def get_scan_report_json_crud(
    scan_id: int,
    user_id: int,
    session: AsyncSession
) -> Optional[Dict[str, Any]]:
    """
    Generate ZAP-compatible JSON report for a scan

    Args:
        scan_id: Scan ID
        user_id: User ID (for ownership verification)
        session: Database session

    Returns:
        Dictionary in ZAP JSON format, or None if scan not found
    """
    from app.utils.report_formatter import ZAPReportFormatter

    logger.info(f"Generating JSON report for scan {scan_id}, user {user_id}")

    try:
        # Get scan with alerts
        scan = await get_scan_by_id_crud(scan_id, user_id, session, include_alerts=True)

        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return None

        # Only generate reports for completed scans
        # Type checker note: scan.status is a loaded enum value, not a ColumnElement
        if scan.status is not ScanStatus.COMPLETED:  # type: ignore[comparison-overlap]
            logger.warning(f"Scan {scan_id} is not completed (status: {scan.status})")
            return None

        # Format scan to JSON report
        report = ZAPReportFormatter.format_scan_to_json(scan, scan.alerts)

        logger.info(f"Successfully generated JSON report for scan {scan_id}")
        return report

    except Exception as e:
        logger.error(f"Error generating JSON report for scan {scan_id}: {e}")
        return None


async def get_scan_report_frontend_json_crud(
    scan_id: int,
    user_id: int,
    session: AsyncSession
) -> Optional[Dict[str, Any]]:
    """
    Generate frontend-friendly JSON report for a scan

    Args:
        scan_id: Scan ID
        user_id: User ID (for ownership verification)
        session: Database session

    Returns:
        Dictionary optimized for frontend, or None if scan not found
    """
    from app.utils.report_formatter import ZAPReportFormatter

    logger.info(f"Generating frontend JSON report for scan {scan_id}, user {user_id}")

    try:
        # Get scan with alerts
        scan = await get_scan_by_id_crud(scan_id, user_id, session, include_alerts=True)

        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return None

        # Only generate reports for completed scans
        # Type checker note: scan.status is a loaded enum value, not a ColumnElement
        if scan.status is not ScanStatus.COMPLETED:  # type: ignore[comparison-overlap]
            logger.warning(f"Scan {scan_id} is not completed (status: {scan.status})")
            return None

        # Format scan to frontend JSON report
        report = ZAPReportFormatter.format_scan_to_frontend_json(scan, scan.alerts)

        logger.info(f"Successfully generated frontend JSON report for scan {scan_id}")
        return report

    except Exception as e:
        logger.error(f"Error generating frontend JSON report for scan {scan_id}: {e}")
        return None


async def get_scan_report_categorized_crud(
    scan_id: int,
    user_id: int,
    session: AsyncSession,
    include_details: bool = True,
    max_issues_per_category: int = 100
) -> Optional[Dict[str, Any]]:
    """
    Generate categorized report with pass/fail status for vulnerability types

    This report provides clear pass/fail indicators for:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Security Headers
    - Open Redirects

    Args:
        scan_id: Scan ID
        user_id: User ID (for ownership verification)
        session: Database session
        include_details: Include full issue details in response
        max_issues_per_category: Maximum number of issues to include per category

    Returns:
        Dictionary with categorized vulnerabilities and pass/fail status, or None if scan not found
    """
    from app.utils.report_formatter import ZAPReportFormatter

    logger.info(f"Generating categorized report for scan {scan_id}, user {user_id}")

    try:
        # Get scan with alerts
        scan = await get_scan_by_id_crud(scan_id, user_id, session, include_alerts=True)

        if not scan:
            logger.warning(f"Scan {scan_id} not found for user {user_id}")
            return None

        # Only generate reports for completed scans
        # Type checker note: scan.status is a loaded enum value, not a ColumnElement
        if scan.status is not ScanStatus.COMPLETED:  # type: ignore[comparison-overlap]
            logger.warning(f"Scan {scan_id} is not completed (status: {scan.status})")
            return None

        # Format scan to categorized report
        report = ZAPReportFormatter.format_scan_to_categorized_report(
            scan, 
            scan.alerts,
            include_details=include_details,
            max_issues_per_category=max_issues_per_category
        )

        logger.info(f"Successfully generated categorized report for scan {scan_id}")
        return report

    except Exception as e:
        logger.error(f"Error generating categorized report for scan {scan_id}: {e}")
        return None
