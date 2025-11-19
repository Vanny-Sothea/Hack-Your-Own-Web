from celery import Task
from datetime import datetime
from typing import Dict, Any, Optional
from app.core.celery_app import celery_app
from app.models.scan import Scan, ScanAlert, ScanStatus, ScanType, RiskLevel
from app.core.db import AsyncSessionLocal
from app.utils.logger import logger
from sqlalchemy import select
import asyncio

# Import the scanner instance manager
from app.services.scanner_manager import scanner_manager

# Import metrics collector
from app.services.metrics import metrics_collector


class ScanTask(Task):
    """Base task with error handling and cleanup"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure - just log, don't try to update DB"""
        logger.error(f"Task {task_id} failed: {exc}")
        # Don't try to update DB here as it causes connection conflicts
        # The scan will remain in IN_PROGRESS state and can be cleaned up separately


@celery_app.task(bind=True, base=ScanTask, name="app.tasks.scan_tasks.run_scan")
def run_scan(self, scan_id: int, target_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute a security scan using OWASP ZAP

    Args:
        scan_id: Database ID of the scan
        target_url: Target URL being scanned (displayed in Flower kwargs)

    Returns:
        Dictionary with scan results summary
    """
    logger.info(f"Starting scan task for scan_id: {scan_id}, target: {target_url or 'Unknown'}")

    # Run async function in sync context
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(_run_scan_async(scan_id, self))
        return result
    finally:
        loop.close()


async def _run_scan_async(scan_id: int, task: Task) -> Dict[str, Any]:
    """Async implementation of scan execution"""
    logger.info(f"Starting async scan execution for scan {scan_id}")

    # Use a single session for the entire scan to avoid connection conflicts
    async with AsyncSessionLocal() as session:
        # Get scan details
        result = await session.execute(select(Scan).filter_by(id=scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            error_msg = f"Scan with id {scan_id} not found"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Validate scan type
        if scan.scan_type not in [ScanType.BASIC, ScanType.FULL]:
            error_msg = f"Invalid scan type {scan.scan_type} for scan {scan_id}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Update scan status to in_progress
        scan.status = ScanStatus.IN_PROGRESS  # type: ignore[assignment]
        scan.started_at = datetime.utcnow()  # type: ignore[assignment]
        scan.celery_task_id = task.request.id
        session.add(scan)
        await session.commit()

        logger.info(f"Scan {scan_id} marked as IN_PROGRESS")

        # Start metrics collection
        metrics_collector.start_scan(scan_id)

        try:
            # Get an optimized scanner instance with pooled connection
            # This reuses the persistent ZAP instance and creates an isolated context
            scanner = scanner_manager.get_scanner(scan_id)
            logger.info(f"Using optimized scanner with connection pooling for scan {scan_id}")

            # Run appropriate scan type (no progress tracking for better performance)
            alerts = []
            if scan.scan_type == ScanType.BASIC:  # type: ignore[comparison-overlap]
                logger.info(f"Running BASIC scan for scan {scan_id}")
                alerts = scanner.run_basic_scan(str(scan.target_url))
            elif scan.scan_type == ScanType.FULL:  # type: ignore[comparison-overlap]
                logger.info(f"Running FULL scan for scan {scan_id}")
                alerts = scanner.run_full_scan(str(scan.target_url))
            else:
                error_msg = f"Invalid scan type: {scan.scan_type}"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Process and store alerts with timing
            logger.info(f"Scan {scan_id}: Processing {len(alerts)} alerts...")
            await _process_alerts(session, scan, alerts)
            logger.info(f"Scan {scan_id}: Committing alerts to database...")
            await session.commit()  # Commit alerts first
            logger.info(f"Scan {scan_id}: Alert processing complete")

            # Clean up the ZAP context for this scan
            scanner_manager.cleanup_scan_context(scan_id)
            logger.debug(f"Cleaned up scan context for scan {scan_id}")

            # Update scan completion (separate transaction for faster write)
            scan.status = ScanStatus.COMPLETED  # type: ignore[assignment]
            scan.completed_at = datetime.utcnow()  # type: ignore[assignment]
            scan.progress_percentage = 100  # type: ignore[assignment]
            scan.current_step = "Completed"  # type: ignore[assignment]
            scan.updated_at = datetime.utcnow()  # type: ignore[assignment]
            session.add(scan)
            await session.commit()  # Quick final commit for scan status

            logger.info(f"Scan {scan_id} completed successfully with {scan.total_alerts} alerts")

            # Record metrics for successful completion
            metrics_collector.complete_scan(
                scan_id=scan_id,
                total_alerts=scan.total_alerts or 0,  # type: ignore[arg-type]
                high_risk=scan.high_risk_count or 0,  # type: ignore[arg-type]
                medium_risk=scan.medium_risk_count or 0,  # type: ignore[arg-type]
                low_risk=scan.low_risk_count or 0,  # type: ignore[arg-type]
                status="completed"
            )

            return {
                "scan_id": scan_id,
                "status": "completed",
                "total_alerts": scan.total_alerts,
                "high_risk": scan.high_risk_count,
                "medium_risk": scan.medium_risk_count,
                "low_risk": scan.low_risk_count,
            }

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")

            # Record metrics for failure
            metrics_collector.complete_scan(
                scan_id=scan_id,
                status="failed",
                error_message=str(e)
            )

            # Clean up the ZAP context even on failure
            try:
                scanner_manager.cleanup_scan_context(scan_id)
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup scan context: {cleanup_error}")

            # Refresh the scan object to avoid detached instance errors
            await session.refresh(scan)
            scan.status = ScanStatus.FAILED  # type: ignore[assignment]
            scan.error_message = str(e)  # type: ignore[assignment]
            scan.completed_at = datetime.utcnow()  # type: ignore[assignment]
            scan.updated_at = datetime.utcnow()  # type: ignore[assignment]
            session.add(scan)
            await session.commit()
            raise


async def _process_alerts(session, scan: Scan, alerts: list):
    """
    Process and store ZAP alerts in database with optimized batch operations.
    Uses bulk insert for much faster performance (5-10x faster than individual adds).
    Implements deduplication to avoid storing duplicate alerts.
    """
    import hashlib

    risk_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    # Map ZAP risk levels to our enum (defined once outside loop)
    risk_mapping = {
        "3": RiskLevel.HIGH,
        "2": RiskLevel.MEDIUM,
        "1": RiskLevel.LOW,
        "0": RiskLevel.INFORMATIONAL,
        "High": RiskLevel.HIGH,
        "Medium": RiskLevel.MEDIUM,
        "Low": RiskLevel.LOW,
        "Informational": RiskLevel.INFORMATIONAL,
    }

    # Deduplication: Track unique alerts by hash
    seen_hashes = set()
    alert_objects = []

    for alert in alerts:
        # Create a unique hash for this alert based on key identifying fields
        # This prevents duplicate alerts for the same issue on the same URL
        alert_key = f"{alert.get('alert')}|{alert.get('url')}|{alert.get('param')}|{alert.get('evidence')}"
        alert_hash = hashlib.sha256(alert_key.encode()).hexdigest()

        # Skip if we've already seen this exact alert
        if alert_hash in seen_hashes:
            logger.debug(f"Skipping duplicate alert: {alert.get('alert')} on {alert.get('url')}")
            continue

        seen_hashes.add(alert_hash)

        risk_str = str(alert.get("risk", "0"))
        risk_level = risk_mapping.get(risk_str, RiskLevel.INFORMATIONAL)

        # Count by risk level
        risk_counts[risk_level.value] += 1

        # Create alert record
        scan_alert = ScanAlert(
            scan_id=scan.id,
            alert_name=alert.get("alert", "Unknown Alert"),
            risk_level=risk_level,
            confidence=alert.get("confidence", "Unknown"),
            description=alert.get("description"),
            solution=alert.get("solution"),
            reference=alert.get("reference"),
            cwe_id=str(alert.get("cweid")) if alert.get("cweid") else None,
            wasc_id=str(alert.get("wascid")) if alert.get("wascid") else None,
            url=alert.get("url", ""),
            method=alert.get("method"),
            param=alert.get("param"),
            attack=alert.get("attack"),
            evidence=alert.get("evidence"),
            other_info=alert.get("other"),
            alert_tags=alert.get("tags"),
        )
        alert_objects.append(scan_alert)

    # Log deduplication stats
    original_count = len(alerts)
    deduplicated_count = len(alert_objects)
    if original_count > deduplicated_count:
        logger.info(f"Deduplication: {original_count} alerts -> {deduplicated_count} unique alerts (removed {original_count - deduplicated_count} duplicates)")

    # Bulk insert all alerts at once (single DB roundtrip instead of N roundtrips)
    if alert_objects:
        session.add_all(alert_objects)
        logger.info(f"Bulk inserting {len(alert_objects)} unique alerts for scan {scan.id}")

    # Update scan summary
    scan.total_alerts = len(alert_objects)  # type: ignore[assignment]
    scan.high_risk_count = risk_counts["high"]  # type: ignore[assignment]
    scan.medium_risk_count = risk_counts["medium"]  # type: ignore[assignment]
    scan.low_risk_count = risk_counts["low"]  # type: ignore[assignment]
    scan.info_count = risk_counts["informational"]  # type: ignore[assignment]
    session.add(scan)


@celery_app.task(bind=True, base=ScanTask, name="app.tasks.scan_tasks.cancel_scan")
def cancel_scan(self, scan_id: int) -> Dict[str, Any]:
    """
    Cancel a running scan

    Args:
        scan_id: Database ID of the scan

    Returns:
        Dictionary with cancellation status
    """
    logger.info(f"Cancelling scan task for scan_id: {scan_id}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(_cancel_scan_async(scan_id))
        return result
    finally:
        loop.close()


async def _cancel_scan_async(scan_id: int) -> Dict[str, Any]:
    """Async implementation of scan cancellation"""

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Scan).filter_by(id=scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            raise ValueError(f"Scan with id {scan_id} not found")

        if scan.status not in [ScanStatus.PENDING, ScanStatus.IN_PROGRESS]:  # type: ignore[comparison-overlap]
            return {
                "scan_id": scan_id,
                "status": "not_cancellable",
                "message": f"Scan is in {scan.status} state and cannot be cancelled"
            }

        # Revoke Celery task if it exists
        if scan.celery_task_id is not None:
            celery_app.control.revoke(scan.celery_task_id, terminate=True)

        # Update scan status
        scan.status = ScanStatus.CANCELLED  # type: ignore[assignment]
        scan.completed_at = datetime.utcnow()  # type: ignore[assignment]
        scan.updated_at = datetime.utcnow()  # type: ignore[assignment]
        scan.error_message = "Scan cancelled by user"  # type: ignore[assignment]
        session.add(scan)
        await session.commit()

        logger.info(f"Scan {scan_id} cancelled successfully")

        return {
            "scan_id": scan_id,
            "status": "cancelled",
            "message": "Scan cancelled successfully"
        }
