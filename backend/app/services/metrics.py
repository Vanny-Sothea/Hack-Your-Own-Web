"""
Metrics Collection Service

Collects and exposes performance metrics for monitoring:
- Scan duration
- Queue size
- Alert counts
- Success/failure rates
"""

import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from app.utils.logger import metrics_logger


@dataclass
class ScanMetrics:
    """Metrics for a single scan"""
    scan_id: int
    started_at: float
    completed_at: Optional[float] = None
    duration_seconds: Optional[float] = None
    total_alerts: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    status: str = "in_progress"
    error_message: Optional[str] = None


class MetricsCollector:
    """
    Singleton metrics collector for scan performance monitoring.
    Thread-safe implementation for concurrent scan metrics.
    """

    _instance: Optional["MetricsCollector"] = None
    _lock = Lock()

    def __init__(self):
        self._scan_metrics: Dict[int, ScanMetrics] = {}
        self._completed_scans: list = []
        self._max_completed_history = 1000  # Keep last 1000 completed scans
        self._metrics_lock = Lock()

    @classmethod
    def get_instance(cls) -> "MetricsCollector":
        """Get singleton instance with thread safety"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def start_scan(self, scan_id: int) -> None:
        """Record scan start"""
        with self._metrics_lock:
            self._scan_metrics[scan_id] = ScanMetrics(
                scan_id=scan_id,
                started_at=time.time()
            )
            metrics_logger.info(
                f"Scan {scan_id} started",
                extra={"scan_id": scan_id, "event": "scan_start"}
            )

    def complete_scan(
        self,
        scan_id: int,
        total_alerts: int = 0,
        high_risk: int = 0,
        medium_risk: int = 0,
        low_risk: int = 0,
        status: str = "completed",
        error_message: Optional[str] = None
    ) -> None:
        """Record scan completion"""
        with self._metrics_lock:
            if scan_id not in self._scan_metrics:
                metrics_logger.warning(f"Scan {scan_id} not found in metrics")
                return

            metric = self._scan_metrics[scan_id]
            metric.completed_at = time.time()
            metric.duration_seconds = metric.completed_at - metric.started_at
            metric.total_alerts = total_alerts
            metric.high_risk_count = high_risk
            metric.medium_risk_count = medium_risk
            metric.low_risk_count = low_risk
            metric.status = status
            metric.error_message = error_message

            # Move to completed scans history
            self._completed_scans.append(metric)
            if len(self._completed_scans) > self._max_completed_history:
                self._completed_scans.pop(0)  # Remove oldest

            # Remove from active scans
            del self._scan_metrics[scan_id]

            metrics_logger.info(
                f"Scan {scan_id} {status} in {metric.duration_seconds:.2f}s with {total_alerts} alerts",
                extra={
                    "scan_id": scan_id,
                    "event": "scan_complete",
                    "duration": metric.duration_seconds,
                    "total_alerts": total_alerts,
                    "high_risk": high_risk,
                    "medium_risk": medium_risk,
                    "low_risk": low_risk,
                    "status": status
                }
            )

    def get_active_scans(self) -> Dict[int, ScanMetrics]:
        """Get currently active scans"""
        with self._metrics_lock:
            return dict(self._scan_metrics)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get aggregated metrics summary for monitoring dashboard.
        Returns Prometheus-compatible metrics.
        """
        with self._metrics_lock:
            active_scans = len(self._scan_metrics)

            # Calculate statistics from recent completed scans
            completed_count = len(self._completed_scans)
            successful_scans = sum(1 for m in self._completed_scans if m.status == "completed")
            failed_scans = sum(1 for m in self._completed_scans if m.status == "failed")

            # Calculate average duration (completed scans only)
            durations = [m.duration_seconds for m in self._completed_scans if m.duration_seconds]
            avg_duration = sum(durations) / len(durations) if durations else 0

            # Calculate average alerts
            total_alerts = sum(m.total_alerts for m in self._completed_scans)
            avg_alerts = total_alerts / completed_count if completed_count > 0 else 0

            # Count by risk level
            total_high_risk = sum(m.high_risk_count for m in self._completed_scans)
            total_medium_risk = sum(m.medium_risk_count for m in self._completed_scans)
            total_low_risk = sum(m.low_risk_count for m in self._completed_scans)

            return {
                # Current state
                "active_scans": active_scans,
                "queue_size": active_scans,  # Approximation

                # Historical metrics
                "completed_scans_total": completed_count,
                "successful_scans_total": successful_scans,
                "failed_scans_total": failed_scans,
                "success_rate": successful_scans / completed_count if completed_count > 0 else 0,

                # Performance metrics
                "avg_scan_duration_seconds": round(avg_duration, 2),
                "avg_alerts_per_scan": round(avg_alerts, 2),

                # Alert metrics
                "total_alerts": total_alerts,
                "total_high_risk_alerts": total_high_risk,
                "total_medium_risk_alerts": total_medium_risk,
                "total_low_risk_alerts": total_low_risk,

                # Timestamp
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

    def get_prometheus_metrics(self) -> str:
        """
        Export metrics in Prometheus exposition format.
        Can be scraped by Prometheus for monitoring.
        """
        summary = self.get_metrics_summary()

        metrics = [
            "# HELP scan_active_total Number of currently active scans",
            "# TYPE scan_active_total gauge",
            f"scan_active_total {summary['active_scans']}",
            "",
            "# HELP scan_completed_total Total number of completed scans",
            "# TYPE scan_completed_total counter",
            f"scan_completed_total {summary['completed_scans_total']}",
            "",
            "# HELP scan_duration_seconds_avg Average scan duration in seconds",
            "# TYPE scan_duration_seconds_avg gauge",
            f"scan_duration_seconds_avg {summary['avg_scan_duration_seconds']}",
            "",
            "# HELP scan_alerts_total Total number of alerts found",
            "# TYPE scan_alerts_total counter",
            f"scan_alerts_total {summary['total_alerts']}",
            "",
            "# HELP scan_alerts_high_risk Total high risk alerts",
            "# TYPE scan_alerts_high_risk counter",
            f"scan_alerts_high_risk {summary['total_high_risk_alerts']}",
            "",
            "# HELP scan_success_rate Success rate of scans",
            "# TYPE scan_success_rate gauge",
            f"scan_success_rate {summary['success_rate']}",
        ]

        return "\n".join(metrics)


# Global metrics collector instance
metrics_collector = MetricsCollector.get_instance()
