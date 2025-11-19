from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Enum as SQLEnum, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from enum import Enum
from .base import Base

if TYPE_CHECKING:
    from app.models.user import User


class ScanStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(Enum):
    BASIC = "basic"           # Basic passive scan (spider + passive) - No verification required
    FULL = "full"             # Full active scan - Requires domain ownership verification


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String, nullable=False, index=True)
    scan_type = Column(SQLEnum(ScanType, values_callable=lambda obj: [e.value for e in obj], name="scantype"), nullable=False, default=ScanType.BASIC)
    status = Column(SQLEnum(ScanStatus, values_callable=lambda obj: [e.value for e in obj], name="scanstatus"), nullable=False, default=ScanStatus.PENDING, index=True)

    # Celery task tracking
    celery_task_id = Column(String, nullable=True, index=True)

    # Progress tracking
    progress_percentage = Column(Integer, nullable=False, default=0)
    current_step = Column(String, nullable=True)

    # Results summary
    total_alerts = Column(Integer, nullable=False, default=0)
    high_risk_count = Column(Integer, nullable=False, default=0)
    medium_risk_count = Column(Integer, nullable=False, default=0)
    low_risk_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)

    # Error tracking
    error_message = Column(String, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="scans")
    alerts = relationship(
        "ScanAlert",
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class RiskLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ScanAlert(Base):
    __tablename__ = "scan_alerts"
    __table_args__ = (
        # OPTIMIZED: Only keep essential composite indexes for common queries
        # Removed individual indexes on: id, alert_name, risk_level, confidence, cwe_id, url, created_at
        # This reduces index overhead during bulk inserts by ~50%
        Index('ix_scan_alerts_scan_risk', 'scan_id', 'risk_level'),  # Filter alerts by scan and risk
        Index('ix_scan_alerts_scan_created', 'scan_id', 'created_at'),  # Sort alerts by creation time within scan
    )

    id = Column(Integer, primary_key=True)  # Removed index=True (primary key is already indexed)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)  # Keep for foreign key

    # Alert details (removed individual indexes)
    alert_name = Column(String, nullable=False)
    risk_level = Column(SQLEnum(RiskLevel, values_callable=lambda obj: [e.value for e in obj], name="risklevel"), nullable=False)
    confidence = Column(String, nullable=False)

    # Vulnerability details
    description = Column(String, nullable=True)
    solution = Column(String, nullable=True)
    reference = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)  # Removed index (can filter via scan_id first)
    wasc_id = Column(String, nullable=True)

    # Location
    url = Column(String, nullable=False)  # Removed index (scan_id filtering is sufficient)
    method = Column(String, nullable=True)
    param = Column(String, nullable=True)
    attack = Column(String, nullable=True)
    evidence = Column(String, nullable=True)

    # Additional data
    other_info = Column(String, nullable=True)
    alert_tags = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)  # Removed individual index (covered by composite)

    # Relationships
    scan = relationship("Scan", back_populates="alerts")
