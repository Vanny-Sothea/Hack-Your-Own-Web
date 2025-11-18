from pydantic import BaseModel, Field, HttpUrl, validator
from datetime import datetime
from typing import Optional, Dict, Any, List
from app.models.scan import ScanStatus, ScanType, RiskLevel


class BasicScanCreate(BaseModel):
    target_url: HttpUrl = Field(..., description="The target URL to scan")

    @validator('target_url')
    def validate_url(cls, v):
        url_str = str(v)
        if not url_str.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return url_str

    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "https://example.com"
            }
        }


class FullScanCreate(BaseModel):
    target_url: HttpUrl = Field(..., description="The target URL to scan (must be a verified domain)")

    @validator('target_url')
    def validate_url(cls, v):
        url_str = str(v)
        if not url_str.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return url_str

    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "https://example.com"
            }
        }


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    progress_percentage: Optional[int] = Field(None, ge=0, le=100)
    current_step: Optional[str] = None
    error_message: Optional[str] = None


class ScanAlertSummaryResponse(BaseModel):
    """Lightweight alert response for listing"""
    id: int
    alert_name: str
    risk_level: RiskLevel
    confidence: str
    url: str
    method: Optional[str] = None
    cwe_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanAlertResponse(BaseModel):
    """Detailed alert response with full information"""
    id: int
    alert_name: str
    risk_level: RiskLevel
    confidence: str
    description: Optional[str] = None
    solution: Optional[str] = None
    reference: Optional[str] = None
    cwe_id: Optional[str] = None
    wasc_id: Optional[str] = None
    url: str
    method: Optional[str] = None
    param: Optional[str] = None
    attack: Optional[str] = None
    evidence: Optional[str] = None
    other_info: Optional[str] = None
    alert_tags: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: int
    user_id: int
    target_url: str
    scan_type: ScanType
    status: ScanStatus
    celery_task_id: Optional[str] = None
    progress_percentage: int
    current_step: Optional[str] = None
    total_alerts: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    info_count: int
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    """Scan details with summary alerts (lightweight)"""
    alerts: List[ScanAlertSummaryResponse] = []

    class Config:
        from_attributes = True


class ScanFullDetailResponse(ScanResponse):
    """Scan details with full alert information (detailed)"""
    alerts: List[ScanAlertResponse] = []

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanStatsResponse(BaseModel):
    total_scans: int
    pending_scans: int
    in_progress_scans: int
    completed_scans: int
    failed_scans: int
    total_vulnerabilities: int
    high_risk_vulnerabilities: int
    medium_risk_vulnerabilities: int
    low_risk_vulnerabilities: int


# ====== ANONYMOUS SCAN SCHEMAS (No Auth Required) ======

class AnonymousScanCreate(BaseModel):
    """Request schema for anonymous basic scan (no authentication required)"""
    target_url: HttpUrl = Field(..., description="The target URL to scan")

    @validator('target_url')
    def validate_url(cls, v):
        url_str = str(v)
        if not url_str.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return url_str

    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "https://example.com"
            }
        }


class AnonymousAlertResponse(BaseModel):
    """Alert response for anonymous scans"""
    alert_name: str
    risk_level: RiskLevel
    confidence: str
    description: Optional[str] = None
    solution: Optional[str] = None
    reference: Optional[str] = None
    cwe_id: Optional[str] = None
    wasc_id: Optional[str] = None
    url: str
    method: Optional[str] = None
    param: Optional[str] = None
    attack: Optional[str] = None
    evidence: Optional[str] = None
    other_info: Optional[str] = None


class AnonymousScanResponse(BaseModel):
    """Response schema for anonymous scan results"""
    success: bool
    message: str
    scan_data: Dict[str, Any] = Field(..., description="Scan results and metadata")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Scan completed successfully",
                "scan_data": {
                    "target_url": "https://example.com",
                    "scan_type": "basic",
                    "scan_duration_seconds": 45.2,
                    "total_alerts": 12,
                    "high_risk_count": 2,
                    "medium_risk_count": 5,
                    "low_risk_count": 3,
                    "info_count": 2,
                    "alerts": [],
                    "completed_at": "2025-11-18T10:30:00Z"
                }
            }
        }
