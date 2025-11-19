# Import all models to ensure they are registered with SQLAlchemy
from app.models.base import Base
from app.models.user import User, RefreshToken
from app.models.site import Site
from app.models.scan import Scan, ScanAlert, ScanStatus, ScanType, RiskLevel

# Configure all mappers after all models are imported
# This ensures all string references in relationships can be resolved
from sqlalchemy.orm import configure_mappers
configure_mappers()

__all__ = [
    "Base",
    "User",
    "RefreshToken",
    "Site",
    "Scan",
    "ScanAlert",
    "ScanStatus",
    "ScanType",
    "RiskLevel",
]
