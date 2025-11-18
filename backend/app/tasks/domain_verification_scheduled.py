from app.models.site import Site
from app.utils.logger import logger
from app.core.db import SessionLocal
from ..core.celery_app import celery_app
from sqlalchemy import select, delete
import dns.resolver
from datetime import datetime
from app.core.config import AppConfig
from datetime import datetime, timedelta
from app.tasks.domain_verification import verify_domain_task


@celery_app.task
def scheduled_domain_maintenance():
    """
    Periodic task to:
    - Recheck all verified domains
    - Delete unverified domains older than 24 hours
    """
    logger.info("Starting scheduled domain maintenance...")
    try:
        with SessionLocal() as session:
            all_sites = session.execute(select(Site)).scalars().all()
            now = datetime.utcnow()
            for site in all_sites:
                # --- CASE 1: Unverified domains ---
                if not site.is_verified:
                    # If domain older than 24h → delete
                    if (now - site.created_at) > timedelta(hours=24):
                        logger.warning(f"Deleting stale unverified domain: {site.domain} for user {site.user_id}")
                        session.delete(site)
                        session.commit()
                    continue

                # --- CASE 2: Verified domains ---
                logger.info(f"🔍 Rechecking verified domain: {site.domain}")
                result = verify_domain_task(domain=site.domain, user_id=site.user_id)
                if not result:
                    # If domain no longer verified
                    logger.warning(f"Domain {site.domain} failed re-verification. Removing record.")
                    session.delete(site)
                    session.commit()

            logger.info("Scheduled domain maintenance completed successfully.")
    except Exception as e:
        logger.error(f"Error during scheduled domain maintenance: {e}")
