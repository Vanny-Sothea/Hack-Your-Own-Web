from app.models.site import Site
from app.utils.logger import logger
from app.core.db import SessionLocal
from ..core.celery_app import celery_app
from sqlalchemy import select, delete
import dns.resolver
from datetime import datetime
from app.core.config import AppConfig

@celery_app.task
def verify_domain_task(domain: str, user_id: int, PREFIX: str = AppConfig.DOMAIN_VERIFICATION_TOKEN_PREFIX):
    logger.info(f"Starting domain verification task for domain: {domain}, user_id: {user_id}")
    try:
        # Create a fresh resolver instance (no cache, no stale data)
        resolver = dns.resolver.Resolver()
        resolver.cache = None
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]  # Use reliable public DNS servers
        resolver.timeout = 3 # Per DNS server timeout {seconds}
        resolver.lifetime = 5 # Overall query timeout {seconds}

        # Fetch fresh TXT records
        answers = resolver.resolve(domain, 'TXT')

        with SessionLocal() as session:
            site = session.execute(
                select(Site).where(
                    Site.domain == domain,
                    Site.user_id == user_id
                )
            ).scalars().first()

            if not site:
                logger.warning(f"No site found for domain {domain}")
                return False

            found = False
            for rdata in answers:
                txt = "".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings]).strip().strip('"')
                # logger.info(f"Found TXT record: {txt}")
                token_candidate = txt
                if token_candidate.startswith(PREFIX):
                    token_candidate = token_candidate[len(PREFIX):]
                if site.verification_token == token_candidate:  # type: ignore[comparison-overlap]
                    found = True
                    break

            if found:
                site.is_verified = True  # type: ignore[assignment]
                session.add(site)
                session.commit()

                # Remove other users' unverified entries for this domain
                session.execute(
                    delete(Site).where(
                        Site.domain == domain,
                        Site.user_id != user_id,
                        Site.is_verified == False  # type: ignore[comparison-overlap]
                    )
                )
                session.commit()

                logger.info(f"Domain verification successful for domain: {domain}")
                return True
            else:
                # Explicitly mark as unverified (for re-verification)
                site.is_verified = False  # type: ignore[assignment]
                session.add(site)
                session.commit()

                logger.warning(f"Verification token not found in DNS TXT records for domain: {domain}")
                return False

    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain does not exist: {domain}")
        return False
    except Exception as e:
        logger.error(f"Error verifying domain {domain}: {e}")
        return False
    
    # Fallback: mark as unverified on any exception
    with SessionLocal() as session:
        site = session.execute(
            select(Site).where(
                Site.domain == domain,
                Site.user_id == user_id
            )
        ).scalars().first()
        if site:
            site.is_verified = False  # type: ignore[assignment]
            # site.verified_at = None
            session.add(site)
            session.commit()

    return False
