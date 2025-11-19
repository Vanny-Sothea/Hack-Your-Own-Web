from fastapi import HTTPException, status
from sqlalchemy.future import select
from sqlalchemy import and_
from app.models.site import Site
from app.utils.logger import logger
from app.core.config import AppConfig
import dns.resolver


async def verify_site_ownership(domain, user, session):
    """
    Verify that user owns the domain and DNS TXT record still exists.
    
    This checks:
    1. Domain exists in database for this user
    2. Domain is marked as verified
    3. DNS TXT record still matches (prevents attacks after TXT removal)
    """
    logger.info(f"Verifying ownership for domain: {domain.domain}, user: {user.id}")
    
    # Step 1: Check database
    result = await session.execute(
        select(Site).where(
            and_(
                Site.user_id == user.id,
                Site.domain == domain.domain,
                Site.is_verified == True
            )
        )
    )
    site = result.scalars().first()
    
    if not site:
        logger.warning(f"Domain not found or not verified: {domain.domain}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Domain '{domain.domain}' is not verified. Please verify it first at /api/v1/site"
        )
    
    # Step 2: Check DNS TXT record
    try:
        resolver = dns.resolver.Resolver()
        resolver.cache = None
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = 3
        resolver.lifetime = 5
        
        answers = resolver.resolve(domain.domain, 'TXT')
        
        # Look for matching token in TXT records
        for rdata in answers:
            txt_record = "".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
            txt_record = txt_record.strip().strip('"')
            
            # Remove prefix if present
            token = txt_record
            if token.startswith(AppConfig.DOMAIN_VERIFICATION_TOKEN_PREFIX):
                token = token[len(AppConfig.DOMAIN_VERIFICATION_TOKEN_PREFIX):]
            
            # Check if token matches
            if site.verification_token == token:
                logger.info(f"Domain verified successfully: {domain.domain}")
                return True
        
        # Token not found - mark as unverified
        logger.warning(f"TXT record not found for domain: {domain.domain}")
        site.is_verified = False
        session.add(site)
        await session.commit()
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"DNS verification failed. TXT record missing or incorrect for '{domain.domain}'"
        )
        
    except dns.resolver.NoAnswer:
        logger.warning(f"No TXT records found for domain: {domain.domain}")
        site.is_verified = False
        session.add(site)
        await session.commit()
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No TXT records found for '{domain.domain}'"
        )
        
    except dns.resolver.Timeout:
        logger.error(f"DNS timeout for domain: {domain.domain}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DNS verification timeout. Please try again"
        )
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(f"DNS verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DNS verification error"
        )
