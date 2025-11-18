from app.utils.logger import logger
from fastapi.responses import JSONResponse
from sqlalchemy import select
from app.models.site import Site
from app.utils.generate_tokens import generate_domain_verification_token
from datetime import datetime
from app.tasks.domain_verification import verify_domain_task
from app.core.config import AppConfig


async def domain_registry_crud(data, user, session):
    logger.info(f"Domain registration endpoint hit")
    try:
        result = await session.execute(select(Site).where(Site.domain == data.domain))
        existingDomains = result.scalars().all()

        # Domain is verified by this same user
        verified_by_user = next((d for d in existingDomains if d.user_id == user.id and d.is_verified), None)
        if verified_by_user:
            logger.warning(f"User {user.id} already verified domain {data.domain}.")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "You have already verified this domain."}
            )

        # Domain is verified by another user
        verified_by_other = next((d for d in existingDomains if d.user_id != user.id and d.is_verified), None)
        if verified_by_other:
            logger.warning(f"Domain {data.domain} is already verified by another user (id={verified_by_other.user_id}).")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "This domain is already verified by another user."}
            )
        
        # Same user has an unverified entry — allow re-registration
        user_unverified = next((d for d in existingDomains if d.user_id == user.id and not d.is_verified), None)
        if user_unverified:
            logger.info(f"Existing unverified domain {data.domain} found for user {user.id}, deleting for re-registration.")
            await session.delete(user_unverified)
            await session.commit()

        # Create a new verification entry for this user
        domain_verification_token, expires_at = await generate_domain_verification_token()
        new_domain = Site(
            domain=data.domain,
            verification_token=domain_verification_token,
            # verification_token_expires_at=expires_at,
            is_verified=False,
            user_id=user.id
        )
        session.add(new_domain)
        await session.commit()

        logger.info(f"Domain {data.domain} registered successfully.")

        return JSONResponse(
            status_code=201,
            content={"success": True, "message": "Domain registered successfully.", "verificationToken": f"{AppConfig.DOMAIN_VERIFICATION_TOKEN_PREFIX}{new_domain.verification_token}"}
        )

    except Exception as e:
        logger.error(f"Error registering domain: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def edit_domain_crud(data, user, session):
    logger.info(f"Domain edit endpoint hit")
    try:
        domain_entry = (await session.execute(
            select(Site).where(
                Site.domain == data.domain,
                Site.user_id == user.id
            )
        )).scalars().first()

        if not domain_entry:
            logger.warning(f"User {user.id} is not authorized to edit domain {data.domain}.")
            return JSONResponse(
                status_code=403,
                content={"success": False, "message": "Not authorized to edit this domain."}
            )

        if (domain_entry.is_verified):
            logger.warning(f"Domain {data.domain} is already verified and cannot be edited.")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Verified domains cannot be edited."}
            )
        
        # Edit/Update domain and update new verification token
        domain_verification_token, expires_at = await generate_domain_verification_token()
        domain_entry.domain = data.new_domain
        domain_entry.verification_token = domain_verification_token
        # domain_entry.verification_token_expires_at = expires_at
        await session.commit()
        logger.info(f"Domain {data.domain} edited to {data.new_domain} successfully.")

        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "Domain edited successfully.", "verificationToken": f"{AppConfig.DOMAIN_VERIFICATION_TOKEN_PREFIX}{domain_entry.verification_token}"}
        )

    except Exception as e:
        logger.error(f"Error editing domain: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def get_domain_status_crud(data, user, session):
    logger.info(f"Get domain status endpoint hit")
    try:
        domain_entry = (await session.execute(
            select(Site).where(
                Site.domain == data.domain,
                Site.user_id == user.id
            )
        )).scalars().first()

        if not domain_entry:
            logger.warning(f"User {user.id} is not authorized to access domain {data.domain}.")
            return JSONResponse(
                status_code=403,
                content={"success": False, "message": "Not authorized to access this domain."}
            )

        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "isVerified": domain_entry.is_verified,
            }
        )

    except Exception as e:
        logger.error(f"Error retrieving domain status: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def domain_verification_crud(data, user, session):
    logger.info(f"Domain verification endpoint hit")
    try:
        domain_entry = (await session.execute(
            select(Site).where(
                Site.domain == data.domain,
                Site.user_id == user.id
            )
        )).scalars().first()

        if (not domain_entry):
            logger.warning(f"User {user.id} is not authorized to verify domain {data.domain}.")
            return JSONResponse(
                status_code=403,
                content={"success": False, "message": "Not authorized to verify this domain."}
            )
        
        if (domain_entry.is_verified):
            logger.info(f"Domain {data.domain} is already verified. Recheck verification status.")

        # if (datetime.utcnow() > domain_entry.verification_token_expires_at):
        #     logger.warning(f"Domain {data.domain} does not have a valid verification token.")
        #     return JSONResponse(
        #         status_code=400,
        #         content={"success": False, "message": "verification token expired — please regenerate"}
        #     )
        
        verify_domain_task.delay(data.domain, user.id)

        return JSONResponse(
            status_code=202,
            content={"success": True, "message": "Verification in progress. Please check again in a few minutes."}
        )

    except Exception as e:
        logger.error(f"Error verifying domain: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
    

async def get_list_user_domains_crud(user, session):
    logger.info(f"List user domains endpoint hit")
    try:
        result = await session.execute(select(Site).where(Site.user_id == user.id))
        user_domains = result.scalars().all()

        domains_list = [
            { 
                "id": domain.id,
                "domain": domain.domain,
                "isVerified": domain.is_verified,
            }
            for domain in user_domains
        ]

        return JSONResponse(
            status_code=200,
            content={"success": True, "domains": domains_list}
        )

    except Exception as e:
        logger.error(f"Error listing user domains: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def remove_domain_crud(data, user, session):
    logger.info(f"Domain removal endpoint hit")
    try:
        domain_entry = (await session.execute(
            select(Site).where(
                Site.domain == data.domain,
                Site.user_id == user.id
            )
        )).scalars().first()

        if not domain_entry:
            logger.warning(f"User {user.id} is not authorized to remove domain {data.domain}.")
            return JSONResponse(
                status_code=403,
                content={"success": False, "message": "Not authorized to remove this domain."}
            )

        await session.delete(domain_entry)
        await session.commit()

        logger.info(f"Domain {data.domain} removed successfully.")

        return JSONResponse(
            status_code=204,
            content=None
        )

    except Exception as e:
        logger.error(f"Error removing domain: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
