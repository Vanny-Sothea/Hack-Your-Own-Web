from datetime import datetime, timedelta
from ..models.user import User, RefreshToken
from ..core.security import get_password_hash, verify_password, revoke_token, revoke_session_token
from sqlalchemy import select, delete
from ..utils.logger import logger
from fastapi.responses import JSONResponse
import random
import string
from ..core.email_helpers import send_email_verification, send_email_verification_success, send_email_password_reset
from ..utils.generate_tokens import generate_tokens, generate_verification_token

async def sign_up_crud(data, response, session):
    logger.info("Account sign-up endpoint hit")
    try:
        existingUser = (await session.execute(select(User).where(User.email == data.email))).scalars().first()
        if existingUser:
            if existingUser.is_verified:
                logger.warning("Email already in use by a verified user")
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "message": "User already exists"}
                )
            else:
                logger.warning("User already signup but not yet verified. Delete the existing user")
                await session.delete(existingUser)
                await session.commit()

        verification_code = ''.join(random.choices(string.digits, k=6))
        password_hash = await get_password_hash(data.password)

        user = User(
            first_name=data.first_name,
            last_name=data.last_name,
            email=data.email,
            password_hash=password_hash,
            verification_code=verification_code,
            verification_code_expires_at=datetime.utcnow() + timedelta(minutes=3),
        )
        session.add(user)
        await session.commit()
        
        # Combine first_name and last_name only if last_name exists
        user_name = f"{data.first_name} {data.last_name}" if data.last_name is not None else data.first_name
        await send_email_verification(
            email=data.email,
            user_name=user_name,
            verification_code=verification_code
        )

        user_data = {
            "email": user.email,
        }

        await generate_verification_token(response, user_data)

        return JSONResponse(
            status_code=201,
            headers=response.headers,
            content={"success": True, "message": "User created successfully"}
        )

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def verify_email_crud(response, data, user_cookie, session):
    logger.info("Account verification endpoint hit")
    try:
        user_email = user_cookie['user']['email']
        user = (await session.execute(select(User).where(User.email == user_email))).scalars().first()
        if not user:
            logger.warning("User not found during verification")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )
        if user.is_verified:
            logger.info("User already verified")
            return JSONResponse(
                status_code=200,
                content={"success": True, "message": "User already verified"}
            )
        if user.verification_code != data.verification_code:
            logger.warning("Invalid verification code provided")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Invalid or expired verification code"}
            )
        if user.verification_code_expires_at is not None and datetime.utcnow() > user.verification_code_expires_at:
            logger.warning("Verification code expired")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Invalid or expired verification code"}
            )

        user.is_verified = True
        user.updated_at = datetime.utcnow()
        user.verification_code = None
        user.verification_code_expires_at = None
        session.add(user)
        await session.commit()

        # Combine first_name and last_name only if last_name exists
        user_name = f"{user.first_name} {user.last_name}" if user.last_name is not None else user.first_name
        await send_email_verification_success(
            email=user.email,
            user_name=user_name,
        )

        await revoke_token(response)

        logger.info("User verified successfully")

        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "User verified successfully"}
        )
    except Exception as e:
        logger.error(f"Error verifying user: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
    

async def resend_verification_code_crud(response, user_cookie, session):
    logger.info("Resend verification code endpoint hit")
    try:
        user_email = user_cookie['user']['email']
        user = (await session.execute(select(User).where(User.email == user_email))).scalars().first()
        if not user:
            logger.warning("User not found during resend verification code")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )
        if user.is_verified:
            logger.info("User already verified")
            return JSONResponse(
                status_code=200,
                content={"success": True, "message": "User already verified"}
            )

        verification_code = ''.join(random.choices(string.digits, k=6))
        user.verification_code = verification_code
        user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=3)
        session.add(user)
        await session.commit()

        # Combine first_name and last_name only if last_name exists
        user_name = f"{user.first_name} {user.last_name}" if user.last_name is not None else user.first_name
        await send_email_verification(
            email=user.email,
            user_name=user_name,
            verification_code=verification_code
        )

        user_data = {
            "email": user.email,
        }

        await generate_verification_token(response, user_data)

        logger.info("Verification code resent successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "Verification code resent successfully"}
        )
    except Exception as e:
        logger.error(f"Error resending verification code: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
    

async def login_crud(data, response, session):
    logger.info("Account login endpoint hit")
    try:
        user = (await session.execute(select(User).where(User.email == data.email))).scalars().first()
        if not user:
            logger.warning("User not found during login")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )
        if not user.is_verified:
            logger.warning("User not verified during login")
            return JSONResponse(
                status_code=403,
                content={"success": False, "message": "User not found"}
            )
        if not await verify_password(data.password, user.password_hash):
            logger.warning("Incorrect password provided during login")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Incorrect password"}
            )

        user_data = {
            "id": str(user.id),
            "email": user.email,
        }
        
        await generate_tokens(response, user_data, session)

        logger.info("User logged in successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={
                "success": True,
                "message": "Login successful",
            }
        )
    except Exception as e:
        logger.error(f"Error logging in user: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )

async def reset_password_request_crud(data, response, session):
    logger.info("Password reset request endpoint hit")
    try:
        user = (await session.execute(
            select(User).where(
                (User.email == data.email) & (User.is_verified == True)
            )
        )).scalars().first()

        if not user:
            logger.warning("User not found during password reset request")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )

        verification_code = ''.join(random.choices(string.digits, k=6))
        user.verification_code = verification_code
        user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=3)
        session.add(user)
        await session.commit()

        # Combine first_name and last_name only if last_name exists
        user_name = f"{user.first_name} {user.last_name}" if user.last_name is not None else user.first_name
        await send_email_password_reset(
            email=user.email,
            user_name=user_name,
            verification_code=verification_code
        )

        user_data = {
            "email": user.email,
        }

        await generate_verification_token(response, user_data)

        logger.info("Password reset code sent successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "Password reset code sent to email"}
        )
    except Exception as e:
        logger.error(f"Error during password reset request: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
    

async def resend_reset_password_request_crud(response, user_cookie, session):
    logger.info("Resend password reset code endpoint hit")
    try:
        user_email = user_cookie['user']['email']
        user = (await session.execute(
            select(User).where(
                (User.email == user_email) & (User.is_verified == True)
            )
        )).scalars().first()

        if not user:
            logger.warning("User not found during resend password reset code")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )

        verification_code = ''.join(random.choices(string.digits, k=6))
        user.verification_code = verification_code
        user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=3)
        session.add(user)
        await session.commit()

        # Combine first_name and last_name only if last_name exists
        user_name = f"{user.first_name} {user.last_name}" if user.last_name is not None else user.first_name
        await send_email_password_reset(
            email=user.email,
            user_name=user_name,
            verification_code=verification_code
        )

        user_data = {
            "email": user.email,
        }

        await generate_verification_token(response, user_data)

        logger.info("Password reset code resent successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "Password reset code resent successfully"}
        )
    except Exception as e:
        logger.error(f"Error resending password reset code: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
    

async def reset_password_verify_crud(data, response, user_cookie, session):
    logger.info("Password reset verify endpoint hit")
    try:
        user_email = user_cookie['user']['email']

        user = (await session.execute(
            select(User).where(
                (User.email == user_email) & (User.is_verified == True)
            )
        )).scalars().first()

        if not user:
            logger.warning("User not found during password reset")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )
        if user.verification_code != data.verification_code:
            logger.warning("Invalid verification code provided")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Invalid or expired verification code"}
            )
        if user.verification_code_expires_at is not None and datetime.utcnow() > user.verification_code_expires_at:
            logger.warning("Verification code expired")
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Invalid or expired verification code"}
            )

        user.verification_code = None
        user.verification_code_expires_at = None
        session.add(user)
        await session.commit()

        await revoke_token(response)

        user_data = {
            "id": user.id,
            "email": user.email,
        }

        await generate_verification_token(response, user_data, key="resetPasswordVerificationToken", expire_minutes=10)

        logger.info("Verify password reset request successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "Password reset request verified successfully"}
        )
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def reset_password_crud(data, response, user_cookie, session):
    logger.info("Password reset endpoint hit")
    try:
        user_email = user_cookie['user']['email']

        user = (await session.execute(
            select(User).where(
                (User.email == user_email) & (User.is_verified == True)
            )
        )).scalars().first()

        if not user:
            logger.warning("User not found during password reset")
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "User not found"}
            )

        user.password_hash = await get_password_hash(data.new_password)
        user.updated_at = datetime.utcnow()

        # Delete refresh tokens directly
        # SQLAlchemy comparison creates ColumnElement[bool], not plain bool
        await session.execute(
            delete(RefreshToken).where(RefreshToken.user_id == user.id)  # type: ignore[arg-type]
        )

        session.add(user)
        await session.commit()

        await revoke_token(response, key="resetPasswordVerificationToken")
        await revoke_session_token(response)

        logger.info("Password reset successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "Password reset successfully"}
        )
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )


async def logout_crud(response, user_cookie, session):
    logger.info("Account logout endpoint hit")
    try:
        user_id = int(user_cookie['user']['id'])

        # Delete refresh tokens directly
        # SQLAlchemy comparison creates ColumnElement[bool], not plain bool
        await session.execute(
            delete(RefreshToken).where(RefreshToken.user_id == user_id)  # type: ignore[arg-type]
        )
        await session.commit()

        await revoke_token(response)
        await revoke_session_token(response)

        logger.info("User logged out successfully")
        return JSONResponse(
            status_code=200,
            headers=response.headers,
            content={"success": True, "message": "Logout successful"}
        )
    except Exception as e:
        logger.error(f"Error logging out user: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Internal server error"}
        )
