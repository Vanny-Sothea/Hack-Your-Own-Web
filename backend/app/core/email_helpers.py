from app.core.config import AppConfig
from app.core.email import send_email

async def send_email_verification(email: str, user_name: str, verification_code: str):
    data = {
        'app_name': AppConfig.APP_NAME,
        'user_name': user_name,
        'verification_code': verification_code
    }

    subject = f"{verification_code} is your {AppConfig.APP_NAME} verification code"
    await send_email(
        recipients=[email],
        subject=subject,
        template_name="email_verification.html",
        context=data
    )


async def send_email_verification_success(email: str, user_name: str):
    data = {
        'app_name': AppConfig.APP_NAME,
        'user_name': user_name
    }

    subject = f"Your {AppConfig.APP_NAME} account has been verified successfully"
    await send_email(
        recipients=[email],
        subject=subject,
        template_name="email_verification_success.html",
        context=data
    )


async def send_email_password_reset(email: str, user_name: str, verification_code: str):
    data = {
        'app_name': AppConfig.APP_NAME,
        'user_name': user_name,
        'verification_code': verification_code
    }

    subject = f"{verification_code} is your {AppConfig.APP_NAME} password reset code"
    await send_email(
        recipients=[email],
        subject=subject,
        template_name="email_password_reset.html",
        context=data
    )