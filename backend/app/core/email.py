from pathlib import Path
from pydantic import SecretStr
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from app.core.config import MailConfig

conf = ConnectionConfig(
    MAIL_USERNAME=MailConfig.MAIL_USERNAME,
    MAIL_PASSWORD=SecretStr(MailConfig.MAIL_PASSWORD),
    MAIL_FROM=MailConfig.MAIL_FROM,
    MAIL_FROM_NAME=MailConfig.MAIL_FROM_NAME,
    MAIL_PORT=int(MailConfig.MAIL_PORT),
    MAIL_SERVER=MailConfig.MAIL_SERVER,
    MAIL_STARTTLS=MailConfig.MAIL_STARTTLS,
    MAIL_SSL_TLS=MailConfig.MAIL_SSL_TLS,
    MAIL_DEBUG=MailConfig.MAIL_DEBUG,
    USE_CREDENTIALS=MailConfig.USE_CREDENTIALS,
    TEMPLATE_FOLDER=Path(__file__).parent / "mail_templates",
)

fm = FastMail(conf)

async def send_email(recipients: list, subject: str, template_name: str, context: dict):
    message = MessageSchema(
        subject=subject,
        recipients=recipients,
        template_body=context,
        subtype=MessageType.html,
    )

    await fm.send_message(message, template_name=template_name)