from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncEngine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import Config
from typing import AsyncGenerator

# async engine object with NullPool to avoid event loop conflicts in Celery workers
# NullPool creates a new connection for each request and closes it immediately after use
async_engine = create_async_engine(
    url=Config.DATABASE_URL,
    echo=False,
    future=True,
    poolclass=NullPool,  # No connection pooling - prevents event loop attachment issues
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Dependency for FastAPI
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


# Convert the async URL to a sync one automatically for Celery tasks
SYNC_DATABASE_URL = Config.DATABASE_URL.replace("+asyncpg", "")

sync_engine = create_engine(
    SYNC_DATABASE_URL,
    echo=False,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=sync_engine
)
