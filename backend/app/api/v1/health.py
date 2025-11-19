"""
Health Check Endpoints

Provides health check endpoints for monitoring system status:
- Overall health
- ZAP service connectivity
- Database connectivity
- Redis/Celery connectivity
- Metrics endpoint
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.db import get_session
from app.services.scanner_manager import scanner_manager
from app.services.metrics import metrics_collector
from app.core.celery_app import celery_app
from app.utils.logger import logger

router = APIRouter()


@router.get("/health", tags=["Health"])
async def health_check(session: AsyncSession = Depends(get_session)):
    """
    Overall health check - returns 200 if all services are healthy
    Checks: Database, ZAP, Redis/Celery
    """
    health_status = {
        "status": "healthy",
        "services": {}
    }

    try:
        # Check database
        db_healthy = await check_database_health(session)
        health_status["services"]["database"] = "healthy" if db_healthy else "unhealthy"

        # Check ZAP
        zap_healthy = check_zap_health()
        health_status["services"]["zap"] = "healthy" if zap_healthy else "unhealthy"

        # Check Redis/Celery
        celery_healthy = check_celery_health()
        health_status["services"]["celery"] = "healthy" if celery_healthy else "unhealthy"

        # Overall status
        all_healthy = db_healthy and zap_healthy and celery_healthy
        health_status["status"] = "healthy" if all_healthy else "degraded"

        status_code = 200 if all_healthy else 503

        return JSONResponse(
            status_code=status_code,
            content=health_status
        )

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )


@router.get("/health/db", tags=["Health"])
async def database_health(session: AsyncSession = Depends(get_session)):
    """Database connectivity health check"""
    try:
        is_healthy = await check_database_health(session)

        if is_healthy:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "healthy",
                    "service": "database",
                    "message": "Database connection successful"
                }
            )
        else:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "service": "database",
                    "message": "Database connection failed"
                }
            )

    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "database",
                "error": str(e)
            }
        )


@router.get("/health/zap", tags=["Health"])
async def zap_health():
    """ZAP scanner service health check"""
    try:
        is_healthy = check_zap_health()

        if is_healthy:
            connection_status = scanner_manager.get_connection_status()
            return JSONResponse(
                status_code=200,
                content={
                    "status": "healthy",
                    "service": "zap",
                    "message": "ZAP connection successful",
                    "details": connection_status
                }
            )
        else:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "service": "zap",
                    "message": "ZAP connection failed"
                }
            )

    except Exception as e:
        logger.error(f"ZAP health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "zap",
                "error": str(e)
            }
        )


@router.get("/health/celery", tags=["Health"])
async def celery_health():
    """Celery/Redis connectivity health check"""
    try:
        is_healthy = check_celery_health()

        if is_healthy:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "healthy",
                    "service": "celery",
                    "message": "Celery/Redis connection successful"
                }
            )
        else:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "service": "celery",
                    "message": "Celery/Redis connection failed"
                }
            )

    except Exception as e:
        logger.error(f"Celery health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "celery",
                "error": str(e)
            }
        )


@router.get("/metrics", tags=["Health"])
async def get_metrics():
    """
    Get scan metrics summary (JSON format)
    Returns aggregated performance metrics
    """
    try:
        metrics = metrics_collector.get_metrics_summary()
        return JSONResponse(
            status_code=200,
            content=metrics
        )
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )


@router.get("/metrics/prometheus", tags=["Health"])
async def get_prometheus_metrics():
    """
    Get metrics in Prometheus exposition format
    Can be scraped by Prometheus for monitoring
    """
    try:
        metrics_text = metrics_collector.get_prometheus_metrics()
        return PlainTextResponse(
            content=metrics_text,
            media_type="text/plain; version=0.0.4"
        )
    except Exception as e:
        logger.error(f"Failed to get Prometheus metrics: {e}")
        return PlainTextResponse(
            content=f"# Error: {str(e)}",
            status_code=500
        )


# Helper functions

async def check_database_health(session: AsyncSession) -> bool:
    """Check if database is accessible"""
    try:
        # Simple query to test connection
        result = await session.execute(text("SELECT 1"))
        return result.scalar() == 1
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def check_zap_health() -> bool:
    """Check if ZAP service is accessible"""
    try:
        # Force a connection attempt to verify ZAP is actually reachable
        # This will initialize the connection if it hasn't been initialized yet
        from zapv2 import ZAPv2
        from app.core.config import ZAPConfig

        zap_client = ZAPv2(
            apikey=ZAPConfig.ZAP_API_KEY,
            proxies={
                "http": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
                "https": f"http://{ZAPConfig.ZAP_HOST}:{ZAPConfig.ZAP_PORT}",
            }
        )

        # Try to get version - this will fail if ZAP is not accessible
        version = zap_client.core.version
        logger.debug(f"ZAP health check passed - version: {version}")
        return True
    except Exception as e:
        logger.error(f"ZAP health check failed: {e}")
        return False


def check_celery_health() -> bool:
    """Check if Celery/Redis is accessible"""
    try:
        # Ping Celery workers
        inspect = celery_app.control.inspect()
        stats = inspect.stats()
        # If we get stats back, Celery is running
        return stats is not None and len(stats) > 0
    except Exception as e:
        logger.error(f"Celery health check failed: {e}")
        return False


health_router = router
