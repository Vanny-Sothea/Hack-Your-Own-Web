import sys
from pathlib import Path
# Add the current directory to Python path
sys.path.append(str(Path(__file__).parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.auth import auth_router
from app.api.v1.site import site_router
from app.api.v1.scan import scan_router
from app.api.v1.health import health_router
from app.core.db import async_engine
from sqlalchemy import text


version = "v1"
app = FastAPI(
    title="Hack Your Own Web API",
    description="Security scanning platform API with OWASP ZAP integration",
    version=version,
)

# CORS Configuration
origins = [
    "http://localhost:3000",  # React frontend
    "http://127.0.0.1:3000",
    "http://localhost:8000",  # API docs
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix=f"/api/{version}/auth", tags=["Authentication"])
app.include_router(site_router, prefix=f"/api/{version}/site", tags=["Site Management"])
app.include_router(scan_router, prefix=f"/api/{version}/scans", tags=["Security Scans"])
app.include_router(health_router, prefix=f"/api/{version}", tags=["Health"])


@app.get("/")
async def root():
    return {
        "message": "Hack Your Own Web API",
        "version": version,
        "docs": "/docs",
        "health": f"/api/{version}/health",
        "metrics": f"/api/{version}/metrics"
    }

@app.on_event("startup")
async def startup_event():
    try:
        async with async_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        print("Database connection successful")
    except Exception as e:
        print(f"Database connection failed: {e}")
