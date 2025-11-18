import sys
from pathlib import Path
# Add the current directory to Python path
sys.path.append(str(Path(__file__).parent))

from fastapi import FastAPI
from app.api.v1 import auth_router, site_router, scan_router
from app.core.db import async_engine
from sqlalchemy import text
# from fastapi.middleware.cors import CORSMiddleware


version = "v1"
app = FastAPI(
    version=version,
)

# origins = [
#     "http://localhost:8000",  # your frontend
#     "http://127.0.0.1:8000",
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,  # important for cookies
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

app.include_router(auth_router, prefix=f"/api/{version}/auth", tags=["auth"])
app.include_router(site_router, prefix=f"/api/{version}/site", tags=["site"])
app.include_router(scan_router, prefix=f"/api/{version}/scan", tags=["scan"])

@app.on_event("startup")
async def startup_event():
    try:
        async with async_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        print("Database connection successful")
    except Exception as e:
        print(f"Database connection failed: {e}")