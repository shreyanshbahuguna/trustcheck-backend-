from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware   # ⭐ CORS import
from app.api import routes
from app.db import session as db_session
from app.core.config import settings
import logging

app = FastAPI(title="TrustCheck-India API")

# ⭐ CORS Middleware (REQUIRED FIX)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # allow all frontend origins
    allow_credentials=True,
    allow_methods=["*"],       # allow GET, POST, OPTIONS, DELETE, PUT
    allow_headers=["*"],       # allow Content-Type, Authorization
)

# Include routes
app.include_router(routes.router)

@app.on_event("startup")
def startup():
    # create tables if not present (simple approach)
    from app.db.session import engine, Base
    from app import models
    Base.metadata.create_all(bind=engine)
    logging.info("Database tables ensured.")

@app.get("/health")
def health():
    return {"status": "ok", "env": settings.APP_ENV}
