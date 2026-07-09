"""
DTAC-IR Database Engine
Async SQLAlchemy setup with connection pooling.
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from loguru import logger

from app.core.config import get_settings

settings = get_settings()

# Async engine with connection pool tuned for packet-heavy workloads
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,          # Detect stale connections
    pool_recycle=3600,           # Recycle connections every hour
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a DB session and guarantees cleanup."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables on startup (dev only — use Alembic in production)."""
    async with engine.begin() as conn:
        from app.models import models  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables initialized")
