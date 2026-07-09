"""
DTAC-IR Logging Configuration
Structured JSON logging for SOC/SIEM-ready output.
"""
import sys
import logging
from loguru import logger


class InterceptHandler(logging.Handler):
    """
    Redirect standard library logging to Loguru.
    Ensures uvicorn, SQLAlchemy, etc. all go through our logger.
    """
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging(debug: bool = False) -> None:
    """Initialize logging. Call once at application startup."""
    log_level = "DEBUG" if debug else "INFO"

    # Remove default loguru handler
    logger.remove()

    # Console: human-readable in dev, JSON in prod
    logger.add(
        sys.stdout,
        level=log_level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # File: always JSON for SIEM ingestion
    logger.add(
        "logs/dtac_ir_{time:YYYY-MM-DD}.log",
        rotation="00:00",          # New file every day
        retention="30 days",
        compression="gz",
        level="INFO",
        serialize=True,            # JSON output
    )

    # Intercept stdlib loggers
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy.engine"):
        std_logger = logging.getLogger(name)
        std_logger.handlers = [InterceptHandler()]
        std_logger.propagate = False

    logger.info("✅ Logging initialized", level=log_level)
