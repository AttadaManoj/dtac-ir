"""
DTAC-IR Backend — Main Application
FastAPI app with WebSocket support for real-time dashboard updates.
"""
import asyncio
import threading
from contextlib import asynccontextmanager
from loguru import logger
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import setup_logging
from app.core.database import init_db, AsyncSessionLocal
from app.detection.engine import DetectionEngine
from app.ml.inference import get_inference_engine
from app.trust.scorer import trust_engine
from app.models.models import Device, Alert, DeviceStatus
from app.api.v1.endpoints.websocket import broadcast_alert

settings = get_settings()

# ── Global Engine Instance ────────────────────────────────────────────────────────
detection_engine: DetectionEngine = None
_main_loop: asyncio.AbstractEventLoop = None  # captured at startup for thread-safe scheduling


from app.models.models import SeverityLevel, AttackType

# The ML model's output classes don't share a taxonomy with the DB's AttackType
# enum (Phase 1 rules vs Phase 2 ML were built independently). Map anything
# unrecognized to ANOMALY rather than crashing the persistence path.
_ATTACK_TYPE_MAP = {
    "port_scan": AttackType.PORT_SCAN,
    "syn_flood": AttackType.SYN_FLOOD,
    "dns_exfiltration": AttackType.DNS_EXFILTRATION,
    "brute_force": AttackType.BRUTE_FORCE,
    "arp_spoofing": AttackType.ARP_SPOOFING,
    "normal": AttackType.NORMAL,
    "benign": AttackType.NORMAL,
    "botnet": AttackType.BOTNET,
    "dos": AttackType.DOS,
    "web_attack": AttackType.WEB_ATTACK,
}


async def _persist_threat(features, severity: str) -> None:
    """
    Upsert the source device and write an Alert row.
    Runs on the main event loop (scheduled from the capture thread).
    """
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select

        result = await db.execute(select(Device).where(Device.ip_address == features.src_ip))
        device = result.scalar_one_or_none()

        live_score = trust_engine.get_score(features.src_ip)
        live_status = trust_engine.get_status(features.src_ip)  # e.g. "trusted"
        device_status = DeviceStatus(live_status)  # value-based lookup ("trusted" -> TRUSTED)

        if device is None:
            device = Device(
                ip_address=features.src_ip,
                trust_score=live_score,
                status=device_status,
                is_blocked=False,
                total_packets=0,
                total_alerts=0,
            )
            db.add(device)
            await db.flush()  # get device.id before use below
        else:
            device.trust_score = live_score
            device.status = device_status

        device.total_alerts = (device.total_alerts or 0) + 1

        mapped_attack_type = _ATTACK_TYPE_MAP.get(
            features.predicted_class.lower(), AttackType.ANOMALY
        )

        alert = Alert(
            title=f"{features.predicted_class.upper()} detected",
            description=f"Rule: {features.rule_triggered}",
            severity=SeverityLevel(severity),  # severity is already lowercase, e.g. "critical"
            attack_type=mapped_attack_type,
            src_ip=features.src_ip,
            dst_ip=features.dst_ip,
            dst_port=features.dst_port,
            ml_confidence=features.ml_confidence,
            rule_triggered=features.rule_triggered,
            device_id=device.id,
        )
        db.add(alert)

        await db.commit()
        await db.refresh(alert)

        # Push immediately over WebSocket instead of waiting up to 2s for the
        # next trust_update tick — this is what the frontend's "new_alert"
        # handler was built for but nothing was ever calling it.
        await broadcast_alert({
            "id": alert.id,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "title": alert.title,
            "severity": alert.severity.value if hasattr(alert.severity, "value") else alert.severity,
            "attack_type": alert.attack_type.value if hasattr(alert.attack_type, "value") else alert.attack_type,
            "src_ip": alert.src_ip,
            "ml_confidence": alert.ml_confidence,
        })


def on_threat_detected(features) -> None:
    """
    Callback fired by DetectionEngine when a threat is detected.
    Updates trust score and triggers alerts.
    This runs in the capture thread — keep it fast.
    """
    severity = _severity_from_attack(features.predicted_class)

    trust_engine.record_alert(
        ip=features.src_ip,
        severity=severity,
        attack_type=features.predicted_class,
        ml_confidence=features.ml_confidence,
    )
    logger.warning(
        f"🚨 {features.predicted_class.upper()} | {features.src_ip} → "
        f"{features.dst_ip}:{features.dst_port} | "
        f"Rule: {features.rule_triggered}"
    )

    # Persist to Postgres — this runs in a background thread, so schedule the
    # coroutine onto the main asyncio event loop instead of calling it directly.
    if _main_loop is not None:
        try:
            asyncio.run_coroutine_threadsafe(_persist_threat(features, severity), _main_loop)
        except Exception as e:
            logger.error(f"Failed to schedule DB persistence: {e}")


def _severity_from_attack(attack_type: str) -> str:
    severity_map = {
        "syn_flood":        "critical",
        "dns_exfiltration": "high",
        "brute_force":      "high",
        "port_scan":        "medium",
        "anomaly":          "medium",
        "normal":           "low",
    }
    return severity_map.get(attack_type.lower(), "medium")


# ── Lifespan ─────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic using modern FastAPI lifespan context."""
    global detection_engine, _main_loop

    _main_loop = asyncio.get_running_loop()

    setup_logging(debug=settings.debug)
    logger.info(f"🚀 Starting {settings.app_name} v{settings.app_version}")

    # Init DB
    await init_db()

    # Start detection engine in background thread (Scapy blocks)
    detection_engine = DetectionEngine(alert_callback=on_threat_detected)
    capture_thread = threading.Thread(
        target=detection_engine.start_capture,
        kwargs={
            "interface": settings.capture_interface,
            "packet_filter": settings.capture_filter,
        },
        daemon=True,
        name="PacketCapture",
    )
    capture_thread.start()
    logger.info(f"✅ Detection engine started on interface: {settings.capture_interface}")

    # Load ML inference engine and attach to detection engine
    ml_engine = get_inference_engine(
        model_dir="ml/models/",
        confidence_threshold=settings.ml_confidence_threshold,
    )
    detection_engine.set_ml_engine(ml_engine)
    if ml_engine.is_loaded:
        logger.info("✅ ML inference engine ready")
    else:
        logger.warning("⚠️  ML model not found — rule-based detection only (run: python ml/train.py)")

    yield  # Application runs here

    # Shutdown
    detection_engine.stop_capture()
    logger.info("🛑 DTAC-IR shutdown complete")


# ── App Factory ──────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "DTAC-IR: Dynamic Trust Assessment & Control — Incident Response Platform. "
            "Real-time network intrusion detection with ML-powered threat classification "
            "and automated response capabilities."
        ),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # CORS — allow React dev server in development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=(
            ["http://localhost:3000", "http://localhost:5173"]
            if settings.debug
            else [settings.environment]
        ),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    from app.api.v1.endpoints import alerts, devices, incidents, stats, websocket, ml
    app.include_router(alerts.router,    prefix=f"{settings.api_v1_prefix}/alerts",    tags=["Alerts"])
    app.include_router(devices.router,   prefix=f"{settings.api_v1_prefix}/devices",   tags=["Devices"])
    app.include_router(incidents.router, prefix=f"{settings.api_v1_prefix}/incidents", tags=["Incidents"])
    app.include_router(stats.router,     prefix=f"{settings.api_v1_prefix}/stats",     tags=["Statistics"])
    app.include_router(websocket.router, prefix=f"{settings.api_v1_prefix}/ws",        tags=["WebSocket"])
    app.include_router(ml.router,        prefix=f"{settings.api_v1_prefix}/ml",        tags=["ML Model"])

    @app.get("/health", tags=["Health"])
    async def health_check():
        return JSONResponse({
            "status": "healthy",
            "version": settings.app_version,
            "engine": detection_engine.get_stats() if detection_engine else "not started",
        })

    return app


app = create_app()
