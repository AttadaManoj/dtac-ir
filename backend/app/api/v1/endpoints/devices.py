"""Devices API — Device inventory + trust score management."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Device, DeviceStatus
from app.trust.scorer import trust_engine

router = APIRouter()


class TrustOverrideRequest(BaseModel):
    new_score: float
    reason: str


@router.get("/")
async def list_devices(
    status: DeviceStatus | None = None,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List all monitored devices with current trust scores."""
    query = select(Device).order_by(desc(Device.last_seen))
    if status:
        query = query.where(Device.status == status)
    query = query.limit(limit)
    result = await db.execute(query)
    devices = result.scalars().all()

    # Merge in-memory trust scores (real-time) with DB records
    live_scores = trust_engine.get_all_scores()

    return {
        "total": len(devices),
        "devices": [
            {
                "id": d.id,
                "ip_address": d.ip_address,
                "mac_address": d.mac_address,
                "hostname": d.hostname,
                "trust_score": live_scores.get(d.ip_address, {}).get("score", d.trust_score),
                "status": live_scores.get(d.ip_address, {}).get("status", d.status),
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "is_blocked": d.is_blocked,
                "total_packets": d.total_packets,
                "total_alerts": d.total_alerts,
            }
            for d in devices
        ],
    }


@router.get("/{ip}/trust")
async def get_device_trust(ip: str):
    """Get real-time trust score and event history for a device."""
    score = trust_engine.get_score(ip)
    status = trust_engine.get_status(ip)
    history = trust_engine.get_device_history(ip)
    return {
        "ip": ip,
        "score": score,
        "status": status,
        "history": history[-20:],  # Last 20 events
    }


@router.post("/{ip}/trust/override")
async def override_trust_score(
    ip: str,
    request: TrustOverrideRequest,
    db: AsyncSession = Depends(get_db),
):
    """Analyst manually overrides trust score (e.g., after false positive review)."""
    new_score = trust_engine.manual_override(ip, request.new_score, request.reason)
    return {
        "ip": ip,
        "new_score": new_score,
        "status": trust_engine.get_status(ip),
        "reason": request.reason,
    }


@router.get("/scores/live")
async def get_all_live_scores():
    """Get real-time trust scores for all tracked devices — used by dashboard."""
    return trust_engine.get_all_scores()
