"""Alerts API — CRUD + filtering for security alerts."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from loguru import logger

from app.core.database import get_db
from app.models.models import Alert, AlertStatus, SeverityLevel

router = APIRouter()


@router.get("/")
async def list_alerts(
    status: Optional[AlertStatus] = None,
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with optional filtering by status and severity."""
    query = select(Alert).order_by(desc(Alert.created_at))

    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "total": len(alerts),
        "offset": offset,
        "limit": limit,
        "alerts": [
            {
                "id": a.id,
                "created_at": a.created_at,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "attack_type": a.attack_type,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "dst_port": a.dst_port,
                "ml_confidence": a.ml_confidence,
                "rule_triggered": a.rule_triggered,
                "is_acknowledged": a.is_acknowledged,
            }
            for a in alerts
        ],
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Get a single alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    analyst: str = Query(..., description="Analyst name acknowledging the alert"),
    db: AsyncSession = Depends(get_db),
):
    """Mark an alert as acknowledged by an analyst."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    alert.is_acknowledged = True
    alert.acknowledged_by = analyst
    alert.status = AlertStatus.INVESTIGATING
    await db.commit()
    logger.info(f"Alert {alert_id} acknowledged by {analyst}")
    return {"message": f"Alert {alert_id} acknowledged", "acknowledged_by": analyst}


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    status: AlertStatus,
    db: AsyncSession = Depends(get_db),
):
    """Update alert status (investigating → resolved / false_positive)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    alert.status = status
    await db.commit()
    return {"message": f"Alert {alert_id} status updated to {status}"}
