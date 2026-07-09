"""Stats API — Dashboard statistics and metrics."""
from fastapi import APIRouter
from sqlalchemy import select, func, desc
from app.trust.scorer import trust_engine

router = APIRouter()


@router.get("/summary")
async def get_summary():
    """
    High-level dashboard summary stats.
    Returns counts and top threat sources — polled every 5s by the dashboard.
    """
    all_scores = trust_engine.get_all_scores()

    status_counts = {"trusted": 0, "suspicious": 0, "quarantined": 0, "blocked": 0}
    for device in all_scores.values():
        status = device.get("status", "trusted")
        status_counts[status] = status_counts.get(status, 0) + 1

    high_risk = sorted(
        [d for d in all_scores.values() if d["score"] < 50],
        key=lambda x: x["score"]
    )[:10]

    return {
        "total_devices": len(all_scores),
        "status_breakdown": status_counts,
        "high_risk_devices": high_risk,
        "average_trust_score": (
            sum(d["score"] for d in all_scores.values()) / len(all_scores)
            if all_scores else 100.0
        ),
    }
