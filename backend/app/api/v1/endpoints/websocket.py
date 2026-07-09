"""
WebSocket endpoint — Real-time event streaming to the React dashboard.
Pushes live alerts, trust score changes, and engine stats every second.
"""
import asyncio
import json
import time
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

from app.trust.scorer import trust_engine

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections for broadcast."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected | Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected | Remaining: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        if not self.active_connections:
            return
        data = json.dumps(message, default=str)
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_connections.remove(ws)


manager = ConnectionManager()


@router.websocket("/live")
async def websocket_live(websocket: WebSocket):
    """
    Main WebSocket endpoint.
    Streams: trust_update, engine_stats, ping
    Dashboard connects here for real-time data without polling.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Push stats every 2 seconds
            scores = trust_engine.get_all_scores()
            await manager.broadcast({
                "type": "trust_update",
                "timestamp": time.time(),
                "devices": list(scores.values())[:50],   # Top 50 devices
            })
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


async def broadcast_alert(alert_data: dict):
    """Called by detection engine when a new alert fires — pushes to all dashboards."""
    await manager.broadcast({
        "type": "new_alert",
        "timestamp": time.time(),
        "alert": alert_data,
    })
