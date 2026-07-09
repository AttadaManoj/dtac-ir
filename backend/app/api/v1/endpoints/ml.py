"""ML API — Model status, inference stats, and manual prediction endpoint."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class PredictRequest(BaseModel):
    """Manual prediction request — for testing the model via API."""
    destination_port: int = 80
    total_fwd_packets: int = 10
    total_length_fwd_packets: int = 1500
    fwd_packet_length_max: int = 500
    fwd_packet_length_mean: float = 150.0
    flow_bytes_per_sec: float = 5000.0
    flow_packets_per_sec: float = 50.0
    syn_flag_count: int = 1
    rst_flag_count: int = 0
    ack_flag_count: int = 10
    fwd_psh_flags: int = 1


@router.get("/status")
async def ml_status():
    """Get current ML model status and inference statistics."""
    from app.ml.inference import get_inference_engine
    engine = get_inference_engine()
    stats = engine.get_stats()
    return {
        "model_loaded": stats["model_loaded"],
        "n_classes": stats.get("n_classes", 0),
        "n_features": stats.get("n_features", 0),
        "confidence_threshold": stats["confidence_threshold"],
        "inference_stats": {
            "total_predictions": stats["total_predictions"],
            "threats_detected": stats["threats_detected"],
            "below_threshold": stats["below_threshold"],
            "avg_inference_ms": round(stats["avg_inference_ms"], 3),
        },
        "note": (
            "Model active" if stats["model_loaded"]
            else "Run 'python ml/train.py' to train and load the model"
        ),
    }


@router.post("/predict")
async def manual_predict(request: PredictRequest):
    """
    Manually test the ML model with custom feature values.
    Useful for demos and validation — hit this from the Swagger UI.
    """
    from app.ml.inference import get_inference_engine
    engine = get_inference_engine()

    if not engine.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="ML model not loaded. Train it first: python ml/train.py"
        )

    features = {
        "Destination Port":            request.destination_port,
        "Total Fwd Packets":           request.total_fwd_packets,
        "Total Length of Fwd Packets": request.total_length_fwd_packets,
        "Fwd Packet Length Max":       request.fwd_packet_length_max,
        "Fwd Packet Length Mean":      request.fwd_packet_length_mean,
        "Flow Bytes/s":                request.flow_bytes_per_sec,
        "Flow Packets/s":              request.flow_packets_per_sec,
        "SYN Flag Count":              request.syn_flag_count,
        "RST Flag Count":              request.rst_flag_count,
        "ACK Flag Count":              request.ack_flag_count,
        "Fwd PSH Flags":               request.fwd_psh_flags,
    }

    prediction = engine.predict(features)
    return {
        "predicted_class": prediction.predicted_class,
        "confidence": round(prediction.confidence, 4),
        "is_threat": prediction.is_threat,
        "probabilities": {k: round(v, 4) for k, v in prediction.probabilities.items()},
        "inference_time_ms": round(prediction.inference_time_ms, 3),
    }
