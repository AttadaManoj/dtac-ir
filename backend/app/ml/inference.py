"""
DTAC-IR ML Pipeline — Step 7: Runtime Inference Engine

Bridges the trained ML model with the live packet capture pipeline.
Loaded once at startup, called per-packet during capture.

Design:
  - Model loaded into memory once (not per-request)
  - Thread-safe: multiple capture threads can call predict() concurrently
  - Graceful degradation: if model not found, falls back to rule-only detection
  - Confidence thresholding: low-confidence predictions don't trigger alerts

Integration with detection engine:
    from app.ml.inference import MLInferenceEngine
    engine = MLInferenceEngine.load()
    prediction = engine.predict(packet_features_dict)
"""
import json
import time
import threading
import numpy as np
import joblib
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from loguru import logger


@dataclass
class MLPrediction:
    """Result of a single ML inference call."""
    predicted_class: str        # e.g. "PORT_SCAN", "BENIGN"
    confidence: float           # 0.0 – 1.0 (max class probability)
    probabilities: dict         # {class_name: probability}
    is_threat: bool             # True if predicted_class != "BENIGN" and conf >= threshold
    inference_time_ms: float    # Latency tracking


class MLInferenceEngine:
    """
    Thread-safe runtime inference engine.

    Loads model artifacts once and serves predictions for live packets.
    Falls back to rule-based detection if model files are not found.

    Args:
        model_dir:           Directory containing ids_model.pkl, scaler.pkl, feature_list.json
        confidence_threshold: Minimum confidence to classify as threat (default: 0.75)
                             Below this, falls back to "BENIGN" even if model predicts threat.
                             Tunable — lower = more sensitive, more false positives.
    """

    def __init__(
        self,
        model_dir: str = "ml/models/",
        confidence_threshold: float = 0.75,
    ):
        self.model_dir = Path(model_dir)
        self.confidence_threshold = confidence_threshold
        self._lock = threading.Lock()

        self._model = None
        self._scaler = None
        self._label_encoder = None
        self._feature_names: list[str] = []
        self._class_names: list[str] = []
        self._loaded = False

        # Stats for dashboard monitoring
        self._stats = {
            "total_predictions": 0,
            "threats_detected": 0,
            "below_threshold": 0,
            "avg_inference_ms": 0.0,
        }

    @classmethod
    def load(
        cls,
        model_dir: str = "ml/models/",
        confidence_threshold: float = 0.75,
    ) -> "MLInferenceEngine":
        """
        Factory method — loads all artifacts and returns a ready engine.
        Returns an unloaded engine (graceful degradation) if files not found.
        """
        engine = cls(model_dir=model_dir, confidence_threshold=confidence_threshold)
        engine._try_load()
        return engine

    def _try_load(self) -> None:
        """Attempt to load model artifacts. Logs warning on failure instead of crashing."""
        model_path = self.model_dir / "ids_model.pkl"
        scaler_path = self.model_dir / "scaler.pkl"
        encoder_path = self.model_dir / "label_encoder.pkl"
        feature_path = self.model_dir / "feature_list.json"

        missing = [
            p for p in [model_path, scaler_path, encoder_path, feature_path]
            if not p.exists()
        ]
        if missing:
            logger.warning(
                f"⚠️  ML model not loaded — missing files: {[p.name for p in missing]}\n"
                f"   Run: python ml/train.py  to generate model artifacts\n"
                f"   Detection will use rule-based engine only until model is trained."
            )
            return

        try:
            self._model = joblib.load(model_path)
            self._scaler = joblib.load(scaler_path)
            self._label_encoder = joblib.load(encoder_path)

            with open(feature_path) as f:
                meta = json.load(f)
            self._feature_names = meta["feature_names"]
            self._class_names = meta["class_names"]
            self._loaded = True
            logger.info(
                f"✅ ML model loaded | "
                f"Classes: {self._class_names} | "
                f"Features: {len(self._feature_names)} | "
                f"Threshold: {self.confidence_threshold}"
            )
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def predict(self, features: dict) -> MLPrediction:
        """
        Classify a single packet's features.

        Args:
            features: Dict mapping feature name → value.
                     Missing features default to 0.0.
                     Extra features are ignored.

        Returns:
            MLPrediction dataclass with class, confidence, and threat flag.

        Thread-safe: uses a lock around numpy operations to prevent race conditions.
        """
        if not self._loaded:
            return MLPrediction(
                predicted_class="UNKNOWN",
                confidence=0.0,
                probabilities={},
                is_threat=False,
                inference_time_ms=0.0,
            )

        t0 = time.perf_counter()

        with self._lock:
            # Build feature vector in the exact order the model was trained on
            row = np.array(
                [float(features.get(f, 0.0)) for f in self._feature_names],
                dtype=np.float32,
            ).reshape(1, -1)

            # Scale
            row_scaled = self._scaler.transform(row)

            # Predict
            pred_int = self._model.predict(row_scaled)[0]
            probas = self._model.predict_proba(row_scaled)[0]

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Decode
        pred_class = self._label_encoder.inverse_transform([pred_int])[0]
        confidence = float(probas[pred_int])
        prob_dict = {
            self._class_names[i]: float(p)
            for i, p in enumerate(probas)
            if i < len(self._class_names)
        }

        # Apply confidence threshold
        is_threat = (pred_class != "BENIGN") and (confidence >= self.confidence_threshold)

        # Update stats
        self._stats["total_predictions"] += 1
        if is_threat:
            self._stats["threats_detected"] += 1
        elif pred_class != "BENIGN":
            self._stats["below_threshold"] += 1

        # Rolling average latency
        n = self._stats["total_predictions"]
        self._stats["avg_inference_ms"] = (
            (self._stats["avg_inference_ms"] * (n - 1) + elapsed_ms) / n
        )

        return MLPrediction(
            predicted_class=pred_class,
            confidence=confidence,
            probabilities=prob_dict,
            is_threat=is_threat,
            inference_time_ms=elapsed_ms,
        )

    def predict_batch(self, features_list: list[dict]) -> list[MLPrediction]:
        """
        Batch prediction — more efficient for bulk processing.
        Used for offline analysis of captured packet logs.
        """
        if not self._loaded or not features_list:
            return []

        t0 = time.perf_counter()

        with self._lock:
            matrix = np.array(
                [
                    [float(f.get(feat, 0.0)) for feat in self._feature_names]
                    for f in features_list
                ],
                dtype=np.float32,
            )
            matrix_scaled = self._scaler.transform(matrix)
            preds = self._model.predict(matrix_scaled)
            probas = self._model.predict_proba(matrix_scaled)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        per_sample_ms = elapsed_ms / len(features_list)

        results = []
        for i, (pred_int, prob_row) in enumerate(zip(preds, probas)):
            pred_class = self._label_encoder.inverse_transform([pred_int])[0]
            confidence = float(prob_row[pred_int])
            is_threat = (pred_class != "BENIGN") and (confidence >= self.confidence_threshold)
            results.append(MLPrediction(
                predicted_class=pred_class,
                confidence=confidence,
                probabilities={
                    self._class_names[j]: float(p)
                    for j, p in enumerate(prob_row)
                    if j < len(self._class_names)
                },
                is_threat=is_threat,
                inference_time_ms=per_sample_ms,
            ))

        return results

    def get_stats(self) -> dict:
        """Return inference statistics for dashboard monitoring."""
        return {
            **self._stats,
            "model_loaded": self._loaded,
            "confidence_threshold": self.confidence_threshold,
            "n_classes": len(self._class_names),
            "n_features": len(self._feature_names),
        }


# ── Module-level singleton (lazy-loaded) ─────────────────────────────────────────
_inference_engine: Optional[MLInferenceEngine] = None


def get_inference_engine(
    model_dir: str = "ml/models/",
    confidence_threshold: float = 0.75,
) -> MLInferenceEngine:
    """
    Get or create the module-level inference engine singleton.
    Call this from app startup instead of creating multiple instances.
    """
    global _inference_engine
    if _inference_engine is None:
        _inference_engine = MLInferenceEngine.load(
            model_dir=model_dir,
            confidence_threshold=confidence_threshold,
        )
    return _inference_engine
