"""
DTAC-IR ML Pipeline — Step 2 & 3: Preprocessor + Feature Engineer

Handles:
  - Label encoding (string → integer)
  - Train/test stratified split
  - SMOTE oversampling for class imbalance
  - StandardScaler fitting (saved for runtime inference)
  - Feature importance-based selection

CICIDS2017 class imbalance example:
  BENIGN      2,271,320  (83%)   ← Dominant — without SMOTE, model ignores rare attacks
  PORT_SCAN      158,930   (6%)
  DOS            252,661   (9%)
  BRUTE_FORCE      13,835  (<1%)
  WEB_ATTACK        2,180  (<1%)  ← Critical to detect, hardest to learn
  BOTNET            1,966  (<1%)
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path
from loguru import logger
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils import resample

try:
    from imblearn.over_sampling import SMOTE
    SMOTE_AVAILABLE = True
except ImportError:
    SMOTE_AVAILABLE = False
    logger.warning("imbalanced-learn not installed — using random oversampling fallback")


class Preprocessor:
    """
    Transforms a raw loaded DataFrame into train/test arrays ready for sklearn.

    Saves:
      - scaler.pkl        → used at runtime for live packet inference
      - label_encoder.pkl → maps integer predictions back to class names
      - feature_list.json → tells inference engine which features to extract

    Args:
        test_size:     Fraction held out for evaluation (default 20%)
        random_state:  Reproducibility seed
        use_smote:     Apply SMOTE to training set (recommended for CICIDS2017)
        smote_strategy: 'minority' oversamples all minority classes to match majority,
                        or a dict like {'WEB_ATTACK': 50000} for manual targets
    """

    def __init__(
        self,
        test_size: float = 0.20,
        random_state: int = 42,
        use_smote: bool = True,
        smote_strategy: str = "minority",
    ):
        self.test_size = test_size
        self.random_state = random_state
        self.use_smote = use_smote and SMOTE_AVAILABLE
        self.smote_strategy = smote_strategy

        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names: list[str] = []
        self.class_names: list[str] = []
        self._is_fitted = False

    def fit_transform(self, df: pd.DataFrame) -> tuple:
        """
        Full preprocessing pipeline on training data.
        Returns: (X_train, X_test, y_train, y_test)
        """
        logger.info("Starting preprocessing pipeline...")

        # ── 1. Separate features and labels ─────────────────────────────────────
        self.feature_names = [c for c in df.columns if c != "label"]
        X = df[self.feature_names].values.astype(np.float32)
        y_raw = df["label"].values

        # ── 2. Encode labels to integers ─────────────────────────────────────────
        y = self.label_encoder.fit_transform(y_raw)
        self.class_names = list(self.label_encoder.classes_)
        logger.info(f"Classes: {self.class_names}")

        # ── 3. Train/test split (stratified) ─────────────────────────────────────
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )
        logger.info(f"Split: {len(X_train):,} train / {len(X_test):,} test")

        # ── 4. Handle class imbalance ─────────────────────────────────────────────
        X_train, y_train = self._balance_classes(X_train, y_train)

        # ── 5. Scale features ─────────────────────────────────────────────────────
        # CRITICAL: fit scaler on training data ONLY — never on test set
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)
        logger.info("Features scaled with StandardScaler")

        self._is_fitted = True
        return X_train, X_test, y_train, y_test

    def _balance_classes(
        self, X: np.ndarray, y: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray]:
        """Apply SMOTE or fallback random oversampling to training data."""
        class_counts = dict(zip(*np.unique(y, return_counts=True)))
        logger.info(f"Pre-balance class distribution: {class_counts}")

        if self.use_smote:
            try:
                # SMOTE needs at least k_neighbors+1 samples per class
                # Set k_neighbors=1 for very small minority classes
                min_samples = min(class_counts.values())
                k_neighbors = min(5, min_samples - 1)
                if k_neighbors < 1:
                    logger.warning("Too few minority samples for SMOTE — using random oversample")
                    return self._random_oversample(X, y)

                smote = SMOTE(
                    sampling_strategy=self.smote_strategy,
                    k_neighbors=k_neighbors,
                    random_state=self.random_state,
                )
                X_bal, y_bal = smote.fit_resample(X, y)
                new_counts = dict(zip(*np.unique(y_bal, return_counts=True)))
                logger.info(f"Post-SMOTE class distribution: {new_counts}")
                return X_bal, y_bal
            except Exception as e:
                logger.warning(f"SMOTE failed ({e}) — falling back to random oversample")
                return self._random_oversample(X, y)
        else:
            return self._random_oversample(X, y)

    def _random_oversample(
        self, X: np.ndarray, y: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray]:
        """Fallback: random oversampling when SMOTE isn't available."""
        max_count = max(np.bincount(y))
        X_parts, y_parts = [X], [y]
        for cls in np.unique(y):
            mask = y == cls
            n_needed = max_count - mask.sum()
            if n_needed > 0:
                X_over = resample(X[mask], n_samples=n_needed, random_state=self.random_state)
                y_over = np.full(n_needed, cls)
                X_parts.append(X_over)
                y_parts.append(y_over)
        return np.vstack(X_parts), np.concatenate(y_parts)

    def transform_single(self, features: dict) -> np.ndarray:
        """
        Transform a single packet's feature dict for runtime inference.
        Called by the inference engine for every live packet.

        Args:
            features: Dict of {feature_name: value} — must match feature_names order
        Returns:
            Scaled numpy array of shape (1, n_features)
        """
        if not self._is_fitted:
            raise RuntimeError("Preprocessor not fitted — run fit_transform first or load from disk")

        row = np.array(
            [features.get(f, 0.0) for f in self.feature_names],
            dtype=np.float32,
        ).reshape(1, -1)
        return self.scaler.transform(row)

    def decode_prediction(self, y_pred: int) -> str:
        """Convert integer prediction back to class name string."""
        return self.label_encoder.inverse_transform([y_pred])[0]

    def decode_predictions(self, y_pred: np.ndarray) -> list[str]:
        """Batch decode."""
        return list(self.label_encoder.inverse_transform(y_pred))

    def save_artifacts(self, model_dir: str = "ml/models/") -> None:
        """
        Save scaler and metadata needed for runtime inference.
        Call this after fit_transform and before deploying.
        """
        import joblib
        model_path = Path(model_dir)
        model_path.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, model_path / "scaler.pkl")
        joblib.dump(self.label_encoder, model_path / "label_encoder.pkl")

        metadata = {
            "feature_names": self.feature_names,
            "class_names": self.class_names,
            "n_features": len(self.feature_names),
            "n_classes": len(self.class_names),
        }
        with open(model_path / "feature_list.json", "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"✅ Artifacts saved to {model_dir}")
        logger.info(f"   scaler.pkl, label_encoder.pkl, feature_list.json")

    @classmethod
    def load_artifacts(cls, model_dir: str = "ml/models/") -> "Preprocessor":
        """Load a previously fitted preprocessor for inference (no training needed)."""
        import joblib
        model_path = Path(model_dir)

        instance = cls.__new__(cls)
        instance.scaler = joblib.load(model_path / "scaler.pkl")
        instance.label_encoder = joblib.load(model_path / "label_encoder.pkl")

        with open(model_path / "feature_list.json") as f:
            meta = json.load(f)

        instance.feature_names = meta["feature_names"]
        instance.class_names = meta["class_names"]
        instance._is_fitted = True
        logger.info(f"Preprocessor loaded from {model_dir}")
        return instance
