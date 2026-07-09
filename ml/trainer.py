"""
DTAC-IR ML Pipeline — Step 4 & 5: Trainer + Evaluator

Trains a Random Forest classifier with:
  - Stratified K-Fold cross-validation
  - RandomizedSearchCV hyperparameter tuning
  - Full evaluation report: confusion matrix, per-class metrics, feature importance
  - Model serialisation to ml/models/ids_model.pkl

Why Random Forest for IDS?
  ✓ Handles mixed scales without normalisation (though we still scale for consistency)
  ✓ Built-in feature importance → explainability for interviews/reports
  ✓ Robust to noisy features (irrelevant features are just rarely used)
  ✓ No vanishing gradient issues like deep nets
  ✓ Fast inference: O(depth * n_trees) = microseconds per packet
"""
import json
import time
import numpy as np
import joblib
from pathlib import Path
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)


# ── Default Hyperparameter Search Space ──────────────────────────────────────────
RF_PARAM_GRID = {
    "n_estimators":      [100, 200, 300],
    "max_depth":         [10, 20, 30, None],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf":  [1, 2, 4],
    "max_features":      ["sqrt", "log2"],
    "class_weight":      ["balanced", "balanced_subsample", None],
}

# Fast training config for dev/testing
RF_FAST_CONFIG = {
    "n_estimators": 100,
    "max_depth": 20,
    "min_samples_split": 5,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "n_jobs": -1,
    "random_state": 42,
}

# Production config after hyperparameter search
RF_PROD_CONFIG = {
    "n_estimators": 300,
    "max_depth": 30,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "max_features": "sqrt",
    "class_weight": "balanced_subsample",
    "n_jobs": -1,
    "random_state": 42,
    "verbose": 1,
}


class IDSTrainer:
    """
    Trains and evaluates the Random Forest IDS model.

    Args:
        model_dir:  Where to save model artifacts
        fast_mode:  If True, uses RF_FAST_CONFIG (no hyperparameter search).
                    Use for development; use False for final portfolio submission.
        tune_hyperparams: Run RandomizedSearchCV before final fit (slow but better)
        cv_folds:   Number of cross-validation folds
        random_state: Reproducibility seed
    """

    def __init__(
        self,
        model_dir: str = "ml/models/",
        fast_mode: bool = False,
        tune_hyperparams: bool = False,
        cv_folds: int = 5,
        random_state: int = 42,
    ):
        self.model_dir = Path(model_dir)
        self.fast_mode = fast_mode
        self.tune_hyperparams = tune_hyperparams
        self.cv_folds = cv_folds
        self.random_state = random_state

        self.model: RandomForestClassifier = None
        self.feature_names: list[str] = []
        self.class_names: list[str] = []
        self.training_results: dict = {}

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: list[str] = None,
        class_names: list[str] = None,
    ) -> RandomForestClassifier:
        """
        Main training entry point.

        Args:
            X_train: Scaled feature matrix (output of Preprocessor.fit_transform)
            y_train: Encoded label array
            feature_names: For feature importance labelling
            class_names:   For human-readable evaluation output
        Returns:
            Fitted RandomForestClassifier
        """
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_train.shape[1])]
        self.class_names = class_names or [str(i) for i in np.unique(y_train)]

        logger.info(f"Training RF IDS | Samples: {len(X_train):,} | Features: {X_train.shape[1]}")
        logger.info(f"Mode: {'fast' if self.fast_mode else 'production'}")

        if self.fast_mode:
            self.model = self._train_fast(X_train, y_train)
        elif self.tune_hyperparams:
            self.model = self._train_with_tuning(X_train, y_train)
        else:
            self.model = self._train_production(X_train, y_train)

        return self.model

    def _train_fast(
        self, X_train: np.ndarray, y_train: np.ndarray
    ) -> RandomForestClassifier:
        """Fast training for dev iteration (~1–2 min on CICIDS2017 sample)."""
        logger.info("Fast mode: skipping hyperparameter search")
        rf = RandomForestClassifier(**RF_FAST_CONFIG)
        t0 = time.time()
        rf.fit(X_train, y_train)
        elapsed = time.time() - t0
        logger.info(f"✅ Fast training complete in {elapsed:.1f}s")
        self.training_results["training_time_s"] = elapsed
        self.training_results["mode"] = "fast"
        return rf

    def _train_production(
        self, X_train: np.ndarray, y_train: np.ndarray
    ) -> RandomForestClassifier:
        """Production training with cross-validation to verify generalisation."""
        logger.info("Production mode: fitting with cross-validation")
        rf = RandomForestClassifier(**RF_PROD_CONFIG)

        # K-Fold CV before final fit — tells us expected real-world performance
        logger.info(f"Running {self.cv_folds}-fold stratified cross-validation...")
        cv = StratifiedKFold(n_splits=self.cv_folds, shuffle=True, random_state=self.random_state)
        cv_scores = cross_val_score(rf, X_train, y_train, cv=cv, scoring="f1_weighted", n_jobs=-1)
        logger.info(
            f"CV F1 (weighted): {cv_scores.mean():.4f} ± {cv_scores.std():.4f} "
            f"[{cv_scores.min():.4f} – {cv_scores.max():.4f}]"
        )
        self.training_results["cv_f1_mean"] = float(cv_scores.mean())
        self.training_results["cv_f1_std"] = float(cv_scores.std())

        # Final fit on all training data
        t0 = time.time()
        rf.fit(X_train, y_train)
        elapsed = time.time() - t0
        logger.info(f"✅ Production training complete in {elapsed:.1f}s")
        self.training_results["training_time_s"] = elapsed
        self.training_results["mode"] = "production"
        return rf

    def _train_with_tuning(
        self, X_train: np.ndarray, y_train: np.ndarray
    ) -> RandomForestClassifier:
        """Full hyperparameter search — slow (~20–60 min) but optimal params."""
        logger.info("Hyperparameter tuning mode: RandomizedSearchCV (this will take a while...)")
        base_rf = RandomForestClassifier(n_jobs=-1, random_state=self.random_state)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=self.random_state)

        search = RandomizedSearchCV(
            base_rf,
            RF_PARAM_GRID,
            n_iter=20,
            cv=cv,
            scoring="f1_weighted",
            n_jobs=-1,
            random_state=self.random_state,
            verbose=2,
        )
        t0 = time.time()
        search.fit(X_train, y_train)
        elapsed = time.time() - t0

        logger.info(f"Best params: {search.best_params_}")
        logger.info(f"Best CV F1: {search.best_score_:.4f}")
        logger.info(f"Search completed in {elapsed:.1f}s")

        self.training_results["best_params"] = search.best_params_
        self.training_results["best_cv_f1"] = float(search.best_score_)
        self.training_results["tuning_time_s"] = elapsed
        self.training_results["mode"] = "tuned"
        return search.best_estimator_

    # ── Evaluation ───────────────────────────────────────────────────────────────

    def evaluate(
        self, X_test: np.ndarray, y_test: np.ndarray
    ) -> dict:
        """
        Full evaluation on held-out test set.
        Returns dict of metrics; also prints formatted report.
        """
        if self.model is None:
            raise RuntimeError("Model not trained yet — call train() first")

        logger.info("Evaluating on test set...")
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1_w = f1_score(y_test, y_pred, average="weighted")
        f1_m = f1_score(y_test, y_pred, average="macro")
        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(
            y_test, y_pred,
            target_names=self.class_names,
            output_dict=True,
        )

        print("\n" + "="*60)
        print("  DTAC-IR IDS Model — Evaluation Report")
        print("="*60)
        print(f"  Accuracy:        {acc:.4f} ({acc*100:.2f}%)")
        print(f"  F1 (weighted):   {f1_w:.4f}")
        print(f"  F1 (macro):      {f1_m:.4f}  ← key metric for imbalanced data")
        print("="*60)
        print("\nPer-class metrics:")
        print(classification_report(y_test, y_pred, target_names=self.class_names))
        print("Confusion matrix:")
        print(cm)

        results = {
            "accuracy": float(acc),
            "f1_weighted": float(f1_w),
            "f1_macro": float(f1_m),
            "confusion_matrix": cm.tolist(),
            "per_class": report,
            **self.training_results,
        }
        self.training_results.update(results)
        return results

    def feature_importance_report(self, top_n: int = 15) -> dict:
        """Print and return feature importances — great for portfolio documentation."""
        if self.model is None:
            raise RuntimeError("Model not trained yet")

        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]

        print(f"\nTop {top_n} Feature Importances:")
        print("-" * 40)
        importance_dict = {}
        for rank, idx in enumerate(indices, 1):
            name = self.feature_names[idx] if idx < len(self.feature_names) else f"f{idx}"
            score = importances[idx]
            bar = "█" * int(score * 200)
            print(f"  {rank:2}. {name:<30} {score:.4f}  {bar}")
            importance_dict[name] = float(score)

        return importance_dict

    # ── Persistence ──────────────────────────────────────────────────────────────

    def save_model(self) -> None:
        """Save trained model + training metadata to model_dir."""
        if self.model is None:
            raise RuntimeError("No model to save — train first")

        self.model_dir.mkdir(parents=True, exist_ok=True)
        model_path = self.model_dir / "ids_model.pkl"
        joblib.dump(self.model, model_path, compress=3)
        logger.info(f"✅ Model saved: {model_path} ({model_path.stat().st_size / 1024:.1f} KB)")

        # Save training metadata for portfolio/documentation
        meta_path = self.model_dir / "training_metadata.json"
        metadata = {
            "model_type": "RandomForestClassifier",
            "feature_names": self.feature_names,
            "class_names": self.class_names,
            "n_estimators": self.model.n_estimators,
            "max_depth": self.model.max_depth,
            **self.training_results,
        }
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"✅ Metadata saved: {meta_path}")

    @classmethod
    def load_model(cls, model_dir: str = "ml/models/") -> "IDSTrainer":
        """Load a previously trained model for inference."""
        instance = cls(model_dir=model_dir)
        model_path = Path(model_dir) / "ids_model.pkl"
        instance.model = joblib.load(model_path)

        meta_path = Path(model_dir) / "training_metadata.json"
        if meta_path.exists():
            with open(meta_path) as f:
                meta = json.load(f)
            instance.feature_names = meta.get("feature_names", [])
            instance.class_names = meta.get("class_names", [])

        logger.info(f"Model loaded from {model_path}")
        return instance
