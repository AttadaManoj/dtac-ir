"""
DTAC-IR ML Pipeline — Entry Point
Run this script to train the IDS model from scratch.

Usage:
    # From project root, with ml training venv:
    pip install -r ml/requirements-train.txt

    # Fast mode (dev — ~2–5 min, lower accuracy):
    python ml/train.py --fast

    # Full mode (portfolio — ~15–30 min, best accuracy):
    python ml/train.py

    # With hyperparameter tuning (~60+ min):
    python ml/train.py --tune

    # Use only 20% of data (quick smoke test):
    python ml/train.py --fast --sample 0.2

Output (all in ml/models/):
    ids_model.pkl          ← Trained Random Forest
    scaler.pkl             ← StandardScaler (used at runtime)
    label_encoder.pkl      ← Label ↔ integer mapping
    feature_list.json      ← Feature names + class names metadata
    training_metadata.json ← Metrics, params, timestamps
"""
import sys
import time
import argparse
from pathlib import Path
from loguru import logger

# Allow running from project root: python ml/train.py
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.data_loader import CICIDSLoader
from ml.preprocessor import Preprocessor
from ml.trainer import IDSTrainer


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train DTAC-IR IDS model on CICIDS2017 dataset"
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="Fast training mode: 100 trees, no CV (dev iteration)"
    )
    parser.add_argument(
        "--tune", action="store_true",
        help="Run RandomizedSearchCV hyperparameter tuning (slow)"
    )
    parser.add_argument(
        "--sample", type=float, default=1.0,
        help="Fraction of dataset to use (0.1–1.0). Default: 1.0"
    )
    parser.add_argument(
        "--dataset-dir", type=str, default="ml/datasets/",
        help="Path to CICIDS2017 CSV directory. Default: ml/datasets/"
    )
    parser.add_argument(
        "--model-dir", type=str, default="ml/models/",
        help="Output directory for model artifacts. Default: ml/models/"
    )
    parser.add_argument(
        "--no-smote", action="store_true",
        help="Disable SMOTE oversampling (faster, less accurate on minority classes)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    t_start = time.time()

    logger.info("="*60)
    logger.info("  DTAC-IR IDS Model Training Pipeline")
    logger.info("="*60)
    logger.info(f"  Dataset dir:  {args.dataset_dir}")
    logger.info(f"  Model dir:    {args.model_dir}")
    logger.info(f"  Sample frac:  {args.sample}")
    logger.info(f"  Fast mode:    {args.fast}")
    logger.info(f"  Tune params:  {args.tune}")
    logger.info(f"  SMOTE:        {not args.no_smote}")
    logger.info("="*60)

    # ── Step 1: Load Data ────────────────────────────────────────────────────────
    logger.info("\n[1/5] Loading CICIDS2017 dataset...")
    loader = CICIDSLoader(
        dataset_dir=args.dataset_dir,
        sample_frac=args.sample,
    )
    try:
        df = loader.load()
    except FileNotFoundError as e:
        logger.error(str(e))
        logger.info("\n📥 How to get the dataset:")
        logger.info("  1. Go to: https://www.unb.ca/cic/datasets/ids-2017.html")
        logger.info("  2. Download the CSV files (not PCAP)")
        logger.info(f"  3. Extract to: {args.dataset_dir}")
        logger.info("\n💡 For testing without the real dataset:")
        logger.info("  python ml/generate_synthetic.py  ← creates a small synthetic dataset")
        sys.exit(1)

    CICIDSLoader.describe(df)

    # ── Step 2 & 3: Preprocess ───────────────────────────────────────────────────
    logger.info("\n[2/5] Preprocessing and splitting data...")
    preprocessor = Preprocessor(
        test_size=0.20,
        use_smote=not args.no_smote,
    )
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(df)

    # ── Step 4: Train ────────────────────────────────────────────────────────────
    logger.info("\n[3/5] Training Random Forest...")
    trainer = IDSTrainer(
        model_dir=args.model_dir,
        fast_mode=args.fast,
        tune_hyperparams=args.tune,
    )
    trainer.train(
        X_train, y_train,
        feature_names=preprocessor.feature_names,
        class_names=preprocessor.class_names,
    )

    # ── Step 5: Evaluate ─────────────────────────────────────────────────────────
    logger.info("\n[4/5] Evaluating on test set...")
    results = trainer.evaluate(X_test, y_test)
    trainer.feature_importance_report(top_n=15)

    # ── Step 6: Save ─────────────────────────────────────────────────────────────
    logger.info("\n[5/5] Saving model artifacts...")
    trainer.save_model()
    preprocessor.save_artifacts(args.model_dir)

    # ── Summary ──────────────────────────────────────────────────────────────────
    total_time = time.time() - t_start
    logger.info("\n" + "="*60)
    logger.info("  Training Complete!")
    logger.info("="*60)
    logger.info(f"  Accuracy:       {results['accuracy']:.4f} ({results['accuracy']*100:.2f}%)")
    logger.info(f"  F1 (weighted):  {results['f1_weighted']:.4f}")
    logger.info(f"  F1 (macro):     {results['f1_macro']:.4f}")
    logger.info(f"  Total time:     {total_time:.1f}s ({total_time/60:.1f} min)")
    logger.info("="*60)
    logger.info(f"\nModel artifacts saved to: {args.model_dir}")
    logger.info("Next step: start the backend — it will auto-load the model on startup.")

    return results


if __name__ == "__main__":
    main()
