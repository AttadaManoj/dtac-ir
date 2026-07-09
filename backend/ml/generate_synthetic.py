"""
DTAC-IR — Synthetic Dataset Generator
Generates a realistic synthetic network traffic dataset for testing the ML pipeline
WITHOUT needing to download the 8GB CICIDS2017 dataset.

Useful for:
  - Validating the full train → save → infer pipeline works
  - CI/CD testing
  - Quick demos without dataset setup

Generated classes mimic CICIDS2017 feature distributions:
  BENIGN, PORT_SCAN, DOS, BRUTE_FORCE, WEB_ATTACK, BOTNET

Usage:
    python ml/generate_synthetic.py
    python ml/generate_synthetic.py --samples 50000 --output ml/datasets/synthetic.csv
"""
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from loguru import logger


# Feature name must match SELECTED_FEATURES in data_loader.py (stripped)
FEATURE_COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Fwd IAT Total", "Bwd IAT Total",
    "Fwd PSH Flags", "SYN Flag Count", "RST Flag Count",
    "ACK Flag Count", "Destination Port",
]

# Each class: (mean_vector, std_scale, n_samples)
# Values are rough approximations of CICIDS2017 class distributions
CLASS_PROFILES = {
    "BENIGN": {
        "n": 70000,
        "features": {
            "Flow Duration":              (100000, 50000),
            "Total Fwd Packets":          (10, 8),
            "Total Backward Packets":     (8, 6),
            "Total Length of Fwd Packets":(1500, 800),
            "Total Length of Bwd Packets":(1200, 600),
            "Fwd Packet Length Max":      (500, 200),
            "Fwd Packet Length Mean":     (150, 80),
            "Bwd Packet Length Max":      (400, 200),
            "Bwd Packet Length Mean":     (130, 70),
            "Flow Bytes/s":               (5000, 3000),
            "Flow Packets/s":             (50, 30),
            "Flow IAT Mean":              (5000, 2000),
            "Flow IAT Std":               (3000, 1500),
            "Fwd IAT Total":              (50000, 20000),
            "Bwd IAT Total":              (50000, 20000),
            "Fwd PSH Flags":              (1, 0.5),
            "SYN Flag Count":             (1, 0.3),
            "RST Flag Count":             (0, 0.1),
            "ACK Flag Count":             (10, 5),
            "Destination Port":           (443, 100),
        }
    },
    "PORT_SCAN": {
        "n": 10000,
        "features": {
            "Flow Duration":              (500, 300),    # Very short flows
            "Total Fwd Packets":          (1, 0.5),      # Single SYN
            "Total Backward Packets":     (0.5, 0.3),
            "Total Length of Fwd Packets":(60, 20),
            "Total Length of Bwd Packets":(40, 15),
            "Fwd Packet Length Max":      (60, 10),
            "Fwd Packet Length Mean":     (60, 5),
            "Bwd Packet Length Max":      (40, 10),
            "Bwd Packet Length Mean":     (40, 5),
            "Flow Bytes/s":               (50000, 20000), # High rate, tiny packets
            "Flow Packets/s":             (500, 200),
            "Flow IAT Mean":              (100, 50),
            "Flow IAT Std":               (50, 20),
            "Fwd IAT Total":              (100, 50),
            "Bwd IAT Total":              (100, 50),
            "Fwd PSH Flags":              (0, 0.1),
            "SYN Flag Count":             (1, 0.2),       # All SYN, no ACK
            "RST Flag Count":             (0.5, 0.3),
            "ACK Flag Count":             (0.2, 0.2),
            "Destination Port":           (32768, 20000), # Random high ports
        }
    },
    "DOS": {
        "n": 12000,
        "features": {
            "Flow Duration":              (60000, 20000),
            "Total Fwd Packets":          (500, 200),     # Flood
            "Total Backward Packets":     (5, 3),
            "Total Length of Fwd Packets":(30000, 10000),
            "Total Length of Bwd Packets":(300, 100),
            "Fwd Packet Length Max":      (60, 10),
            "Fwd Packet Length Mean":     (60, 5),        # Uniform small packets
            "Bwd Packet Length Max":      (60, 20),
            "Bwd Packet Length Mean":     (60, 10),
            "Flow Bytes/s":               (500000, 100000),# Very high throughput
            "Flow Packets/s":             (5000, 2000),
            "Flow IAT Mean":              (200, 50),      # Very low inter-arrival
            "Flow IAT Std":               (50, 20),
            "Fwd IAT Total":              (100000, 30000),
            "Bwd IAT Total":              (1000, 500),
            "Fwd PSH Flags":              (0, 0.1),
            "SYN Flag Count":             (500, 100),     # SYN flood
            "RST Flag Count":             (0, 0.1),
            "ACK Flag Count":             (2, 1),
            "Destination Port":           (80, 5),        # Targeting web server
        }
    },
    "BRUTE_FORCE": {
        "n": 3000,
        "features": {
            "Flow Duration":              (5000, 2000),
            "Total Fwd Packets":          (20, 10),
            "Total Backward Packets":     (15, 8),
            "Total Length of Fwd Packets":(800, 300),
            "Total Length of Bwd Packets":(600, 200),
            "Fwd Packet Length Max":      (100, 30),
            "Fwd Packet Length Mean":     (40, 15),
            "Bwd Packet Length Max":      (80, 20),
            "Bwd Packet Length Mean":     (40, 15),
            "Flow Bytes/s":               (5000, 2000),
            "Flow Packets/s":             (200, 80),
            "Flow IAT Mean":              (2000, 800),
            "Flow IAT Std":               (1000, 500),
            "Fwd IAT Total":              (30000, 10000),
            "Bwd IAT Total":              (30000, 10000),
            "Fwd PSH Flags":              (1, 0.5),
            "SYN Flag Count":             (1, 0.3),
            "RST Flag Count":             (1, 0.5),
            "ACK Flag Count":             (15, 8),
            "Destination Port":           (22, 0.5),      # Always SSH
        }
    },
    "WEB_ATTACK": {
        "n": 2000,
        "features": {
            "Flow Duration":              (10000, 5000),
            "Total Fwd Packets":          (8, 4),
            "Total Backward Packets":     (6, 3),
            "Total Length of Fwd Packets":(2000, 800),   # Large payloads (SQLi strings)
            "Total Length of Bwd Packets":(3000, 1000),
            "Fwd Packet Length Max":      (1000, 300),
            "Fwd Packet Length Mean":     (250, 100),
            "Bwd Packet Length Max":      (1500, 400),
            "Bwd Packet Length Mean":     (500, 150),
            "Flow Bytes/s":               (20000, 8000),
            "Flow Packets/s":             (80, 30),
            "Flow IAT Mean":              (3000, 1000),
            "Flow IAT Std":               (2000, 800),
            "Fwd IAT Total":              (20000, 8000),
            "Bwd IAT Total":              (15000, 6000),
            "Fwd PSH Flags":              (1, 0.4),
            "SYN Flag Count":             (1, 0.3),
            "RST Flag Count":             (0, 0.1),
            "ACK Flag Count":             (8, 4),
            "Destination Port":           (80, 5),
        }
    },
    "BOTNET": {
        "n": 3000,
        "features": {
            "Flow Duration":              (200000, 80000), # Long-lived C2 connections
            "Total Fwd Packets":          (50, 20),
            "Total Backward Packets":     (40, 15),
            "Total Length of Fwd Packets":(3000, 1000),
            "Total Length of Bwd Packets":(2500, 800),
            "Fwd Packet Length Max":      (200, 80),
            "Fwd Packet Length Mean":     (60, 20),       # Small beacons
            "Bwd Packet Length Max":      (200, 80),
            "Bwd Packet Length Mean":     (60, 20),
            "Flow Bytes/s":               (1000, 500),    # Low and slow
            "Flow Packets/s":             (5, 2),
            "Flow IAT Mean":              (20000, 8000),  # Regular intervals (beacon)
            "Flow IAT Std":               (2000, 800),    # Low std = regular timing
            "Fwd IAT Total":              (500000, 200000),
            "Bwd IAT Total":              (400000, 150000),
            "Fwd PSH Flags":              (1, 0.4),
            "SYN Flag Count":             (1, 0.3),
            "RST Flag Count":             (0, 0.1),
            "ACK Flag Count":             (50, 20),
            "Destination Port":           (6667, 100),    # IRC/C2 port
        }
    },
}


def generate_synthetic_dataset(
    n_total: int = 100000,
    output_path: str = "ml/datasets/synthetic.csv",
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Generate synthetic CICIDS2017-like dataset.

    Args:
        n_total:     Total samples (distributed proportionally across classes)
        output_path: Where to save the CSV
        random_state: Seed for reproducibility
    """
    rng = np.random.RandomState(random_state)
    frames = []

    # Scale n_samples proportionally to n_total
    base_total = sum(p["n"] for p in CLASS_PROFILES.values())
    scale = n_total / base_total

    logger.info(f"Generating {n_total:,} synthetic samples...")

    for label, profile in CLASS_PROFILES.items():
        n = max(100, int(profile["n"] * scale))
        rows = {}
        for feat in FEATURE_COLS:
            mean, std = profile["features"].get(feat, (0, 1))
            values = rng.normal(mean, std, n)
            values = np.clip(values, 0, None)  # All network features are non-negative
            rows[feat] = values

        df_class = pd.DataFrame(rows)
        df_class["Label"] = label
        frames.append(df_class)
        logger.info(f"  {label:<20}: {n:,} samples generated")

    df = pd.concat(frames, ignore_index=True)

    # Shuffle
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)

    # Add leading spaces to feature names to match CICIDS2017 format
    rename_map = {f: f" {f}" for f in FEATURE_COLS}
    df = df.rename(columns=rename_map)

    # Save
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    logger.info(f"\n✅ Synthetic dataset saved: {output}")
    logger.info(f"   Shape: {df.shape}")
    logger.info(f"   Size:  {output.stat().st_size / 1024:.1f} KB")
    logger.info(f"\nClass distribution:")
    for cls, count in df["Label"].value_counts().items():
        logger.info(f"  {cls:<20} {count:>6,}")

    return df


def parse_args():
    parser = argparse.ArgumentParser(description="Generate synthetic IDS training data")
    parser.add_argument("--samples", type=int, default=100000, help="Total samples to generate")
    parser.add_argument("--output", type=str, default="ml/datasets/synthetic.csv")
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    generate_synthetic_dataset(
        n_total=args.samples,
        output_path=args.output,
        random_state=args.seed,
    )
    logger.info("\nNext step: python ml/train.py --fast")
