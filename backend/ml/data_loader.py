"""
DTAC-IR ML Pipeline — Step 1: Data Loader
Handles CICIDS2017 dataset: multi-file merge, column normalisation, label mapping.

CICIDS2017 structure (download from UNB):
  ml/datasets/
    Monday-WorkingHours.pcap_ISCX.csv      ← Benign only
    Tuesday-WorkingHours.pcap_ISCX.csv     ← FTP-Patator, SSH-Patator
    Wednesday-WorkingHours.pcap_ISCX.csv   ← DoS Slowloris, Slowhttptest, Hulk, GoldenEye, Heartbleed
    Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
    Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
    Friday-WorkingHours-Morning.pcap_ISCX.csv  ← Botnet
    Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

Usage:
    from ml.data_loader import CICIDSLoader
    loader = CICIDSLoader("ml/datasets/")
    df = loader.load()
"""
import os
import glob
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger


# ── Label Mapping ────────────────────────────────────────────────────────────────
# CICIDS2017 has 14+ label variants — map to our 7 canonical attack types.
LABEL_MAP = {
    # Benign
    "benign":                       "BENIGN",
    "normal":                       "BENIGN",

    # DoS / DDoS
    "dos hulk":                     "DOS",
    "dos goldeneye":                "DOS",
    "dos slowloris":                "DOS",
    "dos slowhttptest":             "DOS",
    "ddos":                         "DOS",
    "heartbleed":                   "DOS",

    # Port Scan
    "portscan":                     "PORT_SCAN",

    # Brute Force
    "ftp-patator":                  "BRUTE_FORCE",
    "ssh-patator":                  "BRUTE_FORCE",
    "brute force":                  "BRUTE_FORCE",

    # Web Attacks
    "web attack \x96 brute force":  "WEB_ATTACK",
    "web attack \x96 xss":          "WEB_ATTACK",
    "web attack \x96 sql injection":"WEB_ATTACK",
    "web attack – brute force":     "WEB_ATTACK",
    "web attack – xss":             "WEB_ATTACK",
    "web attack – sql injection":   "WEB_ATTACK",

    # Direct uppercase labels (from synthetic dataset generator)
    "benign":                       "BENIGN",  # already present, kept for clarity
    "port_scan":                    "PORT_SCAN",
    "dos":                          "DOS",
    "brute_force":                  "BRUTE_FORCE",
    "web_attack":                   "WEB_ATTACK",
    "botnet":                       "BOTNET",

    # Botnet / Infiltration
    "bot":                          "BOTNET",
    "infiltration":                 "BOTNET",
}

# The 20 features we actually use — selected by domain knowledge + importance analysis.
# Full CICIDS2017 has 78 features; many are redundant or near-zero variance.
SELECTED_FEATURES = [
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    " Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Mean",
    " Bwd Packet Length Max",
    " Bwd Packet Length Mean",
    " Flow Bytes/s",
    " Flow Packets/s",
    " Flow IAT Mean",
    " Flow IAT Std",
    " Fwd IAT Total",
    " Bwd IAT Total",
    " Fwd PSH Flags",
    " SYN Flag Count",
    " RST Flag Count",
    " ACK Flag Count",
    " Destination Port",
]

# Clean column name mapping (strip leading spaces, standardize)
FEATURE_RENAME = {f: f.strip() for f in SELECTED_FEATURES}
CLEAN_FEATURES = [f.strip() for f in SELECTED_FEATURES]


class CICIDSLoader:
    """
    Loads and preprocesses CICIDS2017 CSV files.

    Args:
        dataset_dir: Path to directory containing CICIDS2017 CSV files
        sample_frac: Fraction of data to use (0.0–1.0). Use < 1.0 for fast dev runs.
        random_state: Reproducibility seed
    """

    def __init__(
        self,
        dataset_dir: str = "ml/datasets/",
        sample_frac: float = 1.0,
        random_state: int = 42,
    ):
        self.dataset_dir = Path(dataset_dir)
        self.sample_frac = sample_frac
        self.random_state = random_state

    def load(self) -> pd.DataFrame:
        """
        Main entry point. Returns cleaned DataFrame with features + 'label' column.
        Raises FileNotFoundError if no CSVs found in dataset_dir.
        """
        csv_files = sorted(glob.glob(str(self.dataset_dir / "*.csv")))
        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files found in {self.dataset_dir}\n"
                f"Download CICIDS2017 from: https://www.unb.ca/cic/datasets/ids-2017.html\n"
                f"Extract to: {self.dataset_dir}"
            )

        logger.info(f"Found {len(csv_files)} CSV file(s) in {self.dataset_dir}")

        frames = []
        for path in csv_files:
            logger.info(f"  Loading: {os.path.basename(path)}")
            try:
                df = pd.read_csv(path, encoding="utf-8", low_memory=False)
                frames.append(df)
                logger.info(f"    → {len(df):,} rows, {len(df.columns)} cols")
            except Exception as e:
                logger.warning(f"    ⚠ Skipping {path}: {e}")

        if not frames:
            raise ValueError("All CSV files failed to load")

        combined = pd.concat(frames, ignore_index=True)
        logger.info(f"Combined: {len(combined):,} total rows")

        return self._preprocess(combined)

    def _preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        # ── 1. Find and clean label column ──────────────────────────────────────
        label_col = self._find_label_column(df)
        df = df.rename(columns={label_col: "raw_label"})
        df["label"] = df["raw_label"].str.strip().str.lower().map(LABEL_MAP)

        unmapped = df["label"].isna().sum()
        if unmapped > 0:
            unique_unmapped = df[df["label"].isna()]["raw_label"].unique()
            logger.warning(f"  {unmapped:,} rows with unmapped labels: {unique_unmapped}")
            df = df.dropna(subset=["label"])

        logger.info(f"Label distribution:\n{df['label'].value_counts().to_string()}")

        # ── 2. Select features ───────────────────────────────────────────────────
        available = [c for c in SELECTED_FEATURES if c in df.columns]
        missing = [c for c in SELECTED_FEATURES if c not in df.columns]
        if missing:
            logger.warning(f"  Missing {len(missing)} expected features: {missing[:5]}...")

        df = df[available + ["label"]].copy()
        df = df.rename(columns=FEATURE_RENAME)

        # ── 3. Clean numeric issues ──────────────────────────────────────────────
        feature_cols = [c for c in df.columns if c != "label"]
        df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")

        # Replace inf values
        df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

        # Drop rows where >50% of features are NaN
        threshold = len(feature_cols) * 0.5
        before = len(df)
        df = df.dropna(thresh=int(threshold) + len(["label"]))
        dropped = before - len(df)
        if dropped:
            logger.info(f"  Dropped {dropped:,} rows with excessive NaN")

        # Fill remaining NaN with column median
        df[feature_cols] = df[feature_cols].fillna(df[feature_cols].median())

        # ── 4. Sample if requested ───────────────────────────────────────────────
        if self.sample_frac < 1.0:
            # Stratified sample to preserve class distribution
            df = df.groupby("label", group_keys=False).apply(
                lambda x: x.sample(frac=self.sample_frac, random_state=self.random_state)
            )
            logger.info(f"  Sampled {self.sample_frac:.0%} → {len(df):,} rows")

        df = df.reset_index(drop=True)
        logger.info(f"✅ Final dataset: {len(df):,} rows, {len(df.columns)-1} features")
        return df

    def _find_label_column(self, df: pd.DataFrame) -> str:
        """CICIDS2017 label column varies slightly across files."""
        candidates = [" Label", "Label", "label", " label", "Class", "class"]
        for col in candidates:
            if col in df.columns:
                return col
        # Fallback: last column is usually the label
        logger.warning(f"Label column not found in {list(df.columns[-3:])} — using last column")
        return df.columns[-1]

    @staticmethod
    def describe(df: pd.DataFrame) -> None:
        """Print a quick summary of the loaded dataset."""
        print(f"\n{'='*50}")
        print(f"Dataset shape: {df.shape}")
        print(f"\nClass distribution:")
        vc = df["label"].value_counts()
        for cls, count in vc.items():
            pct = count / len(df) * 100
            print(f"  {cls:<20} {count:>8,}  ({pct:5.1f}%)")
        print(f"\nFeatures: {[c for c in df.columns if c != 'label']}")
        print(f"{'='*50}\n")
