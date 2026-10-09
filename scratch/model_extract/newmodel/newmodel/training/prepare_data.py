"""
UniGuard Stage 1: Data Prep & Time-blocked Splitting.

1. Reads raw CSVs from CIC-IDS2017-improved
2. Extracts metadata (Flow ID, IPs, Ports, Timestamp) + Base Features
3. Drops 'Attempted Category' != -1 rows and EXACT duplicates of features
4. Performs a strictly TIME-BLOCKED split per (day, class):
   Train 60% | Val 10% | Gap 5% (dropped) | Cal 5% | Test 20%
5. Computes derived forward-only features and saves to parquets.
"""
import json
import logging
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from uniguard.features import prepare

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOGS_DIR / "prepare_data.log", mode="w", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


def get_metadata_cols():
    return ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp']


def time_block_split(df: pd.DataFrame, day: str, label: str):
    """
    Splits a dataframe of a specific day and label into time blocks.
    Train 60% | Val 10% | Gap 5% | Cal 5% | Test 20%
    """
    if len(df) == 0:
        return {}, 0
        
    df = df.copy()
    
    # Try multiple datetime formats
    try:
        df['dt'] = pd.to_datetime(df['Timestamp'], format='mixed', dayfirst=True)
    except:
        try:
            df['dt'] = pd.to_datetime(df['Timestamp'])
        except Exception as e:
            log.error(f"Could not parse timestamp for {day} {label}: {e}")
            return {"train": df, "val": pd.DataFrame(), "cal": pd.DataFrame(), "test": pd.DataFrame()}, 0
            
    df = df.sort_values('dt')
    
    n_total = len(df)
    t_min = df['dt'].min()
    t_max = df['dt'].max()
    t_duration = t_max - t_min
    
    if t_duration.total_seconds() == 0:
        # Fall back to row-count splitting if everything happens at the exact same second
        idx_train = int(n_total * 0.6)
        idx_val = int(n_total * 0.7)
        idx_gap = int(n_total * 0.75)
        idx_cal = int(n_total * 0.8)
        
        splits = {
            "train": df.iloc[:idx_train].drop(columns=['dt']),
            "val": df.iloc[idx_train:idx_val].drop(columns=['dt']),
            "cal": df.iloc[idx_gap:idx_cal].drop(columns=['dt']),
            "test": df.iloc[idx_cal:].drop(columns=['dt'])
        }
        gap_dropped = idx_gap - idx_val
        return splits, gap_dropped

    t_train = t_min + t_duration * 0.60
    t_val = t_min + t_duration * 0.70
    t_gap = t_min + t_duration * 0.75
    t_cal = t_min + t_duration * 0.80

    mask_train = df['dt'] <= t_train
    mask_val = (df['dt'] > t_train) & (df['dt'] <= t_val)
    mask_gap = (df['dt'] > t_val) & (df['dt'] <= t_gap)
    mask_cal = (df['dt'] > t_gap) & (df['dt'] <= t_cal)
    mask_test = df['dt'] > t_cal
    
    splits = {
        "train": df[mask_train].drop(columns=['dt']),
        "val": df[mask_val].drop(columns=['dt']),
        "cal": df[mask_cal].drop(columns=['dt']),
        "test": df[mask_test].drop(columns=['dt'])
    }
    gap_dropped = mask_gap.sum()
    
    return splits, gap_dropped


def main():
    log.info("STAGE 1: Data Audit & Time-blocked Splitting")
    
    data_dir = Path(r"C:\Users\soura\Downloads\CICIDS2017_improved")
    if not data_dir.exists():
        log.error(f"Directory not found: {data_dir}")
        return
        
    csv_files = list(data_dir.glob("*.csv"))
    if not csv_files:
        log.error("No CSV files found.")
        return
        
    # We will build 4 dataframes for the splits
    split_dfs = {"train": [], "val": [], "cal": [], "test": []}
    
    total_raw_rows = 0
    total_attempted_dropped = 0
    total_dedup_dropped = 0
    total_gap_dropped = 0
    
    meta_cols = get_metadata_cols()
    
    for f in csv_files:
        day_name = f.stem.lower()
        log.info(f"Processing {day_name}...")
        
        # We need Label, Attempted Category, meta cols, and BASE_FEATURES
        # Some columns might have trailing spaces in the CSV headers
        try:
            # Read first row to get columns
            sample = pd.read_csv(f, nrows=1)
            raw_cols = sample.columns.tolist()
            col_map = {c.strip(): c for c in raw_cols}
            
            usecols = []
            for c in meta_cols + config.BASE_FEATURES + ['Label', 'Attempted Category']:
                if c in col_map:
                    usecols.append(col_map[c])
                    
            df = pd.read_csv(f, usecols=usecols)
            df.rename(columns={c: c.strip() for c in df.columns}, inplace=True)
            
        except Exception as e:
            log.error(f"Error reading {f}: {e}")
            continue
            
        initial_len = len(df)
        total_raw_rows += initial_len
        
        # 1. Drop Attempted
        if 'Attempted Category' in df.columns:
            mask_attempted = df['Attempted Category'] != -1
            n_attempted = mask_attempted.sum()
            if n_attempted > 0:
                df = df[~mask_attempted]
                total_attempted_dropped += n_attempted
            df = df.drop(columns=['Attempted Category'])
            
        # 2. Map Labels
        df['Label'] = df['Label'].replace(config.LABEL_MERGE)
        
        # 3. Deduplicate exact feature rows (excluding metadata)
        # We find duplicate rows looking ONLY at BASE_FEATURES + Label
        feat_cols = [c for c in config.BASE_FEATURES if c in df.columns]
        n_before_dedup = len(df)
        df = df.drop_duplicates(subset=feat_cols + ['Label'])
        n_dedup = n_before_dedup - len(df)
        total_dedup_dropped += n_dedup
        
        # 4. Time-blocked split per class
        for label in df['Label'].unique():
            df_class = df[df['Label'] == label]
            splits, gap = time_block_split(df_class, day_name, label)
            
            total_gap_dropped += gap
            
            for split_name, df_split in splits.items():
                if len(df_split) > 0:
                    # add day column for tracking
                    df_split = df_split.copy()
                    df_split['day'] = day_name
                    split_dfs[split_name].append(df_split)
                    
    log.info("\n=== Data Processing Summary ===")
    log.info(f"Total Raw Rows:        {total_raw_rows:,}")
    log.info(f"Attempted Dropped:     {total_attempted_dropped:,}")
    log.info(f"Exact Dedup Dropped:   {total_dedup_dropped:,}")
    log.info(f"Time-Gap Dropped:      {total_gap_dropped:,}")
    
    # Concatenate and compute derived features
    out_dir = config.PROJECT_ROOT / "data_processed"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    for split_name in ["train", "val", "cal", "test"]:
        if not split_dfs[split_name]:
            log.warning(f"No data for split {split_name}")
            continue
            
        combined = pd.concat(split_dfs[split_name], ignore_index=True)
        log.info(f"\nComputing features for {split_name.upper()} split ({len(combined):,} rows)")
        
        # Print class distribution for this split
        log.info(combined['Label'].value_counts().to_string())
        
        # Prepare features (Base -> All)
        X = prepare(combined, config.BASE_FEATURES, config.ALL_FEATURES, derived=True, validate=True)
        
        # Add back metadata and Label
        for c in meta_cols + ['Label', 'day']:
            if c in combined.columns:
                X[c] = combined[c]
                
        # Save parquet
        out_path = out_dir / f"{split_name}.parquet"
        X.to_parquet(out_path)
        log.info(f"Saved {out_path}")
        
    log.info("\nSTAGE 1 COMPLETE: Time-blocked splitting and preparation.")


if __name__ == "__main__":
    main()
