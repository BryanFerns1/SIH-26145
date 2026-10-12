import pytest
import pandas as pd
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from training.prepare_data import time_block_split

def test_time_block_split():
    # Create a synthetic dataframe with timestamps spread over 100 seconds
    base_time = datetime(2026, 1, 1, 12, 0, 0)
    timestamps = [base_time + timedelta(seconds=i) for i in range(101)]
    
    df = pd.DataFrame({
        "Timestamp": timestamps,
        "dummy": range(101)
    })
    
    splits, gap = time_block_split(df, "monday", "BENIGN")
    
    # 100 seconds duration.
    # Train: 0-60
    # Val: 61-70
    # Gap: 71-75
    # Cal: 76-80
    # Test: 81-100
    
    assert len(splits["train"]) == 61
    assert len(splits["val"]) == 10
    assert gap == 5
    assert len(splits["cal"]) == 5
    assert len(splits["test"]) == 20
    
    # Check strict ordering
    assert splits["train"]["Timestamp"].max() < splits["val"]["Timestamp"].min()
    assert splits["val"]["Timestamp"].max() < splits["cal"]["Timestamp"].min()
    assert splits["cal"]["Timestamp"].max() < splits["test"]["Timestamp"].min()
