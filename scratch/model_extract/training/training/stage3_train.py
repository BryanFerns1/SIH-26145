"""
Stage 3: Model training for UniGuard 1D CNN Beacon Detector.

Trains Variant A, B, and A+B models with:
  - Focal loss
  - Capture-level splits
  - 3 random seeds (mean +/- std reporting)
  - Early stopping on validation loss
"""

import os
import sys
import time
import json
import pickle
import random
import argparse
from collections import Counter, defaultdict

import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


def set_seeds(seed: int):
    """Set all random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    import tensorflow as tf
    tf.random.set_seed(seed)


def load_flows(flows_path: str) -> list:
    """Load extracted flows from pickle."""
    with open(flows_path, 'rb') as f:
        return pickle.load(f)


def split_by_scenario(flows: list, test_scenarios: list,
                       val_scenarios: list = None) -> tuple:
    """
    Capture-level split: hold out entire scenarios.

    Returns (train_flows, val_flows, test_flows)
    """
    test_set = set(test_scenarios)
    val_set = set(val_scenarios) if val_scenarios else set()

    train, val, test = [], [], []
    for f in flows:
        sid = f['scenario_id']
        if sid in test_set:
            test.append(f)
        elif sid in val_set:
            val.append(f)
        else:
            train.append(f)

    return train, val, test


def split_random(flows: list, test_frac: float = 0.15,
                  val_frac: float = 0.15, seed: int = 42) -> tuple:
    """Random flow-level split (labelled INFLATED)."""
    rng = np.random.RandomState(seed)
    indices = rng.permutation(len(flows))

    n_test = int(len(flows) * test_frac)
    n_val = int(len(flows) * val_frac)

    test_idx = indices[:n_test]
    val_idx = indices[n_test:n_test + n_val]
    train_idx = indices[n_test + n_val:]

    train = [flows[i] for i in train_idx]
    val = [flows[i] for i in val_idx]
    test = [flows[i] for i in test_idx]

    return train, val, test


def prepare_data(flows: list, variant: str = 'A',
                  include_tcp_flags: bool = True,
                  meta: dict = None):
    """
    Prepare input arrays and labels from flow dicts.

    variant: 'A', 'B', or 'AB'
    """
    from preprocessing import (preprocess_variant_a, build_beacon_series,
                                preprocess_variant_b, compute_beacon_scores)

    # Filter out unknown labels
    labelled = [f for f in flows if f['label'] >= 0]

    if variant == 'A':
        X = preprocess_variant_a(labelled, meta, include_tcp_flags)
        y = np.array([f['label'] for f in labelled], dtype=np.float32)
        return X, y

    elif variant == 'B':
        groups = build_beacon_series(labelled, meta)
        X, keys, labels = preprocess_variant_b(groups, meta)
        y = np.array(labels, dtype=np.float32)
        # Filter out unknown
        mask = y >= 0
        return X[mask], y[mask]

    elif variant == 'AB':
        # Branch A
        X_a = preprocess_variant_a(labelled, meta, include_tcp_flags)
        # Branch B
        groups = build_beacon_series(labelled, meta)
        X_b, keys, labels_b = preprocess_variant_b(groups, meta)
        y_b = np.array(labels_b, dtype=np.float32)
        mask_b = y_b >= 0
        # For AB we need matched arrays -- use Variant A only for now
        # (full AB requires index alignment which is complex)
        # Fall back to A arrays with a warning
        print("  NOTE: AB variant uses Variant A arrays (AB alignment not yet implemented)")
        X = X_a
        y = np.array([f['label'] for f in labelled], dtype=np.float32)
        return X, y
    else:
        raise ValueError(f"Unsupported variant: {variant}")


def train_single(X_train, y_train, X_val, y_val,
                  variant: str, seed: int,
                  epochs: int = 50, batch_size: int = 512,
                  model_dir: str = "model_bundle"):
    """Train a single model with given seed."""
    import tensorflow as tf
    from model import build_model_a, build_model_b, focal_loss, count_params

    set_seeds(seed)

    if variant == 'A':
        model = build_model_a(N=X_train.shape[1], C=X_train.shape[2])
    elif variant == 'B':
        model = build_model_b(K=X_train.shape[1])
    else:
        raise ValueError(f"Unsupported variant: {variant}")

    n_params = count_params(model)
    print(f"\n  Model parameters: {n_params:,}")

    # Compile with focal loss
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss=focal_loss(gamma=2.0, alpha=0.25),
        metrics=['accuracy'],
    )

    # Callbacks
    os.makedirs(model_dir, exist_ok=True)
    ckpt_path = os.path.join(model_dir, f"best_{variant}_seed{seed}.keras")

    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor='val_loss', patience=10, restore_best_weights=True,
            verbose=1
        ),
        tf.keras.callbacks.ModelCheckpoint(
            ckpt_path, monitor='val_loss', save_best_only=True, verbose=0
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6, verbose=1
        ),
    ]

    # Class weights for focal loss augmentation
    n_pos = int(y_train.sum())
    n_neg = len(y_train) - n_pos
    print(f"  Train: {n_pos:,} botnet, {n_neg:,} benign (ratio 1:{n_neg/max(n_pos,1):.1f})")

    t0 = time.time()
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=1,
    )

    train_time = time.time() - t0
    print(f"  Training time: {train_time:.1f}s")

    # Load best checkpoint
    model = tf.keras.models.load_model(
        ckpt_path, custom_objects={'_focal_loss': focal_loss(gamma=2.0, alpha=0.25)}
    )

    return model, history, n_params


def evaluate(model, X_test, y_test, scenario_flows=None):
    """
    Evaluate model and return metrics dict.

    Returns dict with precision, recall, f1, roc_auc, pr_auc, confusion matrix.
    """
    from sklearn.metrics import (precision_recall_fscore_support,
                                  roc_auc_score, average_precision_score,
                                  confusion_matrix)

    y_pred_proba = model.predict(X_test, batch_size=1024, verbose=0).flatten()
    y_pred = (y_pred_proba >= 0.5).astype(int)

    n_pos = int(y_test.sum())
    n_neg = len(y_test) - n_pos

    # Overall metrics
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average='binary', zero_division=0
    )

    try:
        roc_auc = roc_auc_score(y_test, y_pred_proba)
    except ValueError:
        roc_auc = float('nan')

    try:
        pr_auc = average_precision_score(y_test, y_pred_proba)
    except ValueError:
        pr_auc = float('nan')

    cm = confusion_matrix(y_test, y_pred)

    results = {
        "n_positive": n_pos,
        "n_negative": n_neg,
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "confusion_matrix": cm.tolist(),
        "statistically_weak": n_pos < 50,
    }

    if results['f1'] >= 0.999 or results['roc_auc'] >= 0.999:
        results['leakage_warning'] = (
            "INVESTIGATION NEEDED: Metric >= 0.999. Check for duplicate flows, "
            "same-capture contamination, or label leakage via ports/IPs."
        )

    return results


def main():
    parser = argparse.ArgumentParser(description="Stage 3: Model training")
    parser.add_argument("--flows", default="extracted_flows/all_flows.pkl",
                        help="Path to extracted flows pickle")
    from splits import TRAIN_SCENARIOS, VAL_SCENARIOS, CAL_SCENARIOS, TEST_SCENARIOS
    parser.add_argument("--variant", default="A", choices=["A", "B", "AB"],
                        help="Model variant")
    parser.add_argument("--n-seeds", type=int, default=3,
                        help="Number of training seeds")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: 5 epochs, 1 seed")
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--output-dir", default="model_bundle",
                        help="Output directory for models")
    parser.add_argument("--test-scenarios", type=int, nargs="+",
                        default=TEST_SCENARIOS,
                        help="Scenarios held out for testing")
    parser.add_argument("--val-scenarios", type=int, nargs="+",
                        default=VAL_SCENARIOS,
                        help="Scenarios held out for validation")
    parser.add_argument("--cal-scenarios", type=int, nargs="+",
                        default=CAL_SCENARIOS,
                        help="Scenarios held out for calibration")
    parser.add_argument("--include-tcp-flags", action="store_true", default=True)
    args = parser.parse_args()

    if args.quick:
        args.epochs = 5
        args.n_seeds = 1
        print("[QUICK MODE] 5 epochs, 1 seed")

    print("="*60)
    print("UniGuard 1D CNN - Stage 3: Training")
    print("="*60)

    # Load flows
    flows_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.flows)
    print(f"\nLoading flows from {flows_path}")
    flows = load_flows(flows_path)
    print(f"Loaded {len(flows):,} flows")

    # Label distribution
    labels = Counter(f['label'] for f in flows)
    print(f"Labels: {dict(labels)}")

    from preprocessing import DEFAULT_META
    meta = DEFAULT_META.copy()

    # --- Capture-level split (using splits.py) ---
    from splits import split_flows, validate_splits
    validate_splits()

    # Exclude cal scenarios from training
    cal_set = set(args.cal_scenarios)
    test_set = set(args.test_scenarios)
    val_set = set(args.val_scenarios)

    # Verify disjointness
    all_held = cal_set | test_set | val_set
    assert len(all_held) == len(cal_set) + len(test_set) + len(val_set), \
        "train/val/cal/test are NOT disjoint!"

    train_flows = [f for f in flows if f['scenario_id'] not in all_held]
    val_flows = [f for f in flows if f['scenario_id'] in val_set]
    cal_flows = [f for f in flows if f['scenario_id'] in cal_set]
    test_flows = [f for f in flows if f['scenario_id'] in test_set]

    print(f"\nCapture-level split:")
    print(f"  Train scenarios: {sorted(set(f['scenario_id'] for f in train_flows))}")
    print(f"  Val scenarios:   {args.val_scenarios}")
    print(f"  Cal scenarios:   {args.cal_scenarios}")
    print(f"  Test scenarios:  {args.test_scenarios}")
    print(f"  Train: {len(train_flows):,} flows")
    print(f"  Val:   {len(val_flows):,} flows")
    print(f"  Cal:   {len(cal_flows):,} flows (not used in training)")
    print(f"  Test:  {len(test_flows):,} flows")

    # Prepare data
    print(f"\nPreparing {args.variant} input arrays...")
    X_train, y_train = prepare_data(train_flows, args.variant,
                                     args.include_tcp_flags, meta)
    X_val, y_val = prepare_data(val_flows, args.variant,
                                 args.include_tcp_flags, meta)
    X_test, y_test = prepare_data(test_flows, args.variant,
                                   args.include_tcp_flags, meta)

    print(f"  X_train: {X_train.shape}, y_train: {y_train.shape}")
    print(f"  X_val:   {X_val.shape}, y_val:   {y_val.shape}")
    print(f"  X_test:  {X_test.shape}, y_test:  {y_test.shape}")

    # --- Train with multiple seeds ---
    seeds = [42, 123, 456][:args.n_seeds]
    all_results = []
    best_model = None
    best_val_loss = float('inf')

    for i, seed in enumerate(seeds):
        print(f"\n{'='*40}")
        print(f"Training seed {i+1}/{len(seeds)}: {seed}")
        print(f"{'='*40}")

        model, history, n_params = train_single(
            X_train, y_train, X_val, y_val,
            variant=args.variant, seed=seed,
            epochs=args.epochs, batch_size=args.batch_size,
            model_dir=args.output_dir,
        )

        # Evaluate
        results = evaluate(model, X_test, y_test)
        results['seed'] = seed
        results['n_params'] = n_params
        all_results.append(results)

        print(f"\n  Results (seed={seed}):")
        print(f"    Precision: {results['precision']:.4f}")
        print(f"    Recall:    {results['recall']:.4f}")
        print(f"    F1:        {results['f1']:.4f}")
        print(f"    ROC-AUC:   {results['roc_auc']:.4f}")
        print(f"    PR-AUC:    {results['pr_auc']:.4f}")
        if results.get('leakage_warning', ''):
            print(f"    ⚠️  {results['leakage_warning']}")

        val_loss = min(history.history['val_loss'])
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_model = model

    # --- Aggregate results ---
    print(f"\n{'='*60}")
    print(f"AGGREGATE RESULTS ({len(seeds)} seeds)")
    print(f"{'='*60}")

    for metric in ['precision', 'recall', 'f1', 'roc_auc', 'pr_auc']:
        values = [r[metric] for r in all_results]
        mean_val = np.mean(values)
        std_val = np.std(values)
        print(f"  {metric:>12}: {mean_val:.4f} ± {std_val:.4f}")

    # Save best model
    os.makedirs(args.output_dir, exist_ok=True)
    model_path = os.path.join(args.output_dir, "model.keras")
    best_model.save(model_path)
    print(f"\nBest model saved to {model_path}")

    # Save results
    results_path = os.path.join(args.output_dir, "training_results.json")
    with open(results_path, 'w') as f:
        json.dump({
            'variant': args.variant,
            'seeds': seeds,
            'test_scenarios': args.test_scenarios,
            'val_scenarios': args.val_scenarios,
            'per_seed': all_results,
            'aggregate': {
                metric: {
                    'mean': float(np.mean([r[metric] for r in all_results])),
                    'std': float(np.std([r[metric] for r in all_results])),
                }
                for metric in ['precision', 'recall', 'f1', 'roc_auc', 'pr_auc']
            }
        }, f, indent=2)

    # Save meta.json
    meta['input_shape_A'] = list(X_train.shape[1:]) if args.variant in ('A', 'AB') else None
    meta['input_shape_B'] = list(X_train.shape[1:]) if args.variant == 'B' else None
    meta['n_params'] = n_params
    meta['seeds'] = seeds
    meta['train_scenarios'] = sorted(set(f['scenario_id'] for f in train_flows))
    meta['val_scenarios'] = args.val_scenarios
    meta['cal_scenarios'] = args.cal_scenarios
    meta['test_scenarios'] = args.test_scenarios
    meta['checkpoint'] = 'best'
    meta['training_data_scenarios'] = sorted(set(f['scenario_id'] for f in train_flows))
    meta['missing_scenarios'] = [9, 10, 11]

    # Library versions
    import tensorflow as tf
    import sklearn
    meta['library_versions'] = {
        'tensorflow': tf.__version__,
        'numpy': np.__version__,
        'scikit-learn': sklearn.__version__,
    }
    try:
        import onnxruntime
        meta['library_versions']['onnxruntime'] = onnxruntime.__version__
    except ImportError:
        pass

    from preprocessing import save_meta
    meta_path = os.path.join(args.output_dir, "meta.json")
    save_meta(meta, meta_path)
    print(f"Meta saved to {meta_path}")

    print("\nStage 3 complete!")
    return best_model, all_results


# No longer need SCENARIOS import at module level for training_data_scenarios

if __name__ == "__main__":
    main()
