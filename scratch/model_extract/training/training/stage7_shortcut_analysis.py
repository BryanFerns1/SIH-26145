"""
Stage 7: Direction-shortcut analysis for UniGuard 1D CNN.

Baselines:
  (i)   Rule: first packet is SYN without ACK
  (ii)  Logistic regression on [n_pkts, total_bytes, first_pkt_size, is_syn_first]
  (iii) CNN (Variant A)

Subset analysis:
  CNN on SYN-first only, non-SYN-first only, TCP only, UDP only

Ablations (train 3 seeds each):
  full 7ch | no TCP flags (3ch) | no size | no IAT | first-8-packets only
"""

import os
import sys
import json
import time
import pickle
import argparse
from collections import Counter

import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

from sklearn.metrics import (roc_auc_score, average_precision_score,
                              precision_recall_fscore_support)
from sklearn.linear_model import LogisticRegression

from ctu13_ground_truth import SCENARIOS
from preprocessing import DEFAULT_META, preprocess_variant_a
from stage3_train import load_flows, set_seeds
from splits import (TRAIN_SCENARIOS, VAL_SCENARIOS, CAL_SCENARIOS,
                    TEST_SCENARIOS, validate_splits)


def compute_metrics(y_true, y_pred_proba, threshold=0.5):
    """Compute standard metrics."""
    y_pred = (y_pred_proba >= threshold).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average='binary', zero_division=0
    )
    try:
        auc = roc_auc_score(y_true, y_pred_proba)
    except ValueError:
        auc = float('nan')
    try:
        pr_auc = average_precision_score(y_true, y_pred_proba)
    except ValueError:
        pr_auc = float('nan')

    n_benign = int((y_true == 0).sum())
    if n_benign > 0:
        fpr = float(np.mean(y_pred_proba[y_true == 0] >= threshold))
    else:
        fpr = float('nan')

    return {
        'auc': float(auc),
        'pr_auc': float(pr_auc),
        'precision': float(prec),
        'recall': float(rec),
        'f1': float(f1),
        'fpr_at_05': float(fpr),
    }


def extract_simple_features(flows):
    """Extract simple features for logistic regression baseline."""
    X = np.zeros((len(flows), 4), dtype=np.float32)
    y = np.zeros(len(flows), dtype=np.float32)

    for i, f in enumerate(flows):
        sizes = f.get('pkt_sizes', [])
        flags = f.get('pkt_tcp_flags', [])

        X[i, 0] = len(sizes)                    # n_pkts
        X[i, 1] = sum(sizes) if sizes else 0     # total_bytes
        X[i, 2] = sizes[0] if sizes else 0       # first_pkt_size
        # is_syn_first: first packet has SYN (0x02) but NOT ACK (0x10)
        if flags:
            X[i, 3] = 1.0 if (flags[0] & 0x02) and not (flags[0] & 0x10) else 0.0
        y[i] = f.get('label', 0)

    return X, y


def syn_rule_scores(flows):
    """Rule baseline: score = 1.0 if first packet is SYN-only."""
    scores = np.zeros(len(flows), dtype=np.float32)
    for i, f in enumerate(flows):
        flags = f.get('pkt_tcp_flags', [])
        if flags and (flags[0] & 0x02) and not (flags[0] & 0x10):
            scores[i] = 1.0
    return scores


def run_baselines(train_flows, test_flows, label='test'):
    """Run all three baselines on given splits."""
    print(f"\n  --- Baselines on {label} ---")
    results = {}

    # Labels
    y_test = np.array([f['label'] for f in test_flows], dtype=np.float32)

    # (i) SYN rule
    syn_scores = syn_rule_scores(test_flows)
    results['syn_rule'] = compute_metrics(y_test, syn_scores)
    print(f"    SYN rule:    AUC={results['syn_rule']['auc']:.4f}, "
          f"PR-AUC={results['syn_rule']['pr_auc']:.4f}, "
          f"FPR={results['syn_rule']['fpr_at_05']:.4f}")

    # (ii) Logistic regression
    X_train_lr, y_train_lr = extract_simple_features(train_flows)
    X_test_lr, _ = extract_simple_features(test_flows)

    lr = LogisticRegression(max_iter=1000, C=1.0)
    lr.fit(X_train_lr, y_train_lr)
    lr_scores = lr.predict_proba(X_test_lr)[:, 1]
    results['logistic_regression'] = compute_metrics(y_test, lr_scores)
    print(f"    Logistic:    AUC={results['logistic_regression']['auc']:.4f}, "
          f"PR-AUC={results['logistic_regression']['pr_auc']:.4f}, "
          f"FPR={results['logistic_regression']['fpr_at_05']:.4f}")

    # (iii) CNN -- use existing model
    meta = DEFAULT_META.copy()
    X_test_cnn = preprocess_variant_a(test_flows, meta, True)

    try:
        import tensorflow as tf
        from model import focal_loss
        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "model_bundle", "model.keras")
        model = tf.keras.models.load_model(model_path,
                                            custom_objects={'_focal_loss': focal_loss()})
        cnn_scores = model.predict(X_test_cnn, batch_size=1024, verbose=0).flatten()
        results['cnn'] = compute_metrics(y_test, cnn_scores)
        print(f"    CNN:         AUC={results['cnn']['auc']:.4f}, "
              f"PR-AUC={results['cnn']['pr_auc']:.4f}, "
              f"FPR={results['cnn']['fpr_at_05']:.4f}")
    except Exception as e:
        print(f"    CNN: FAILED ({e})")
        results['cnn'] = {'error': str(e)}

    return results


def run_subset_analysis(test_flows):
    """CNN metrics on subsets: SYN-first, non-SYN-first, TCP, UDP."""
    print("\n  --- Subset Analysis ---")
    results = {}

    meta = DEFAULT_META.copy()

    # Load model
    import tensorflow as tf
    from model import focal_loss
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "model_bundle", "model.keras")
    model = tf.keras.models.load_model(model_path,
                                        custom_objects={'_focal_loss': focal_loss()})

    subsets = {
        'syn_first': [f for f in test_flows
                       if f.get('pkt_tcp_flags', []) and
                       (f['pkt_tcp_flags'][0] & 0x02) and
                       not (f['pkt_tcp_flags'][0] & 0x10)],
        'non_syn_first': [f for f in test_flows
                           if not (f.get('pkt_tcp_flags', []) and
                           (f['pkt_tcp_flags'][0] & 0x02) and
                           not (f['pkt_tcp_flags'][0] & 0x10))],
        'tcp_only': [f for f in test_flows if f.get('proto', 0) == 6],
        'udp_only': [f for f in test_flows if f.get('proto', 0) == 17],
    }

    for name, subset in subsets.items():
        if len(subset) < 10:
            print(f"    {name}: too few flows ({len(subset)}), skipped")
            results[name] = {'n_flows': len(subset), 'skipped': True}
            continue

        X = preprocess_variant_a(subset, meta, True)
        y = np.array([f['label'] for f in subset], dtype=np.float32)
        scores = model.predict(X, batch_size=1024, verbose=0).flatten()
        m = compute_metrics(y, scores)
        m['n_flows'] = len(subset)
        results[name] = m
        print(f"    {name} (n={len(subset)}): AUC={m['auc']:.4f}, "
              f"recall={m['recall']:.4f}, FPR={m['fpr_at_05']:.4f}")

    return results


def run_ablations(train_flows, val_flows, test_flows, seeds, epochs, batch_size):
    """Train ablation variants and compare."""
    print("\n  --- Ablations ---")
    from model import build_model_a, focal_loss, count_params
    import tensorflow as tf

    meta = DEFAULT_META.copy()
    results = {}

    ablations = {
        'full_7ch': {'include_tcp_flags': True, 'N': 32},
        'no_flags_3ch': {'include_tcp_flags': False, 'N': 32},
        'first_8_only': {'include_tcp_flags': True, 'N': 8},
    }

    y_train = np.array([f['label'] for f in train_flows if f['label'] >= 0], dtype=np.float32)
    y_val = np.array([f['label'] for f in val_flows if f['label'] >= 0], dtype=np.float32)
    y_test = np.array([f['label'] for f in test_flows if f['label'] >= 0], dtype=np.float32)

    for ablation_name, config in ablations.items():
        print(f"\n    Ablation: {ablation_name}")
        include_flags = config['include_tcp_flags']
        N = config['N']
        C = 7 if include_flags else 3

        # Preprocess with modified meta
        abl_meta = meta.copy()
        abl_meta['N'] = N

        train_labelled = [f for f in train_flows if f['label'] >= 0]
        val_labelled = [f for f in val_flows if f['label'] >= 0]
        test_labelled = [f for f in test_flows if f['label'] >= 0]

        X_train = preprocess_variant_a(train_labelled, abl_meta, include_flags)
        X_val = preprocess_variant_a(val_labelled, abl_meta, include_flags)
        X_test = preprocess_variant_a(test_labelled, abl_meta, include_flags)

        seed_results = []
        for seed in seeds:
            set_seeds(seed)
            model = build_model_a(N=N, C=C)
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
                loss=focal_loss(gamma=2.0, alpha=0.25),
                metrics=['accuracy'],
            )
            model.fit(
                X_train, y_train,
                validation_data=(X_val, y_val),
                epochs=epochs,
                batch_size=batch_size,
                callbacks=[
                    tf.keras.callbacks.EarlyStopping(
                        monitor='val_loss', patience=10, restore_best_weights=True, verbose=0
                    ),
                ],
                verbose=0,
            )
            scores = model.predict(X_test, batch_size=1024, verbose=0).flatten()
            m = compute_metrics(y_test, scores)
            seed_results.append(m)
            print(f"      seed={seed}: AUC={m['auc']:.4f}, F1={m['f1']:.4f}")

        # Aggregate
        agg = {}
        for metric in ['auc', 'pr_auc', 'precision', 'recall', 'f1', 'fpr_at_05']:
            vals = [r[metric] for r in seed_results if not np.isnan(r.get(metric, float('nan')))]
            agg[metric] = {
                'mean': float(np.mean(vals)) if vals else float('nan'),
                'std': float(np.std(vals)) if vals else float('nan'),
            }

        results[ablation_name] = {
            'config': config,
            'per_seed': seed_results,
            'aggregate': agg,
        }
        print(f"      Mean: AUC={agg['auc']['mean']:.4f}+/-{agg['auc']['std']:.4f}, "
              f"F1={agg['f1']['mean']:.4f}+/-{agg['f1']['std']:.4f}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Stage 7: Shortcut Analysis")
    parser.add_argument("--flows", default="extracted_flows/all_flows.pkl")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--n-seeds", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: fewer epochs and seeds")
    args = parser.parse_args()

    if args.quick:
        args.epochs = 5
        args.n_seeds = 1

    print("=" * 60)
    print("UniGuard 1D CNN - Stage 7: Shortcut Analysis")
    print("=" * 60)

    validate_splits()
    base = os.path.dirname(os.path.abspath(__file__))
    flows = load_flows(os.path.join(base, args.flows))

    # Split
    all_held = set(VAL_SCENARIOS + CAL_SCENARIOS + TEST_SCENARIOS)
    train_flows = [f for f in flows if f['scenario_id'] not in all_held and f['label'] >= 0]
    val_flows = [f for f in flows if f['scenario_id'] in VAL_SCENARIOS and f['label'] >= 0]
    test_flows = [f for f in flows if f['scenario_id'] in TEST_SCENARIOS and f['label'] >= 0]

    print(f"\nTrain: {len(train_flows)}, Val: {len(val_flows)}, Test: {len(test_flows)}")

    results = {}

    # 3a: Baselines on val and test
    results['baselines_val'] = run_baselines(train_flows, val_flows, label='val')
    results['baselines_test'] = run_baselines(train_flows, test_flows, label='test')

    # 3b: Subset analysis on test
    results['subsets'] = run_subset_analysis(test_flows)

    # 3c: Ablations
    seeds = [42, 123, 456][:args.n_seeds]
    results['ablations'] = run_ablations(
        train_flows, val_flows, test_flows,
        seeds=seeds, epochs=args.epochs, batch_size=args.batch_size
    )

    # 3d: Label improvement -- binetflow files would be needed
    results['label_improvement'] = {
        'status': 'NOT_AVAILABLE',
        'note': ('Binetflow files not available locally. '
                 'Labels use infected-IP matching (host-level). '
                 'This is a known limitation: some benign flows from '
                 'the infected host are mislabelled as botnet.')
    }

    # Save results
    output_path = os.path.join(base, "model_bundle", "shortcut_analysis.json")
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nShortcut analysis saved to {output_path}")

    # Print summary table
    print("\n" + "=" * 80)
    print("SHORTCUT ANALYSIS SUMMARY")
    print("=" * 80)
    print(f"\n{'Method':<25} {'AUC':>8} {'PR-AUC':>8} {'P':>8} {'R':>8} {'FPR':>8}")
    print("-" * 70)
    for method in ['syn_rule', 'logistic_regression', 'cnn']:
        m = results['baselines_test'].get(method, {})
        if 'error' in m:
            print(f"{method:<25} {'ERROR':>8}")
        else:
            print(f"{method:<25} {m.get('auc',0):.4f}   {m.get('pr_auc',0):.4f}   "
                  f"{m.get('precision',0):.4f}   {m.get('recall',0):.4f}   "
                  f"{m.get('fpr_at_05',0):.4f}")

    print(f"\n{'Subset':<25} {'AUC':>8} {'Recall':>8} {'FPR':>8} {'N':>8}")
    print("-" * 60)
    for name in ['syn_first', 'non_syn_first', 'tcp_only', 'udp_only']:
        m = results['subsets'].get(name, {})
        if m.get('skipped'):
            print(f"{name:<25} {'SKIP':>8} {'':>8} {'':>8} {m.get('n_flows',0):>8}")
        else:
            print(f"{name:<25} {m.get('auc',0):.4f}   {m.get('recall',0):.4f}   "
                  f"{m.get('fpr_at_05',0):.4f}   {m.get('n_flows',0):>8}")

    print(f"\n{'Ablation':<25} {'AUC':>12} {'F1':>12}")
    print("-" * 50)
    for name, data in results.get('ablations', {}).items():
        agg = data.get('aggregate', {})
        auc = agg.get('auc', {})
        f1 = agg.get('f1', {})
        print(f"{name:<25} {auc.get('mean',0):.4f}+/-{auc.get('std',0):.4f}   "
              f"{f1.get('mean',0):.4f}+/-{f1.get('std',0):.4f}")

    print("\nStage 7 complete!")


if __name__ == "__main__":
    main()
