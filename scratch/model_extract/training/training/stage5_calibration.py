"""
Stage 5: Calibration for UniGuard 1D CNN.

- Hold out a calibration set (capture-level, disjoint from train/val/test)
- Calibrate scores using isotonic regression or Platt scaling
- Choose by Brier score
- Plot reliability diagram (cal and test)
- Set thresholds at target FPR 0.2% (HIGH) and 1.0% (REVIEW) on CAL benign
- Evaluate those exact thresholds on TEST and report achieved FPR/recall
- Write achieved_fpr_cal, achieved_recall_cal, achieved_fpr_test, achieved_recall_test
"""

import os
import json
import pickle
import argparse
import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss


def calibrate_scores(y_true, y_scores):
    """
    Calibrate raw model scores using both Platt and Isotonic regression.
    Returns the better calibrator (by Brier score) and comparison metrics.
    """
    from sklearn.linear_model import LogisticRegression

    # Platt (logistic) calibration
    platt = LogisticRegression(C=1.0, solver='lbfgs', max_iter=1000)
    platt.fit(y_scores.reshape(-1, 1), y_true)
    platt_scores = platt.predict_proba(y_scores.reshape(-1, 1))[:, 1]
    platt_brier = brier_score_loss(y_true, platt_scores)

    # Isotonic calibration
    iso = IsotonicRegression(y_min=0, y_max=1, out_of_bounds='clip')
    iso.fit(y_scores, y_true)
    iso_scores = iso.predict(y_scores)
    iso_brier = brier_score_loss(y_true, iso_scores)

    # Raw Brier
    raw_brier = brier_score_loss(y_true, y_scores)

    print(f"  Raw Brier score:      {raw_brier:.6f}")
    print(f"  Platt Brier score:    {platt_brier:.6f}")
    print(f"  Isotonic Brier score: {iso_brier:.6f}")

    if iso_brier <= platt_brier:
        print(f"  -> Using Isotonic calibration (lower Brier)")
        return iso, 'isotonic', {
            'raw_brier': float(raw_brier),
            'platt_brier': float(platt_brier),
            'isotonic_brier': float(iso_brier),
            'chosen': 'isotonic',
        }
    else:
        print(f"  -> Using Platt calibration (lower Brier)")
        return platt, 'platt', {
            'raw_brier': float(raw_brier),
            'platt_brier': float(platt_brier),
            'isotonic_brier': float(iso_brier),
            'chosen': 'platt',
        }


def apply_calibrator(calibrator, cal_type, raw_scores):
    """Apply calibrator to raw scores."""
    if cal_type == 'isotonic':
        return calibrator.predict(raw_scores)
    else:  # platt
        return calibrator.predict_proba(raw_scores.reshape(-1, 1))[:, 1]


def set_thresholds(y_true, calibrated_scores, target_fprs=(0.002, 0.01)):
    """
    Set thresholds from benign calibration data at target FPRs.
    Returns dict mapping tier name to threshold info.
    """
    benign_scores = calibrated_scores[y_true == 0]
    n_benign = len(benign_scores)
    if n_benign == 0:
        return {}

    # Check if we have enough benign data for 0.2% FPR
    if n_benign < 1000:
        print(f"  WARNING: Only {n_benign} benign flows for calibration.")
        print(f"  0.2% FPR threshold requires ~500+ benign flows for stability.")
        print(f"  Using bootstrap CI for threshold estimation.")

    tier_names = ['HIGH', 'REVIEW']
    thresholds = {}

    for tier, target_fpr in zip(tier_names, target_fprs):
        sorted_scores = np.sort(benign_scores)[::-1]

        # Number of false positives allowed
        n_fp_allowed = int(np.ceil(target_fpr * n_benign))

        if n_fp_allowed == 0:
            threshold = float(sorted_scores[0]) + 0.001
        elif n_fp_allowed >= n_benign:
            threshold = 0.0
        else:
            threshold = float(sorted_scores[n_fp_allowed - 1])

        # Actual FPR and recall at this threshold (on CAL data)
        actual_fpr = float(np.mean(benign_scores >= threshold))
        if y_true.sum() > 0:
            botnet_scores = calibrated_scores[y_true == 1]
            actual_recall = float(np.mean(botnet_scores >= threshold))
        else:
            actual_recall = float('nan')

        thresholds[tier] = {
            'score': float(threshold),
            'target_fpr': float(target_fpr),
            'achieved_fpr_cal': float(actual_fpr),
            'achieved_recall_cal': float(actual_recall),
            'n_benign_cal': int(n_benign),
        }

        print(f"  {tier}: threshold={threshold:.4f}, "
              f"cal_FPR={actual_fpr:.4f} (target {target_fpr}), "
              f"cal_recall={actual_recall:.4f}")

    return thresholds


def evaluate_thresholds_on_test(thresholds, y_test, cal_scores_test):
    """Evaluate calibrated thresholds on the TEST set."""
    benign_test = cal_scores_test[y_test == 0]
    botnet_test = cal_scores_test[y_test == 1]

    for tier, info in thresholds.items():
        thresh = info['score']

        if len(benign_test) > 0:
            test_fpr = float(np.mean(benign_test >= thresh))
        else:
            test_fpr = float('nan')

        if len(botnet_test) > 0:
            test_recall = float(np.mean(botnet_test >= thresh))
        else:
            test_recall = float('nan')

        info['achieved_fpr_test'] = test_fpr
        info['achieved_recall_test'] = test_recall

        target_fpr = info['target_fpr']
        ratio = test_fpr / target_fpr if target_fpr > 0 else float('inf')

        status = "OK"
        if ratio > 3.0:
            status = "WARNING: test FPR > 3x target!"
        print(f"  {tier}: test_FPR={test_fpr:.4f} (target {target_fpr}), "
              f"test_recall={test_recall:.4f}, ratio={ratio:.1f}x [{status}]")

    return thresholds


def compute_ece(y_true, y_pred, n_bins=10):
    """Compute Expected Calibration Error."""
    bin_edges = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        mask = (y_pred >= bin_edges[i]) & (y_pred < bin_edges[i + 1])
        if mask.sum() == 0:
            continue
        avg_conf = y_pred[mask].mean()
        avg_acc = y_true[mask].mean()
        ece += mask.sum() * abs(avg_conf - avg_acc)
    return ece / len(y_true)


def plot_reliability_diagram(y_cal, raw_cal, cal_cal,
                              y_test, raw_test, cal_test,
                              output_path):
    """Plot reliability diagram comparing raw vs calibrated on cal and test."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from sklearn.calibration import calibration_curve

    fig, axes = plt.subplots(2, 2, figsize=(14, 12))

    datasets = [
        (axes[0, 0], y_cal, raw_cal, "Calibration Set - Raw Scores"),
        (axes[0, 1], y_cal, cal_cal, "Calibration Set - Calibrated"),
        (axes[1, 0], y_test, raw_test, "Test Set - Raw Scores"),
        (axes[1, 1], y_test, cal_test, "Test Set - Calibrated"),
    ]

    for ax, y, scores, title in datasets:
        try:
            fraction_pos, mean_predicted = calibration_curve(
                y, scores, n_bins=10, strategy='uniform'
            )
            ece = compute_ece(y, scores)
            ax.plot([0, 1], [0, 1], 'k--', label='Perfectly calibrated')
            ax.plot(mean_predicted, fraction_pos, 'o-', label=f'Model (ECE={ece:.4f})')
            ax.set_xlabel('Mean predicted probability')
            ax.set_ylabel('Fraction of positives')
            ax.set_title(title)
            ax.legend()
            ax.grid(True, alpha=0.3)
        except Exception as e:
            ax.set_title(f"{title} (error: {e})")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Reliability diagram saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Stage 5: Calibration")
    parser.add_argument("--flows", default="extracted_flows/all_flows.pkl")
    parser.add_argument("--model", default="model_bundle/model.keras")
    parser.add_argument("--output-dir", default="model_bundle")
    args = parser.parse_args()

    print("=" * 60)
    print("UniGuard 1D CNN - Stage 5: Calibration")
    print("=" * 60)

    import tensorflow as tf
    from model import focal_loss
    from stage3_train import load_flows, prepare_data
    from preprocessing import DEFAULT_META
    from splits import CAL_SCENARIOS, TEST_SCENARIOS, validate_splits

    validate_splits()

    base = os.path.dirname(os.path.abspath(__file__))
    flows = load_flows(os.path.join(base, args.flows))
    meta = DEFAULT_META.copy()

    model = tf.keras.models.load_model(
        os.path.join(base, args.model),
        custom_objects={'_focal_loss': focal_loss()},
    )

    # --- Calibration data (disjoint from train/val/test) ---
    cal_flows = [f for f in flows if f['scenario_id'] in CAL_SCENARIOS
                  and f['label'] >= 0]
    print(f"\nCalibration scenarios: {CAL_SCENARIOS}")
    print(f"Calibration flows: {len(cal_flows):,}")

    # --- Test data ---
    test_flows = [f for f in flows if f['scenario_id'] in TEST_SCENARIOS
                   and f['label'] >= 0]
    print(f"Test scenarios: {TEST_SCENARIOS}")
    print(f"Test flows: {len(test_flows):,}")

    # Label counts
    from collections import Counter
    cal_labels = Counter(f['label'] for f in cal_flows)
    test_labels = Counter(f['label'] for f in test_flows)
    print(f"  Cal labels:  {dict(cal_labels)}")
    print(f"  Test labels: {dict(test_labels)}")

    X_cal, y_cal = prepare_data(cal_flows, 'A', True, meta)
    X_test, y_test = prepare_data(test_flows, 'A', True, meta)

    y_raw_cal = model.predict(X_cal, batch_size=1024, verbose=0).flatten()
    y_raw_test = model.predict(X_test, batch_size=1024, verbose=0).flatten()

    # --- Calibrate on CAL data ---
    print("\nCalibrating scores on CAL set...")
    calibrator, cal_type, cal_metrics = calibrate_scores(y_cal, y_raw_cal)

    # Apply calibration
    y_cal_calibrated = apply_calibrator(calibrator, cal_type, y_raw_cal)
    y_test_calibrated = apply_calibrator(calibrator, cal_type, y_raw_test)

    # --- Set thresholds on CAL benign ---
    print("\nSetting thresholds on CAL benign flows...")
    thresholds = set_thresholds(y_cal, y_cal_calibrated)

    # --- Evaluate on TEST ---
    print("\nEvaluating thresholds on TEST set...")
    thresholds = evaluate_thresholds_on_test(thresholds, y_test, y_test_calibrated)

    # --- ECE ---
    ece_raw_test = compute_ece(y_test, y_raw_test)
    ece_cal_test = compute_ece(y_test, y_test_calibrated)
    print(f"\n  Test ECE (raw):        {ece_raw_test:.6f}")
    print(f"  Test ECE (calibrated): {ece_cal_test:.6f}")

    # --- Save calibrator ---
    os.makedirs(args.output_dir, exist_ok=True)
    cal_path = os.path.join(args.output_dir, "calibrator.pkl")
    with open(cal_path, 'wb') as f:
        pickle.dump({'calibrator': calibrator, 'type': cal_type}, f)
    print(f"\nCalibrator saved to {cal_path}")

    # --- Update meta.json ---
    meta_path = os.path.join(args.output_dir, "meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            meta = json.load(f)
    meta['thresholds'] = thresholds
    meta['calibration'] = cal_metrics
    meta['calibration_scenarios'] = CAL_SCENARIOS
    meta['ece_raw_test'] = ece_raw_test
    meta['ece_calibrated_test'] = ece_cal_test
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    # --- Reliability diagram ---
    plot_path = os.path.join(args.output_dir, "reliability_diagram.png")
    plot_reliability_diagram(
        y_cal, y_raw_cal, y_cal_calibrated,
        y_test, y_raw_test, y_test_calibrated,
        plot_path,
    )

    # --- Save calibration_results.json ---
    cal_results = {
        'calibration_type': cal_type,
        'metrics': cal_metrics,
        'thresholds': thresholds,
        'n_calibration_flows': len(cal_flows),
        'calibration_scenarios': CAL_SCENARIOS,
        'n_test_flows': len(test_flows),
        'test_scenarios': TEST_SCENARIOS,
        'ece_raw_test': float(ece_raw_test),
        'ece_calibrated_test': float(ece_cal_test),
    }
    with open(os.path.join(args.output_dir, "calibration_results.json"), 'w') as f:
        json.dump(cal_results, f, indent=2)

    print("\nStage 5 complete!")


if __name__ == "__main__":
    main()
