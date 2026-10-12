"""
Stage 4: Evaluation Experiments E1-E6 for UniGuard 1D CNN Beacon Detector.

E1. Random flow-level split (INFLATED - for comparison only)
E2. Leave-scenarios-out (capture-level hold out)
E3. Leave-one-botnet-family-out (generalisation)
E4. Benign-periodic false-positive test (on NTP/update/heartbeat traffic)
E5. Evasion test (feature-level perturbation)
E6. Variant A vs B vs A+B, with/without Lomb-Scargle

Each experiment reports per-class precision, recall, F1, PR-AUC, ROC-AUC,
number of positive/negative flows, per-scenario results, and confusion matrices.
"""

import os
import sys
import json
import pickle
import time
import argparse
from collections import Counter, defaultdict

import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

from ctu13_ground_truth import SCENARIOS, FAMILY_SCENARIOS
from preprocessing import (DEFAULT_META, preprocess_variant_a,
                            build_beacon_series, preprocess_variant_b,
                            compute_beacon_scores,
                            perturb_packet_sizes, perturb_timing)
from stage3_train import (set_seeds, load_flows, split_by_scenario,
                           split_random, prepare_data, train_single,
                           evaluate)


def per_scenario_eval(model, flows: list, variant: str = 'A',
                       meta: dict = None, include_tcp_flags: bool = True) -> dict:
    """Evaluate model per scenario."""
    scenario_results = {}
    scenarios = set(f['scenario_id'] for f in flows)

    for sid in sorted(scenarios):
        s_flows = [f for f in flows if f['scenario_id'] == sid]
        if not s_flows:
            continue

        X, y = prepare_data(s_flows, variant, include_tcp_flags, meta)
        if len(y) == 0:
            continue

        results = evaluate(model, X, y)
        results['scenario_id'] = sid
        results['family'] = SCENARIOS.get(sid, {}).get('family', 'unknown')
        scenario_results[sid] = results

    return scenario_results


def run_e1_random_split(flows, variant, meta, seeds, epochs, batch_size, output_dir):
    """E1: Random flow-level split (INFLATED)."""
    print("\n" + "="*60)
    print("E1: RANDOM FLOW-LEVEL SPLIT (INFLATED - FOR COMPARISON ONLY)")
    print("="*60)

    results_all = []
    for seed in seeds:
        set_seeds(seed)
        train_f, val_f, test_f = split_random(flows, seed=seed)

        X_train, y_train = prepare_data(train_f, variant, True, meta)
        X_val, y_val = prepare_data(val_f, variant, True, meta)
        X_test, y_test = prepare_data(test_f, variant, True, meta)

        model, _, _ = train_single(
            X_train, y_train, X_val, y_val,
            variant=variant, seed=seed, epochs=epochs,
            batch_size=batch_size,
            model_dir=os.path.join(output_dir, "e1"),
        )

        results = evaluate(model, X_test, y_test)
        results['seed'] = seed
        results_all.append(results)

        print(f"  Seed {seed}: F1={results['f1']:.4f}, "
              f"ROC-AUC={results['roc_auc']:.4f}")

    # Aggregate
    agg = {}
    for metric in ['precision', 'recall', 'f1', 'roc_auc', 'pr_auc']:
        vals = [r[metric] for r in results_all if not np.isnan(r[metric])]
        agg[metric] = {
            'mean': float(np.mean(vals)) if vals else float('nan'),
            'std': float(np.std(vals)) if vals else float('nan'),
        }

    return {
        'experiment': 'E1_random_split_INFLATED',
        'per_seed': results_all,
        'aggregate': agg,
        'note': 'INFLATED - random flow-level split, for comparison only',
    }


def run_e2_leave_scenarios(flows, variant, meta, seeds, epochs, batch_size,
                            output_dir):
    """E2: Leave-scenarios-out (capture-level hold out)."""
    print("\n" + "="*60)
    print("E2: LEAVE-SCENARIOS-OUT (CAPTURE-LEVEL)")
    print("="*60)

    # Multiple split configurations
    splits = [
        {'test': [9, 10], 'val': [5, 8], 'name': 'test_9_10'},
        {'test': [1, 2],  'val': [6, 7], 'name': 'test_1_2'},
        {'test': [3, 4],  'val': [5, 13], 'name': 'test_3_4'},
    ]

    all_split_results = {}
    for split_cfg in splits:
        print(f"\n  Split: test={split_cfg['test']}, val={split_cfg['val']}")

        split_results = []
        for seed in seeds[:1]:  # One seed per split for speed
            set_seeds(seed)
            train_f, val_f, test_f = split_by_scenario(
                flows, split_cfg['test'], split_cfg['val']
            )

            X_train, y_train = prepare_data(train_f, variant, True, meta)
            X_val, y_val = prepare_data(val_f, variant, True, meta)
            X_test, y_test = prepare_data(test_f, variant, True, meta)

            if len(y_test) == 0:
                print(f"    No labelled test data, skipping")
                continue

            model, _, _ = train_single(
                X_train, y_train, X_val, y_val,
                variant=variant, seed=seed, epochs=epochs,
                batch_size=batch_size,
                model_dir=os.path.join(output_dir, "e2"),
            )

            # Overall results
            results = evaluate(model, X_test, y_test)
            results['seed'] = seed
            split_results.append(results)

            # Per-scenario results
            scenario_results = per_scenario_eval(model, test_f, variant, meta)
            results['per_scenario'] = scenario_results

            print(f"    Seed {seed}: F1={results['f1']:.4f}, "
                  f"ROC-AUC={results['roc_auc']:.4f}")
            for sid, sr in sorted(scenario_results.items()):
                flag = " ⚠️ WEAK" if sr['statistically_weak'] else ""
                print(f"      Scenario {sid} ({sr['family']}): "
                      f"F1={sr['f1']:.4f}, n+={sr['n_positive']}, "
                      f"n-={sr['n_negative']}{flag}")

        all_split_results[split_cfg['name']] = split_results

    return {
        'experiment': 'E2_leave_scenarios_out',
        'splits': {k: v for k, v in all_split_results.items()},
    }


def run_e3_leave_family(flows, variant, meta, seeds, epochs, batch_size,
                         output_dir):
    """E3: Leave-one-botnet-family-out."""
    print("\n" + "="*60)
    print("E3: LEAVE-ONE-BOTNET-FAMILY-OUT")
    print("="*60)

    family_results = {}

    for family, family_scenarios in FAMILY_SCENARIOS.items():
        print(f"\n  Holding out family: {family} (scenarios {family_scenarios})")

        # Test = all scenarios of this family
        # Val = pick one other family's scenario
        remaining = [s for s in SCENARIOS.keys() if s not in family_scenarios]
        if len(remaining) < 2:
            print(f"    Not enough remaining scenarios, skipping")
            continue

        val_scenarios = remaining[:2]

        set_seeds(seeds[0])
        train_f, val_f, test_f = split_by_scenario(
            flows, family_scenarios, val_scenarios
        )

        X_train, y_train = prepare_data(train_f, variant, True, meta)
        X_val, y_val = prepare_data(val_f, variant, True, meta)
        X_test, y_test = prepare_data(test_f, variant, True, meta)

        if len(y_test) == 0 or y_test.sum() == 0:
            print(f"    No positive test data, skipping")
            family_results[family] = {'error': 'no positive test data'}
            continue

        model, _, _ = train_single(
            X_train, y_train, X_val, y_val,
            variant=variant, seed=seeds[0], epochs=epochs,
            batch_size=batch_size,
            model_dir=os.path.join(output_dir, "e3"),
        )

        results = evaluate(model, X_test, y_test)
        scenario_results = per_scenario_eval(model, test_f, variant, meta)
        results['per_scenario'] = scenario_results

        family_results[family] = results
        print(f"    {family}: F1={results['f1']:.4f}, "
              f"ROC-AUC={results['roc_auc']:.4f}, "
              f"n+={results['n_positive']}, n-={results['n_negative']}")
        if results['statistically_weak']:
            print(f"    ⚠️ STATISTICALLY WEAK (< 50 positives)")

    return {
        'experiment': 'E3_leave_family_out',
        'families': family_results,
    }


def run_e5_evasion(model, test_flows, variant, meta):
    """E5: Evasion test with feature-level perturbation."""
    print("\n" + "="*60)
    print("E5: EVASION TEST (FEATURE-LEVEL PERTURBATION)")
    print("="*60)
    print("NOTE: This is feature-level perturbation, not PCAP-level.")

    X_test, y_test = prepare_data(test_flows, variant, True, meta)
    baseline = evaluate(model, X_test, y_test)

    results = {
        'baseline': baseline,
        'perturbations': {},
    }

    # (a) Packet size padding
    pad_ranges = [(0, 50), (0, 200), (0, 500), (0, 1000)]
    for lo, hi in pad_ranges:
        name = f"pad_{lo}_{hi}"
        X_pert = perturb_packet_sizes(X_test, random_pad_range=(lo, hi), meta=meta)
        pert_results = evaluate(model, X_pert, y_test)
        recall_drop = baseline['recall'] - pert_results['recall']
        results['perturbations'][name] = {
            **pert_results,
            'recall_degradation': float(recall_drop),
        }
        print(f"  Size padding [{lo},{hi}]: recall={pert_results['recall']:.4f} "
              f"(drop={-recall_drop:+.4f})")

    # (b) Timing jitter
    jitter_magnitudes = [1e3, 1e4, 1e5, 1e6]  # microseconds
    for jitter in jitter_magnitudes:
        name = f"jitter_{jitter:.0e}"
        X_pert = perturb_timing(X_test, jitter_magnitude_us=jitter, meta=meta)
        pert_results = evaluate(model, X_pert, y_test)
        recall_drop = baseline['recall'] - pert_results['recall']
        results['perturbations'][name] = {
            **pert_results,
            'recall_degradation': float(recall_drop),
        }
        print(f"  Timing jitter {jitter:.0e}us: recall={pert_results['recall']:.4f} "
              f"(drop={-recall_drop:+.4f})")

    # (c) Both
    for (lo, hi), jitter in [((0, 200), 1e4), ((0, 500), 1e5)]:
        name = f"both_pad{lo}_{hi}_jit{jitter:.0e}"
        X_pert = perturb_packet_sizes(X_test, random_pad_range=(lo, hi), meta=meta)
        X_pert = perturb_timing(X_pert, jitter_magnitude_us=jitter, meta=meta)
        pert_results = evaluate(model, X_pert, y_test)
        recall_drop = baseline['recall'] - pert_results['recall']
        results['perturbations'][name] = {
            **pert_results,
            'recall_degradation': float(recall_drop),
        }
        print(f"  Both pad[{lo},{hi}]+jit{jitter:.0e}: "
              f"recall={pert_results['recall']:.4f} (drop={-recall_drop:+.4f})")

    return {
        'experiment': 'E5_evasion_feature_level',
        'note': 'Feature-level perturbation, NOT PCAP-level',
        'results': results,
    }


def main():
    parser = argparse.ArgumentParser(description="Stage 4: Evaluation experiments")
    parser.add_argument("--flows", default="extracted_flows/all_flows.pkl")
    parser.add_argument("--variant", default="A", choices=["A", "B"])
    parser.add_argument("--n-seeds", type=int, default=3)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--output-dir", default="experiments")
    parser.add_argument("--experiments", nargs="+",
                        default=["E1", "E2", "E3", "E5"],
                        choices=["E1", "E2", "E3", "E4", "E5", "E6"])
    args = parser.parse_args()

    print("="*60)
    print("UniGuard 1D CNN - Stage 4: Evaluation Experiments")
    print("="*60)

    flows_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.flows)
    flows = load_flows(flows_path)
    print(f"Loaded {len(flows):,} flows")

    meta = DEFAULT_META.copy()
    seeds = [42, 123, 456][:args.n_seeds]
    os.makedirs(args.output_dir, exist_ok=True)

    all_experiments = {}

    if "E1" in args.experiments:
        e1 = run_e1_random_split(flows, args.variant, meta, seeds,
                                  args.epochs, args.batch_size, args.output_dir)
        all_experiments['E1'] = e1

    if "E2" in args.experiments:
        e2 = run_e2_leave_scenarios(flows, args.variant, meta, seeds,
                                     args.epochs, args.batch_size, args.output_dir)
        all_experiments['E2'] = e2

    if "E3" in args.experiments:
        e3 = run_e3_leave_family(flows, args.variant, meta, seeds,
                                  args.epochs, args.batch_size, args.output_dir)
        all_experiments['E3'] = e3

    if "E5" in args.experiments:
        # Train a model for evasion testing
        print("\nTraining model for E5 evasion test...")
        set_seeds(42)
        train_f, val_f, test_f = split_by_scenario(flows, [8, 12], [6, 7])
        X_train, y_train = prepare_data(train_f, args.variant, True, meta)
        X_val, y_val = prepare_data(val_f, args.variant, True, meta)

        model, _, _ = train_single(
            X_train, y_train, X_val, y_val,
            variant=args.variant, seed=42, epochs=args.epochs,
            batch_size=args.batch_size,
            model_dir=os.path.join(args.output_dir, "e5"),
        )
        e5 = run_e5_evasion(model, test_f, args.variant, meta)
        all_experiments['E5'] = e5

    if "E4" in args.experiments:
        print("\n" + "="*60)
        print("E4: BENIGN PERIODIC FALSE-POSITIVE TEST")
        print("="*60)
        print("STATUS: NOT MET - requires additional benign periodic traffic PCAPs")
        print("  Needed: NTP, OS update, cloud sync, monitoring heartbeat captures")
        print("  Recommended: CIC-IDS2017 benign Monday capture")
        print("  Please provide PCAPs or specify which to download.")
        all_experiments['E4'] = {
            'experiment': 'E4_benign_periodic',
            'status': 'NOT MET',
            'reason': 'Additional benign periodic traffic PCAPs not available',
        }

    if "E6" in args.experiments:
        print("\n" + "="*60)
        print("E6: VARIANT COMPARISON (A vs B vs A+B)")
        print("="*60)
        print("Running after E1-E5 with both variants...")
        # This would train all variants and compare
        all_experiments['E6'] = {
            'experiment': 'E6_variant_comparison',
            'status': 'PENDING - run after A and B separately',
        }

    # Save all results
    results_path = os.path.join(args.output_dir, "experiment_results.json")
    with open(results_path, 'w') as f:
        json.dump(all_experiments, f, indent=2, default=str)
    print(f"\nResults saved to {results_path}")

    print("\nStage 4 complete!")


if __name__ == "__main__":
    main()
