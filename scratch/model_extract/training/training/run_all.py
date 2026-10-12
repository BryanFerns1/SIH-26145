"""
run_all.py - Run the full UniGuard pipeline in order.

Usage:
  python run_all.py                  # Full pipeline (50 epochs, 3 seeds)
  python run_all.py --quick          # Quick smoke test (5 epochs, 1 seed)
  python run_all.py --skip-stage1    # Skip extraction (use existing flows)
"""

import os
import sys
import subprocess
import argparse
import time


def run(cmd, desc):
    """Run a command and print status."""
    print(f"\n{'='*60}")
    print(f"  {desc}")
    print(f"{'='*60}")
    print(f"  CMD: {cmd}\n")

    t0 = time.time()
    result = subprocess.run(cmd, shell=True, cwd=os.path.dirname(os.path.abspath(__file__)))
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"\n  FAILED (exit code {result.returncode}) after {elapsed:.1f}s")
        return False
    else:
        print(f"\n  DONE in {elapsed:.1f}s")
        return True


def main():
    parser = argparse.ArgumentParser(description="Run full UniGuard pipeline")
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: 5 epochs, 1 seed")
    parser.add_argument("--skip-stage1", action="store_true",
                        help="Skip PCAP extraction (use existing flows)")
    parser.add_argument("--skip-stage7", action="store_true",
                        help="Skip shortcut analysis (saves time)")
    args = parser.parse_args()

    quick = "--quick" if args.quick else ""
    epochs = "5" if args.quick else "50"
    n_seeds = "1" if args.quick else "3"

    steps = []

    # Stage 1: Extract flows
    if not args.skip_stage1:
        steps.append(("Stage 1: Extract flows from PCAPs",
                       "python stage1_extract.py"))

    # Stage 3: Train model
    steps.append(("Stage 3: Train Variant A model",
                   f"python stage3_train.py --epochs {epochs} --n-seeds {n_seeds} {quick}"))

    # Stage 5: Calibration
    steps.append(("Stage 5: Calibration + thresholds",
                   "python stage5_calibration.py"))

    # Stage 6: Export + benchmark
    steps.append(("Stage 6: ONNX export + benchmark",
                   "python stage6_export.py"))

    # Stage 7: Shortcut analysis
    if not args.skip_stage7:
        steps.append(("Stage 7: Shortcut analysis",
                       f"python stage7_shortcut_analysis.py --epochs {epochs} --n-seeds {n_seeds} {quick}"))

    # Run tests
    steps.append(("Tests: pytest",
                   "python -m pytest test_uniguard.py -v"))

    print("=" * 60)
    print("UniGuard Full Pipeline")
    print("=" * 60)
    print(f"Mode: {'QUICK' if args.quick else 'FULL'}")
    print(f"Steps: {len(steps)}")

    t_start = time.time()
    for i, (desc, cmd) in enumerate(steps):
        print(f"\n[{i+1}/{len(steps)}]")
        ok = run(cmd, desc)
        if not ok:
            print(f"\nPipeline STOPPED at step {i+1}: {desc}")
            sys.exit(1)

    total = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"Pipeline complete in {total:.0f}s ({total/60:.1f} min)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
