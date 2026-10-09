"""
ONNX Export and Numerical Parity Verification
=============================================
Exports the trained and calibrated HybridNet_v4 model to ONNX.
Validates numerical parity between PyTorch and ONNX Runtime:
  assert max_abs_diff < 1e-4
"""

import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    import onnx
    import onnxruntime as ort
    _HAS_ONNX = True
except ImportError:
    _HAS_ONNX = False

from calibration import TemperatureScaler
from config import TrainingConfig
from model import HybridNet_v4


class CalibratedONNXWrapper(nn.Module):
    """
    Wraps HybridNet_v4 and temperature scaling into a single end-to-end
    inference module outputting calibrated softmax probabilities.
    """
    def __init__(self, model: HybridNet_v4, temperature: float = 1.0):
        super().__init__()
        self.model = model
        self.temperature = nn.Parameter(torch.tensor([temperature], dtype=torch.float32), requires_grad=False)

    def forward(self, token_ids: torch.Tensor, feats: torch.Tensor) -> torch.Tensor:
        logits = self.model(token_ids, feats)
        scaled_logits = logits / self.temperature
        probs = F.softmax(scaled_logits, dim=-1)
        return probs


def export_and_verify_onnx(
    model_path: str = "outputs/hybridnet_v4_best.pt",
    calibrated_path: str = "outputs/hybridnet_v4_calibrated.pt",
    onnx_output_path: str = "outputs/uniguard_charcnn.onnx",
    device: torch.device = None,
) -> bool:
    if not _HAS_ONNX:
        print("[ONNX] Error: onnx and onnxruntime must be installed.")
        return False

    if device is None:
        device = torch.device("cpu")

    print(f"\n{'='*64}")
    print("  ONNX EXPORT & NUMERICAL PARITY VERIFICATION")
    print(f"{'='*64}")

    # 1. Load PyTorch model and config
    print(f"[ONNX] Loading model checkpoint: {model_path}")
    ckpt = torch.load(model_path, map_location=device, weights_only=False)
    cfg_dict = ckpt.get("config", {})
    cfg = TrainingConfig(**{k: v for k, v in cfg_dict.items() if hasattr(TrainingConfig, k)})

    model = HybridNet_v4(cfg).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    # 2. Load temperature
    temperature = 1.0
    if os.path.isfile(calibrated_path):
        cal_ckpt = torch.load(calibrated_path, map_location=device, weights_only=False)
        temperature = float(cal_ckpt.get("temperature", 1.0))
        print(f"[ONNX] Loaded temperature: {temperature:.4f}")
    else:
        print(f"[ONNX] Calibrated checkpoint not found. Using default T=1.0")

    # 3. Create wrapper
    wrapped_model = CalibratedONNXWrapper(model, temperature=temperature).to(device)
    wrapped_model.eval()

    # 4. Dummy inputs for export (batch_size=1)
    dummy_tokens = torch.randint(0, 40, (1, cfg.max_len), dtype=torch.int64, device=device)
    dummy_feats = torch.randn(1, cfg.num_lexical_features, dtype=torch.float32, device=device)

    # 5. Export to ONNX
    os.makedirs(os.path.dirname(onnx_output_path), exist_ok=True)
    print(f"[ONNX] Exporting to: {onnx_output_path}...")
    torch.onnx.export(
        wrapped_model,
        (dummy_tokens, dummy_feats),
        onnx_output_path,
        export_params=True,
        opset_version=18,
        do_constant_folding=True,
        input_names=["token_ids", "lexical_features"],
        output_names=["probabilities"],
        dynamic_axes={
            "token_ids": {0: "batch_size"},
            "lexical_features": {0: "batch_size"},
            "probabilities": {0: "batch_size"},
        },
    )
    print("[ONNX] Model successfully exported to ONNX.")

    # 6. Check ONNX model structure
    onnx_model = onnx.load(onnx_output_path)
    onnx.checker.check_model(onnx_model)
    print("[ONNX] ONNX model structural check passed.")

    # 7. Numerical Parity Verification with onnxruntime
    print("[ONNX] Running numerical parity verification...")
    ort_session = ort.InferenceSession(onnx_output_path, providers=["CPUExecutionProvider"])

    # Test with varying batch sizes: 1, 16, 64
    max_diff_overall = 0.0
    for test_bs in [1, 16, 64]:
        test_tokens = torch.randint(0, 40, (test_bs, cfg.max_len), dtype=torch.int64, device=device)
        test_feats = torch.randn(test_bs, cfg.num_lexical_features, dtype=torch.float32, device=device)

        with torch.no_grad():
            py_probs = wrapped_model(test_tokens, test_feats).cpu().numpy()

        ort_inputs = {
            "token_ids": test_tokens.cpu().numpy(),
            "lexical_features": test_feats.cpu().numpy(),
        }
        ort_probs = ort_session.run(["probabilities"], ort_inputs)[0]

        diff = np.max(np.abs(py_probs - ort_probs))
        max_diff_overall = max(max_diff_overall, diff)
        print(f"[ONNX] Batch Size={test_bs:2d} -> Max absolute diff: {diff:.2e}")

    print(f"[ONNX] Overall Max Absolute Difference: {max_diff_overall:.2e}")
    assert max_diff_overall < 1e-4, f"Parity check failed! Max diff {max_diff_overall} >= 1e-4"
    print("[ONNX] Numerical parity verification PASSED (max abs diff < 1e-4)!")

    # Save verification metadata
    meta = {
        "onnx_model_path": onnx_output_path,
        "opset_version": 14,
        "max_abs_diff": float(max_diff_overall),
        "parity_verified": True,
        "temperature": temperature,
        "max_len": cfg.max_len,
        "num_features": cfg.num_lexical_features,
    }
    with open("outputs/onnx_verification.json", "w") as f:
        json.dump(meta, f, indent=2)

    return True


if __name__ == "__main__":
    export_and_verify_onnx()
