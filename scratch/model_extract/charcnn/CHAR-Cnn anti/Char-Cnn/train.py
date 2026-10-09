"""
Char-CNN v4 — Training Engine
================================
Full training loop with:
  * AdamW + OneCycleLR (20 % warmup, cosine annealing)
  * Automatic Mixed Precision (AMP)
  * Gradient clipping (max_norm = 1.0)
  * Early stopping on validation Macro-F1 (patience = 6)
  * Post-training temperature scaling calibration
  * Decision threshold optimisation via 2D grid search
"""

import copy
import os
import time
from typing import Dict, Optional, Tuple

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import f1_score
from torch.utils.data import DataLoader

from calibration import TemperatureScaler
from config import IDX2LABEL, TrainingConfig
from losses import FocalLoss, compute_focal_weights
from model import HybridNet_v4


# ──────────────────────────────────────────────
# Training loop
# ──────────────────────────────────────────────

def train_one_epoch(
    model: HybridNet_v4,
    loader: DataLoader,
    criterion: FocalLoss,
    optimizer: torch.optim.Optimizer,
    scheduler,
    scaler,
    device: torch.device,
    cfg: TrainingConfig,
) -> Tuple[float, float]:
    """Train for one epoch.  Returns (avg_loss, macro_f1)."""
    model.train()
    total_loss = 0.0
    all_preds, all_labels = [], []

    for tokens, feats, labels in loader:
        tokens = tokens.to(device)
        feats = feats.to(device)
        labels = labels.to(device)

        optimizer.zero_grad(set_to_none=True)

        with torch.amp.autocast(device_type=device.type, enabled=cfg.use_amp):
            logits = model(tokens, feats)
            loss = criterion(logits, labels)

        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip_norm)
        scaler.step(optimizer)
        scaler.update()
        scheduler.step()

        total_loss += loss.item() * labels.size(0)
        preds = logits.argmax(dim=1).cpu().numpy()
        all_preds.append(preds)
        all_labels.append(labels.cpu().numpy())

    all_preds = np.concatenate(all_preds)
    all_labels = np.concatenate(all_labels)
    avg_loss = total_loss / len(all_labels)
    macro_f1 = f1_score(all_labels, all_preds, average="macro")
    return avg_loss, macro_f1


@torch.no_grad()
def validate(
    model: HybridNet_v4,
    loader: DataLoader,
    criterion: FocalLoss,
    device: torch.device,
    cfg: TrainingConfig,
) -> Tuple[float, float]:
    """Validate.  Returns (avg_loss, macro_f1)."""
    model.eval()
    total_loss = 0.0
    all_preds, all_labels = [], []

    for tokens, feats, labels in loader:
        tokens = tokens.to(device)
        feats = feats.to(device)
        labels = labels.to(device)

        with torch.amp.autocast(device_type=device.type, enabled=cfg.use_amp):
            logits = model(tokens, feats)
            loss = criterion(logits, labels)

        total_loss += loss.item() * labels.size(0)
        preds = logits.argmax(dim=1).cpu().numpy()
        all_preds.append(preds)
        all_labels.append(labels.cpu().numpy())

    all_preds = np.concatenate(all_preds)
    all_labels = np.concatenate(all_labels)
    avg_loss = total_loss / len(all_labels)
    macro_f1 = f1_score(all_labels, all_preds, average="macro")
    return avg_loss, macro_f1


# ──────────────────────────────────────────────
# Full training pipeline
# ──────────────────────────────────────────────

def run_training(
    model: HybridNet_v4,
    train_loader: DataLoader,
    val_loader: DataLoader,
    train_labels: np.ndarray,
    cfg: TrainingConfig,
    device: torch.device,
    resume_checkpoint: Optional[str] = None,
    cal_loader: Optional[DataLoader] = None,
) -> Tuple[HybridNet_v4, TemperatureScaler, Dict]:
    """
    Execute the complete training → calibration pipeline.

    Parameters
    ----------
    resume_checkpoint : str or None
        Path to a checkpoint file to resume from.  The model weights are
        loaded before training begins.  If the checkpoint contains full
        training state (optimizer, scheduler, epoch, etc.) an exact
        continuation is performed; otherwise a warm-start with a fresh
        optimizer/scheduler is used.

    Returns
    -------
    model : Best checkpoint model (loaded in eval mode).
    scaler : Fitted TemperatureScaler.
    history : Dict of training metrics per epoch.
    """
    model = model.to(device)

    # ── Resume: load model weights from checkpoint ─
    start_epoch = 1
    resumed_best_val_f1 = -1.0
    resumed_optimizer_state = None
    resumed_scheduler_state = None
    resumed_amp_scaler_state = None
    resumed_history = None

    if resume_checkpoint and os.path.isfile(resume_checkpoint):
        print(f"[RESUME] Loading checkpoint: {resume_checkpoint}")
        ckpt = torch.load(resume_checkpoint, map_location=device, weights_only=False)

        # Load model weights
        model.load_state_dict(ckpt["model_state_dict"])
        print("[RESUME] Model weights loaded successfully.")

        # Check for full training state (saved by this version)
        if "epoch" in ckpt:
            start_epoch = ckpt["epoch"] + 1
            resumed_best_val_f1 = ckpt.get("best_val_f1", -1.0)
            resumed_optimizer_state = ckpt.get("optimizer_state_dict")
            resumed_scheduler_state = ckpt.get("scheduler_state_dict")
            resumed_amp_scaler_state = ckpt.get("amp_scaler_state_dict")
            resumed_history = ckpt.get("history")
            print(
                f"[RESUME] Full state found - resuming from epoch {start_epoch} "
                f"(best val F1={resumed_best_val_f1:.4f})"
            )
        else:
            print(
                "[RESUME] Checkpoint has model weights only (legacy format). "
                "Warm-starting with fresh optimizer/scheduler."
            )
    elif resume_checkpoint:
        print(f"[RESUME] WARNING: Checkpoint not found at {resume_checkpoint}. "
              "Training from scratch.")

    # ── Focal Loss with sqrt-dampened weights ─
    alpha = compute_focal_weights(train_labels, sqrt=True).to(device)
    criterion = FocalLoss(alpha=alpha, gamma=cfg.focal_gamma)
    print(f"[TRAIN] Focal Loss weights (sqrt-balanced): {alpha.cpu().numpy()}")

    # ── Optimiser & Scheduler ────────────────
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay
    )
    total_steps = cfg.epochs * len(train_loader)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer,
        max_lr=cfg.lr,
        total_steps=total_steps,
        pct_start=cfg.warmup_pct,
        anneal_strategy="cos",
    )
    amp_scaler = torch.amp.GradScaler(enabled=(cfg.use_amp and device.type == "cuda"))

    # Restore optimizer/scheduler/scaler if full state was saved
    if resumed_optimizer_state is not None:
        optimizer.load_state_dict(resumed_optimizer_state)
        print("[RESUME] Optimizer state restored.")
    if resumed_scheduler_state is not None:
        scheduler.load_state_dict(resumed_scheduler_state)
        print("[RESUME] Scheduler state restored.")
    if resumed_amp_scaler_state is not None:
        amp_scaler.load_state_dict(resumed_amp_scaler_state)
        print("[RESUME] AMP scaler state restored.")

    # ── Training loop ────────────────────────
    if resumed_history is not None:
        history = resumed_history
    else:
        history = {"train_loss": [], "train_f1": [], "val_loss": [], "val_f1": []}

    best_val_f1 = resumed_best_val_f1
    best_state = copy.deepcopy(model.state_dict()) if resume_checkpoint else None
    epochs_no_improve = 0

    print(f"\n{'='*60}")
    if start_epoch > 1:
        print(
            f"RESUMING TRAINING - epochs {start_epoch}->{cfg.epochs}, "
            f"BS={cfg.batch_size}, device={device}"
        )
    else:
        print(f"TRAINING -- {cfg.epochs} epochs, BS={cfg.batch_size}, device={device}")
    print(f"{'='*60}")

    for epoch in range(start_epoch, cfg.epochs + 1):
        t0 = time.time()

        train_loss, train_f1 = train_one_epoch(
            model, train_loader, criterion, optimizer, scheduler,
            amp_scaler, device, cfg,
        )
        val_loss, val_f1 = validate(model, val_loader, criterion, device, cfg)

        elapsed = time.time() - t0
        history["train_loss"].append(train_loss)
        history["train_f1"].append(train_f1)
        history["val_loss"].append(val_loss)
        history["val_f1"].append(val_f1)

        marker = ""
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_state = copy.deepcopy(model.state_dict())
            epochs_no_improve = 0
            marker = " *"
        else:
            epochs_no_improve += 1

        lr_now = optimizer.param_groups[0]["lr"]
        print(
            f"Epoch {epoch:>3d}/{cfg.epochs}  |  "
            f"Train Loss={train_loss:.4f}  F1={train_f1:.4f}  |  "
            f"Val Loss={val_loss:.4f}  F1={val_f1:.4f}  |  "
            f"LR={lr_now:.2e}  |  {elapsed:.1f}s{marker}"
        )

        if epochs_no_improve >= cfg.patience:
            print(f"[EARLY STOP] No improvement for {cfg.patience} epochs. Stopping.")
            break

    # ── Restore best checkpoint ──────────────
    if best_state is not None:
        model.load_state_dict(best_state)
    # Save checkpoint with full training state for future resumes
    torch.save(
        {
            "model_state_dict": best_state if best_state is not None else model.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            "scheduler_state_dict": scheduler.state_dict(),
            "amp_scaler_state_dict": amp_scaler.state_dict(),
            "epoch": epoch,
            "best_val_f1": best_val_f1,
            "history": history,
            "config": cfg.__dict__,
        },
        cfg.model_save_path,
    )
    print(f"[TRAIN] Best model saved -> {cfg.model_save_path}  (val F1={best_val_f1:.4f})")

    # ── Temperature scaling calibration ──────
    temp_scaler = TemperatureScaler()
    eval_cal_loader = cal_loader if cal_loader is not None else val_loader
    temp_scaler.calibrate(model, eval_cal_loader, device)

    # Save calibrated model
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "temperature": temp_scaler.temperature.item(),
            "config": cfg.__dict__,
        },
        cfg.calibrated_model_path,
    )
    print(f"[TRAIN] Calibrated model saved -> {cfg.calibrated_model_path}")

    return model, temp_scaler, history
