"""
Char-CNN v4 — Temperature Scaling Calibration
================================================
Post-training calibration using a single learned temperature parameter,
optimised via L-BFGS on the validation set NLL.

Reference:
  Guo et al., "On Calibration of Modern Neural Networks", ICML 2017.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from typing import Tuple


class TemperatureScaler(nn.Module):
    """
    Thin wrapper that divides logits by a learned temperature parameter.
    """

    def __init__(self):
        super().__init__()
        # Initialise temperature to 1.0 (no scaling)
        self.temperature = nn.Parameter(torch.ones(1))

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        return logits / self.temperature

    def calibrate(
        self,
        model: nn.Module,
        val_loader: DataLoader,
        device: torch.device,
        max_iter: int = 100,
        lr: float = 0.01,
    ) -> float:
        """
        Learn the optimal temperature on the validation set.

        Parameters
        ----------
        model : nn.Module
            Trained HybridNet_v4 in eval mode.
        val_loader : DataLoader
            Validation data loader.
        device : torch.device
        max_iter : int
            Maximum L-BFGS iterations.
        lr : float
            L-BFGS learning rate.

        Returns
        -------
        float : optimal temperature value.
        """
        # Collect all validation logits and labels
        all_logits = []
        all_labels = []

        model.eval()
        with torch.no_grad():
            for tokens, feats, labels in val_loader:
                tokens = tokens.to(device)
                feats = feats.to(device)
                logits = model(tokens, feats)
                all_logits.append(logits.cpu())
                all_labels.append(labels)

        all_logits = torch.cat(all_logits, dim=0).to(device)
        all_labels = torch.cat(all_labels, dim=0).to(device)

        # Optimise temperature with L-BFGS
        self.to(device)
        nll_criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.LBFGS([self.temperature], lr=lr, max_iter=max_iter)

        def closure():
            optimizer.zero_grad()
            scaled_logits = self.forward(all_logits)
            loss = nll_criterion(scaled_logits, all_labels)
            loss.backward()
            return loss

        optimizer.step(closure)
        optimal_temp = self.temperature.item()
        print(f"[CALIBRATION] Optimal temperature = {optimal_temp:.4f}")
        return optimal_temp


def calibrated_predict(
    model: nn.Module,
    scaler: TemperatureScaler,
    tokens: torch.Tensor,
    feats: torch.Tensor,
    device: torch.device,
) -> Tuple[torch.Tensor, torch.Tensor]:
    """
    Run inference with temperature-scaled probabilities.

    Returns
    -------
    probs : (B, 3) calibrated probabilities.
    preds : (B,) predicted class indices.
    """
    model.eval()
    scaler.eval()
    with torch.no_grad():
        logits = model(tokens.to(device), feats.to(device))
        scaled_logits = scaler(logits)
        probs = F.softmax(scaled_logits, dim=1)
        preds = probs.argmax(dim=1)
    return probs.cpu(), preds.cpu()
