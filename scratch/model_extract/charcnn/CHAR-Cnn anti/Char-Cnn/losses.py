"""
Char-CNN v4 — Focal Loss
==========================
Alpha-weighted Focal Loss with softened inverse class frequencies.

FIX (v4): Class weights are square-rooted to dampen the aggressive minority
class penalties that caused a 42 % false-positive spike on benign domains in v3.

Reference:
  T.-Y. Lin et al., "Focal Loss for Dense Object Detection", ICCV 2017.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from sklearn.utils.class_weight import compute_class_weight


def compute_focal_weights(labels: np.ndarray, sqrt: bool = True) -> torch.Tensor:
    """
    Compute balanced class weights from training labels.

    Parameters
    ----------
    labels : np.ndarray
        Integer class labels for the training set.
    sqrt : bool
        If True, apply square-root dampening to the raw weights.

    Returns
    -------
    torch.Tensor of shape (num_classes,)
    """
    classes = np.unique(labels)
    raw_weights = compute_class_weight("balanced", classes=classes, y=labels)
    if sqrt:
        raw_weights = np.sqrt(raw_weights)
    # Normalise so weights sum to num_classes
    raw_weights = raw_weights / raw_weights.sum() * len(classes)
    return torch.tensor(raw_weights, dtype=torch.float32)


class FocalLoss(nn.Module):
    """
    Multi-class Focal Loss.

    loss(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)

    Parameters
    ----------
    alpha : torch.Tensor or None
        Per-class weights of shape (C,).
    gamma : float
        Focusing parameter (default 2.0).
    reduction : str
        'mean' | 'sum' | 'none'.
    """

    def __init__(
        self,
        alpha: torch.Tensor = None,
        gamma: float = 2.0,
        reduction: str = "mean",
    ):
        super().__init__()
        self.gamma = gamma
        self.reduction = reduction
        if alpha is not None:
            self.register_buffer("alpha", alpha)
        else:
            self.alpha = None

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Parameters
        ----------
        logits : (B, C) raw logits.
        targets : (B,) integer class labels.
        """
        log_probs = F.log_softmax(logits, dim=1)       # (B, C)
        probs = torch.exp(log_probs)                    # (B, C)

        # Gather class probabilities
        targets_one_hot = F.one_hot(targets, num_classes=logits.size(1)).float()
        p_t = (probs * targets_one_hot).sum(dim=1)      # (B,)
        log_p_t = (log_probs * targets_one_hot).sum(dim=1)  # (B,)

        # Focal modulation
        focal_weight = (1.0 - p_t) ** self.gamma        # (B,)

        # Alpha weighting
        if self.alpha is not None:
            alpha_t = self.alpha.gather(0, targets)      # (B,)
            focal_weight = alpha_t * focal_weight

        loss = -focal_weight * log_p_t                   # (B,)

        if self.reduction == "mean":
            return loss.mean()
        elif self.reduction == "sum":
            return loss.sum()
        return loss
