"""
Char-CNN v4 — HybridNet_v4 Model Architecture
================================================
Multi-scale CNN + Lexical Feature Gating + Bidirectional GRU + Dual Pooling.

Architecture overview:
  Input 1: Character tokens  (B, max_len)
  Input 2: Lexical features  (B, 12)

  Character Embedding → Parallel Conv Bank (k=3,5,7,9) → BatchNorm
  Lexical Projection → Early Modulation + Gating
  Bidirectional GRU → Masked Max-Pool + Masked Avg-Pool
  [max_pool ‖ avg_pool ‖ projected_feats] → Dense Head → (B, 3) logits
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

from config import VOCAB_SIZE, PAD_TOKEN, TrainingConfig


class ConvBlock(nn.Module):
    """Single 1D conv with ReLU activation."""

    def __init__(self, in_channels: int, out_channels: int, kernel_size: int):
        super().__init__()
        self.conv = nn.Conv1d(
            in_channels, out_channels, kernel_size, padding=kernel_size // 2
        )
        self.act = nn.ReLU(inplace=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.act(self.conv(x))


class HybridNet_v4(nn.Module):
    """
    Production-ready Char-CNN + Lexical Feature + BiGRU hybrid.
    """

    def __init__(self, cfg: TrainingConfig):
        super().__init__()
        self.cfg = cfg

        # ── Character embedding ───────────────
        self.embedding = nn.Embedding(
            VOCAB_SIZE, cfg.emb_dim, padding_idx=PAD_TOKEN
        )

        # ── Parallel conv bank ────────────────
        self.conv_bank = nn.ModuleList(
            [ConvBlock(cfg.emb_dim, cfg.conv_filters, k) for k in cfg.kernel_sizes]
        )
        total_conv_channels = cfg.conv_filters * len(cfg.kernel_sizes)  # 512
        self.bn_conv = nn.BatchNorm1d(total_conv_channels)

        # ── Lexical feature projection ────────
        self.feat_proj = nn.Sequential(
            nn.Linear(cfg.num_lexical_features, cfg.lexical_proj_dim),
            nn.ReLU(inplace=True),
        )

        # ── Early modulation: project feats → conv channel dim ──
        self.feat_to_conv = nn.Linear(cfg.lexical_proj_dim, total_conv_channels)

        # ── Gating: project feats → 2*gru_hidden for sigmoid gate ──
        self.gate_proj = nn.Linear(cfg.lexical_proj_dim, 2 * cfg.gru_hidden)

        # ── Bidirectional GRU ─────────────────
        self.gru = nn.GRU(
            input_size=total_conv_channels,
            hidden_size=cfg.gru_hidden,
            batch_first=True,
            bidirectional=True,
        )

        # ── Classifier head ──────────────────
        # Input: [max_pool(2H) ‖ avg_pool(2H) ‖ proj_feats(64)]
        head_input_dim = 4 * cfg.gru_hidden + cfg.lexical_proj_dim
        self.classifier = nn.Sequential(
            nn.Linear(head_input_dim, cfg.classifier_hidden),
            nn.Dropout(cfg.dropout),
            nn.ReLU(inplace=True),
            nn.Linear(cfg.classifier_hidden, 3),
        )

        self._init_weights()

    def _init_weights(self):
        """Kaiming initialisation for linear and conv layers."""
        for m in self.modules():
            if isinstance(m, (nn.Linear, nn.Conv1d)):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(
        self,
        token_ids: torch.Tensor,   # (B, L)
        feats: torch.Tensor,       # (B, 12)
    ) -> torch.Tensor:
        B, L = token_ids.shape

        # ── Mask for unpadded positions ───────
        mask = (token_ids != PAD_TOKEN)           # (B, L) bool

        # ── Embedding → (B, L, E) ────────────
        x = self.embedding(token_ids)             # (B, L, emb_dim)

        # ── Conv bank ────────────────────────
        x_t = x.transpose(1, 2)                  # (B, E, L)
        conv_outs = [conv(x_t) for conv in self.conv_bank]
        x_conv = torch.cat(conv_outs, dim=1)     # (B, 512, L)
        x_conv = self.bn_conv(x_conv)            # (B, 512, L)

        # ── Lexical projection ───────────────
        f_proj = self.feat_proj(feats)            # (B, 64)

        # ── Early modulation ─────────────────
        mod = self.feat_to_conv(f_proj)           # (B, 512)
        x_conv = x_conv + mod.unsqueeze(2)       # broadcast over seq dim

        # ── Transpose back for GRU ───────────
        x_seq = x_conv.transpose(1, 2)           # (B, L, 512)

        # ── GRU ──────────────────────────────
        rnn_out, _ = self.gru(x_seq)             # (B, L, 2H)

        # ── Gating on RNN output ─────────────
        gate = torch.sigmoid(self.gate_proj(f_proj))  # (B, 2H)
        rnn_out = rnn_out * gate.unsqueeze(1)         # (B, L, 2H)

        # ── Masked dual pooling ──────────────
        mask_f = mask.unsqueeze(2).float()        # (B, L, 1)

        # Max pool (set masked positions to -inf)
        rnn_masked = rnn_out.masked_fill(~mask.unsqueeze(2), float("-inf"))
        max_pool, _ = rnn_masked.max(dim=1)      # (B, 2H)

        # Average pool (only over unmasked)
        sum_pool = (rnn_out * mask_f).sum(dim=1)  # (B, 2H)
        lengths = mask_f.sum(dim=1).clamp(min=1)  # (B, 1)
        avg_pool = sum_pool / lengths              # (B, 2H)

        # ── Concatenate & classify ───────────
        combined = torch.cat([max_pool, avg_pool, f_proj], dim=1)
        logits = self.classifier(combined)         # (B, 3)
        return logits
