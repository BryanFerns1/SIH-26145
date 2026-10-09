"""
Char-CNN v4 — DNS Threat Detection Engine (SIH26145)
=====================================================
AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.

Modules:
  config      — Centralised configuration, vocabulary, MITRE mappings
  features    — 12 handcrafted lexical feature extractors
  dataset     — Tokeniser and PyTorch Dataset
  splitter    — Group-aware leak-free data splitting
  model       — HybridNet_v4 architecture
  losses      — Alpha-weighted Focal Loss
  calibration — Post-training temperature scaling (L-BFGS)
  train       — Training engine with AMP + OneCycleLR
  evaluate    — Metrics, confusion matrix, benchmarking
  alert       — SIH26145-compliant JSON alert serializer
  main        — Pipeline entry point
"""

__version__ = "4.0.0"
__project__ = "SIH26145"
