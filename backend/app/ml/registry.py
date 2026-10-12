"""UniGuard Model Registry (Phase 2)."""

import logging
from typing import Dict, Any, List
from pathlib import Path
import json

log = logging.getLogger("uniguard.ml")

class ModelRegistry:
    def __init__(self, artifacts_dir: str):
        self.artifacts_dir = Path(artifacts_dir)
        self.models: Dict[str, Any] = {}
        self.metadata: Dict[str, dict] = {}
        self._load_metadata()

    def _load_metadata(self):
        """Discovers models via model_card.json in artifacts."""
        for card_path in self.artifacts_dir.rglob("model_card.json"):
            try:
                with open(card_path, "r") as f:
                    card = json.load(f)
                    self.metadata[card["name"]] = card
                    log.info(f"Discovered model metadata: {card['name']} v{card['version']}")
            except Exception as e:
                log.error(f"Failed to load metadata from {card_path}: {e}")

    async def load_all(self):
        """Loads all discovered models."""
        log.info(f"Loading {len(self.metadata)} models into registry...")
        
        # Load Char-CNN
        if "charcnn_dns" in self.metadata:
            self._load_charcnn()
            
        # Load LightGBM/IForest
        if "lgbm_iforest" in self.metadata:
            self._load_lgbm_iforest()
            
        # Load Beacon CNN
        if "beacon_cnn" in self.metadata:
            self._load_beacon_cnn()

    def _load_charcnn(self):
        log.info("Loading Char-CNN DNS...")
        import onnxruntime as ort
        
        card = self.metadata["charcnn_dns"]
        model_path = self.artifacts_dir / "charcnn" / card["model_file"]
        
        try:
            sess_opts = ort.SessionOptions()
            sess_opts.intra_op_num_threads = 1
            sess_opts.inter_op_num_threads = 1
            
            session = ort.InferenceSession(
                str(model_path), 
                sess_opts,
                providers=['CPUExecutionProvider']
            )
            
            self.models["charcnn_dns"] = {
                "session": session,
                "input_names": [inp.name for inp in session.get_inputs()],
                "output_name": session.get_outputs()[0].name,
                "card": card
            }
            log.info("Char-CNN DNS loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load Char-CNN DNS: {e}")

    def _load_lgbm_iforest(self):
        log.info("Loading LightGBM & IForest...")
        import joblib
        import lightgbm as lgb
        
        card = self.metadata["lgbm_iforest"]
        base_path = self.artifacts_dir / "lgbm_iforest"
        
        try:
            bin_model = lgb.Booster(model_file=str(base_path / card["models"]["lgbm_binary"]["file"]))
            multi_model = lgb.Booster(model_file=str(base_path / card["models"]["lgbm_multi"]["file"]))
            iforest = joblib.load(base_path / card["models"]["iforest"]["file"])
            cal_bin = joblib.load(base_path / card["models"]["calibrator_binary"]["file"])
            cal_multi = joblib.load(base_path / card["models"]["calibrator_multi"]["file"])
            
            # Fix joblib paths
            if hasattr(cal_bin, 'calibrated_classifiers_'):
                for cc in cal_bin.calibrated_classifiers_:
                    cc.estimator._booster = bin_model
            else:
                cal_bin._booster = bin_model
                
            if hasattr(cal_multi, 'calibrated_classifiers_'):
                for cc in cal_multi.calibrated_classifiers_:
                    cc.estimator._booster = multi_model
            else:
                cal_multi._booster = multi_model
            
            self.models["lgbm_iforest"] = {
                "binary": bin_model,
                "multi": multi_model,
                "iforest": iforest,
                "cal_bin": cal_bin,
                "cal_multi": cal_multi,
                "card": card
            }
            log.info("LightGBM & IForest loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load LightGBM & IForest: {e}")

    def _load_beacon_cnn(self):
        log.info("Loading Beacon 1D-CNN...")
        import onnxruntime as ort
        import pickle
        
        card = self.metadata["beacon_cnn"]
        base_path = self.artifacts_dir / "beacon_cnn"
        
        try:
            # Load ONNX model
            sess_opts = ort.SessionOptions()
            sess_opts.intra_op_num_threads = 1
            sess_opts.inter_op_num_threads = 1
            
            session = ort.InferenceSession(
                str(base_path / card["model_file"]), 
                sess_opts,
                providers=['CPUExecutionProvider']
            )
            
            # Load Isotonic calibrator
            with open(base_path / card["calibration"]["calibrator_file"], 'rb') as f:
                cal_data = pickle.load(f)
                calibrator = cal_data['calibrator']
                
            self.models["beacon_cnn"] = {
                "session": session,
                "input_name": session.get_inputs()[0].name,
                "calibrator": calibrator,
                "card": card
            }
            log.info("Beacon 1D-CNN loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load Beacon 1D-CNN: {e}")

    def get_health(self) -> List[dict]:
        """Returns health metrics for all discovered models."""
        health = []
        for name, card in self.metadata.items():
            status = "REAL" if name in self.models else "ERROR"
            health.append({
                "name": name,
                "status": status,
                "version": card.get("version", "1.0.0"),
                "inference_count": 0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0
            })
        return health
