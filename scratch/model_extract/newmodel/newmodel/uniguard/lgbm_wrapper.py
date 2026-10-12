import numpy as np
import lightgbm as lgb
from sklearn.base import BaseEstimator, ClassifierMixin
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

class LGBMWrapper(BaseEstimator, ClassifierMixin):
    def __init__(self, model_path=None, objective="binary"):
        self.model_path = model_path
        self.objective = objective
        if self.model_path is not None:
            self.model = lgb.Booster(model_file=str(self.model_path))
        else:
            self.model = None
        self.classes_ = np.array([0, 1]) if self.objective == "binary" else np.arange(len(config.CLASSES))

    def fit(self, X, y):
        return self

    def predict_proba(self, X):
        preds = self.model.predict(X)
        if self.objective == "binary":
            return np.vstack([1 - preds, preds]).T
        return preds

    def decision_function(self, X):
        if self.objective == "binary":
            p = self.model.predict(X)
            p = np.clip(p, 1e-15, 1 - 1e-15)
            return np.log(p / (1 - p))
        return self.model.predict(X)
