from sklearn.base import BaseEstimator, ClassifierMixin
import lightgbm as lgb
import numpy as np

class LGBMWrapper(BaseEstimator, ClassifierMixin):
    def __init__(self, model_path=None, objective="binary"):
        self.model_path = model_path
        self.objective = objective
        self._booster = None

    def fit(self, X, y):
        # We don't fit here, it's just a wrapper
        pass

    def predict_proba(self, X):
        # The calibrator will use predict_proba or decision_function.
        booster = getattr(self, '_booster', None)
        if booster is None:
            booster = lgb.Booster(model_file=self.model_path)
            self._booster = booster
        
        preds = self._booster.predict(X)
        
        if self.objective == "binary":
            return np.vstack([1 - preds, preds]).T
        else:
            return preds
            
    def predict(self, X):
        probs = self.predict_proba(X)
        if self.objective == "binary":
            return (probs[:, 1] > 0.5).astype(int)
        else:
            return np.argmax(probs, axis=1)

    # Need classes_ for CalibratedClassifierCV
    @property
    def classes_(self):
        if self.objective == "binary":
            return np.array([0, 1])
        else:
            return np.arange(10)
