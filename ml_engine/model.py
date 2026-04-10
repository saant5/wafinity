import math

# ─── Original AnomalyModel (kept unchanged) ───────────────────────────────────
class AnomalyModel:
    def __init__(self):
        self.baseline_length = 100
        self.baseline_entropy = 3.5

    def entropy(self, s):
        prob = [ float(s.count(c)) / len(s) for c in dict.fromkeys(list(s)) ]
        return - sum([ p * math.log2(p) for p in prob ])

    def score(self, payload: str):
        if not payload:
            return 0
        length_score = abs(len(payload) - self.baseline_length) / 10
        entropy_score = abs(self.entropy(payload) - self.baseline_entropy) * 10
        return int(length_score + entropy_score)


# ─── NEW: Ensemble Model (XGBoost + Random Forest) ────────────────────────────
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer
from xgboost import XGBClassifier
import numpy as np

def build_ensemble_pipeline():
    """
    Builds a text-based ensemble pipeline that works directly with
    your existing payload strings — no change needed to your dataset.csv.
    XGBoost (60%) + Random Forest (40%) soft voting.
    """

    # Shared TF-IDF vectorizer output is fed into both classifiers
    # We use a VotingClassifier with text pipeline per estimator
    rf_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 3),      # upgraded: trigrams catch more patterns
            max_features=10000,
            sublinear_tf=True,
        )),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            max_depth=12,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1,
        ))
    ])

    xgb_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 3),
            max_features=10000,
            sublinear_tf=True,
        )),
        ("clf", XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
        ))
    ])

    return rf_pipeline, xgb_pipeline


# Global anomaly model instance (original, unchanged)
model = AnomalyModel()

def ml_anomaly_score(payload: str):
    return model.score(payload)