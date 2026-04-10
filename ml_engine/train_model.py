# ml_engine/train_model.py
import pandas as pd
import joblib
import json
import os
from pathlib import Path
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH   = BASE_DIR / "waf_model.pkl"
FEEDBACK_LOG = BASE_DIR.parent / "data" / "feedback_log.jsonl"

# ─── Load dataset (same as before) ────────────────────────────────────────────
def load_dataset(csv_path=DATASET_PATH):
    df = pd.read_csv(csv_path)
    df["payload"] = df["payload"].astype(str).fillna("")
    df["label"]   = df["label"].astype(int)
    return df["payload"], df["label"]


# ─── NEW: Build Ensemble Pipeline (XGBoost + Random Forest) ───────────────────
def build_pipeline():
    """
    Upgraded pipeline: soft-voting ensemble of XGBoost + Random Forest.
    Each estimator has its own TF-IDF so they learn independently.
    Replaces the single RandomForest from the original train_model.py.
    """
    rf = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 3),
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

    xgb = Pipeline([
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
            
            eval_metric="logloss",
            random_state=42,
        ))
    ])

    # Soft voting = average predicted probabilities (better than hard vote)
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
        weights=[0.4, 0.6],   # XGBoost slightly weighted higher
    )
    return ensemble


# ─── Train & evaluate ─────────────────────────────────────────────────────────
def train(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    print("Training ensemble (XGBoost + Random Forest)...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    joblib.dump(pipeline, MODEL_PATH)
    print(f"Saved upgraded model to {MODEL_PATH}")
    return pipeline


# ─── NEW: Auto-retraining pipeline ────────────────────────────────────────────
# When admin corrects WAF decisions via /admin/feedback in gateway.py,
# entries are appended to feedback_log.jsonl.
# Call retrain_from_feedback() periodically (e.g. cron job or after 500 entries).

RETRAIN_EVERY = 500   # retrain after this many new feedback entries
MIN_SAMPLES   = 100   # minimum feedback entries needed to retrain


def log_feedback(payload: str, true_label: int):
    """
    Log a corrected prediction for later retraining.
    true_label: 0 = benign, 1 = malicious
    """
    os.makedirs(FEEDBACK_LOG.parent, exist_ok=True)
    entry = {"payload": payload, "label": true_label}
    with open(FEEDBACK_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    total = sum(1 for _ in open(FEEDBACK_LOG))
    print(f"Feedback logged. Total: {total}")

    if total >= MIN_SAMPLES and total % RETRAIN_EVERY == 0:
        print("Auto-retrain threshold reached. Retraining...")
        retrain_from_feedback()


def retrain_from_feedback():
    """
    Combines original dataset.csv with all feedback entries,
    then retrains and saves the model.
    """
    # Load original data
    X_orig, y_orig = load_dataset()

    # Load feedback data
    fb_payloads, fb_labels = [], []
    try:
        with open(FEEDBACK_LOG) as f:
            for line in f:
                entry = json.loads(line)
                fb_payloads.append(entry["payload"])
                fb_labels.append(entry["label"])
    except FileNotFoundError:
        print("No feedback log found. Training on original dataset only.")

    import pandas as pd
    X_combined = pd.concat([X_orig, pd.Series(fb_payloads)], ignore_index=True)
    y_combined = pd.concat([y_orig, pd.Series(fb_labels)],   ignore_index=True)

    print(f"Retraining on {len(X_combined)} samples ({len(fb_payloads)} from feedback)...")
    train(X_combined, y_combined)


# ─── Main: run directly to train fresh ────────────────────────────────────────
if __name__ == "__main__":
    X, y = load_dataset()
    train(X, y)