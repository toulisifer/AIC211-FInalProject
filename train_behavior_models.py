"""
train_behavior_models.py
==========================
Nâng cấp so với bản gốc:
  - Thêm SMOTE để xử lý class imbalance
  - Thêm 5-fold cross-validation
  - Tính detection lead sớm hơn (trước khi 20 file bị ảnh hưởng)
  - Lưu feature importance
  - Lưu ROC data để visualize trong Streamlit
  - Sửa lỗi tên cột if_pred/if_score (gốc dùng if_pred nhưng Streamlit đọc if_score)

Output:
  models/random_forest_behavior.joblib
  models/xgboost_behavior.joblib
  models/isolation_forest_behavior.joblib
  reports/behavior_metrics.csv
  reports/behavior_scored_windows.csv
  reports/feature_importance.csv
  reports/roc_data.csv
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report, roc_curve
)
from xgboost import XGBClassifier

INPUT      = "data/processed/behavior/behavior_features.csv"
METRICS_OUT = "reports/behavior_metrics.csv"
SCORED_OUT  = "reports/behavior_scored_windows.csv"
FI_OUT      = "reports/feature_importance.csv"
ROC_OUT     = "reports/roc_data.csv"

os.makedirs("models", exist_ok=True)
os.makedirs("reports", exist_ok=True)

# ---- Load ----
df = pd.read_csv(INPUT)
df["y"] = (df["label"] == "ransomware").astype(int)

DROP = ["window_id", "first_event_index", "last_event_index", "label", "family", "y"]
feature_cols = [c for c in df.columns if c not in DROP]

X = df[feature_cols].fillna(0)
y = df["y"]

print(f"[+] Dataset: {X.shape[0]} windows, {X.shape[1]} features")
print(f"    Ransomware: {y.sum()} | Benign: {(y==0).sum()}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ---- SMOTE nếu mất cân bằng ----
ratio = y_train.sum() / max(len(y_train) - y_train.sum(), 1)
if ratio < 0.4 or ratio > 2.5:
    print("[*] Applying SMOTE for class imbalance...")
    try:
        from imblearn.over_sampling import SMOTE
        sm = SMOTE(random_state=42, k_neighbors=min(5, y_train.sum()-1))
        X_train, y_train = sm.fit_resample(X_train, y_train)
        print(f"[+] After SMOTE — Ransomware: {y_train.sum()} | Benign: {(y_train==0).sum()}")
    except ImportError:
        print("[!] imbalanced-learn not installed, skipping SMOTE")

results   = []
roc_rows  = []


def fpr_from_cm(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return round(fp / max(fp + tn, 1), 4)


def evaluate(name, y_pred, y_prob=None):
    row = {
        "model":               name,
        "precision":           round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall":              round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1":                  round(f1_score(y_test, y_pred, zero_division=0), 4),
        "false_positive_rate": fpr_from_cm(y_test, y_pred),
        "auc_roc":             round(roc_auc_score(y_test, y_prob), 4) if y_prob is not None else None,
    }
    results.append(row)
    print(f"\n  {name}:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Ransomware"], zero_division=0))

    if y_prob is not None:
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        for f, t in zip(fpr, tpr):
            roc_rows.append({"model": name, "fpr": round(f, 4), "tpr": round(t, 4)})


# ============================================================
# MODEL 1 — Random Forest
# ============================================================
print("\n===== RANDOM FOREST =====")
rf = RandomForestClassifier(
    n_estimators=200, max_depth=12,
    class_weight="balanced", random_state=42, n_jobs=-1
)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_prob = rf.predict_proba(X_test)[:, 1]
evaluate("Random Forest", rf_pred, rf_prob)

# CV
cv_scores = cross_val_score(rf, X, y, cv=5, scoring="f1")
print(f"  5-fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

joblib.dump({"model": rf, "feature_cols": feature_cols},
            "models/random_forest_behavior.joblib")

# Feature importance
fi = pd.DataFrame({
    "feature":    feature_cols,
    "importance": rf.feature_importances_
}).sort_values("importance", ascending=False)
fi.to_csv(FI_OUT, index=False)
print(f"[+] Feature importance saved → {FI_OUT}")

# ============================================================
# MODEL 2 — XGBoost
# ============================================================
print("\n===== XGBOOST =====")
scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
xgb = XGBClassifier(
    n_estimators=300, max_depth=5, learning_rate=0.05,
    subsample=0.85, colsample_bytree=0.85,
    scale_pos_weight=scale_pos,
    eval_metric="logloss", random_state=42, verbosity=0
)
xgb.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
xgb_pred = xgb.predict(X_test)
xgb_prob = xgb.predict_proba(X_test)[:, 1]
evaluate("XGBoost", xgb_pred, xgb_prob)

joblib.dump({"model": xgb, "feature_cols": feature_cols},
            "models/xgboost_behavior.joblib")

# ============================================================
# MODEL 3 — Isolation Forest
# ============================================================
print("\n===== ISOLATION FOREST =====")
benign_train = X_train[y_train == 0]
iso = IsolationForest(n_estimators=300, contamination=0.15, random_state=42)
iso.fit(benign_train)
iso_raw  = iso.predict(X_test)
iso_pred = (iso_raw == -1).astype(int)
iso_prob = -iso.score_samples(X_test)
# Normalize to [0,1]
iso_prob = (iso_prob - iso_prob.min()) / max(iso_prob.max() - iso_prob.min(), 1e-9)
evaluate("Isolation Forest", iso_pred, iso_prob)

joblib.dump({"model": iso, "feature_cols": feature_cols},
            "models/isolation_forest_behavior.joblib")

# ============================================================
# Score ALL windows
# ============================================================
scored = df.copy()
rf_prob_all  = rf.predict_proba(X)[:, 1]
xgb_prob_all = xgb.predict_proba(X)[:, 1]
iso_prob_all_raw = -iso.score_samples(X)
iso_prob_all = (iso_prob_all_raw - iso_prob_all_raw.min()) / max(iso_prob_all_raw.max() - iso_prob_all_raw.min(), 1e-9)

scored["rf_score"]   = rf_prob_all
scored["rf_pred"]    = rf.predict(X)
scored["xgb_score"]  = xgb_prob_all
scored["xgb_pred"]   = xgb.predict(X)
scored["if_score"]   = iso_prob_all
scored["if_pred"]    = (iso.predict(X) == -1).astype(int)

# Ensemble score (average of 3)
scored["ensemble_score"] = (scored["rf_score"] + scored["xgb_score"] + scored["if_score"]) / 3
scored["ensemble_pred"]  = (scored["ensemble_score"] > 0.5).astype(int)

# ---- Detection Lead ----
ransom_windows = scored[scored["y"] == 1]
lead_events = None
if len(ransom_windows) > 0:
    start_idx = ransom_windows["first_event_index"].min()
    after_start = scored[scored["first_event_index"] >= start_idx].copy()
    after_start["cum_affected"] = after_start["affected_file_events"].cumsum()

    critical = after_start[after_start["cum_affected"] >= 20]  # 20 files
    alert    = after_start[after_start["rf_pred"] == 1]

    if len(critical) > 0 and len(alert) > 0:
        critical_event = int(critical.iloc[0]["first_event_index"])
        alert_event    = int(alert.iloc[0]["first_event_index"])
        lead_events    = critical_event - alert_event

scored["rf_detection_lead_events"] = lead_events if lead_events is not None else np.nan

scored.to_csv(SCORED_OUT, index=False)

# ---- Save outputs ----
pd.DataFrame(results).to_csv(METRICS_OUT, index=False)
pd.DataFrame(roc_rows).to_csv(ROC_OUT, index=False)

print("\n" + "="*50)
print("[+] METRICS:")
print(pd.DataFrame(results).to_string(index=False))
print(f"\n[+] Detection lead events (RF): {lead_events}")
print(f"[+] Reports saved → reports/")
print(f"[+] Models  saved → models/")
