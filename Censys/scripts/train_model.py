import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os

from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    auc,
    average_precision_score
)
from sklearn.base import clone

# =========================
# Paths & Reproducibility
# =========================
BASE_DIR = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS"
DATASET_PATH = os.path.join(BASE_DIR, "Censys/data/processed/dataset_features_production.csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "Results/Results_datasetv1")
os.makedirs(OUTPUT_DIR, exist_ok=True)

np.random.seed(42)

print("=" * 70)
print("PHISHING DETECTION - LOGISTIC REGRESSION PIPELINE (FINAL)")
print("=" * 70)
print(f"Dataset: {DATASET_PATH}")
print(f"Output:  {OUTPUT_DIR}\n")

# =========================
# Load data
# =========================
df = pd.read_csv(DATASET_PATH)

X = df.drop(columns=["label", "ip"])
y = df["label"]

cat_cols = ["continent", "web_server", "http_any_status_class", "cert_validation_level"]
num_cols = [c for c in X.columns if c not in cat_cols]

# =========================
# Train/test split
# =========================
print("[1/9] Train/test split (80/20, stratified)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# =========================
# FIX: lock OHE categories using TRAIN set
# Ensures identical feature space across folds
# =========================
categories_map = [np.sort(X_train[col].dropna().unique()) for col in cat_cols]

preprocess = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(
            handle_unknown="ignore",
            sparse_output=False,
            categories=categories_map
        ), cat_cols),
        ("num", StandardScaler(), num_cols),
    ],
    remainder="drop"
)

# =========================
# Model (sklearn 1.8+ friendly)
# Use elasticnet + l1_ratio (no deprecated penalty grid)
# l1_ratio=0 -> L2, l1_ratio=1 -> L1
# =========================
base_pipe = Pipeline([
    ("prep", preprocess),
    ("clf", LogisticRegression(
        solver="saga",
        penalty="elasticnet",
        max_iter=5000,
        class_weight="balanced",
        random_state=42
    ))
])

# =========================
# Hyperparameter tuning
# =========================
print("[2/9] Hyperparameter tuning (5-fold CV)...")
param_grid = {
    "clf__C": [0.01, 0.1, 1, 10, 100],
    "clf__l1_ratio": [0.0, 1.0]  # 0 = L2, 1 = L1
}

cv_inner = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

grid = GridSearchCV(
    base_pipe,
    param_grid,
    cv=cv_inner,
    scoring="roc_auc",
    n_jobs=-1,
    verbose=0,
    return_train_score=True
)

grid.fit(X_train, y_train)
best_C = grid.best_params_["clf__C"]
best_l1r = grid.best_params_["clf__l1_ratio"]
print(f"      Best: C={best_C}, l1_ratio={best_l1r} (0=L2,1=L1), CV AUC={grid.best_score_:.4f}")

# =========================
# Evaluate on test set
# =========================
print("[3/9] Evaluating on test set...")
best_pipe = grid.best_estimator_

y_pred = best_pipe.predict(X_test)
y_prob = best_pipe.predict_proba(X_test)[:, 1]

test_auc = roc_auc_score(y_test, y_prob)
test_ap = average_precision_score(y_test, y_prob)

cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

phishing_recall = tp / (tp + fn) if (tp + fn) else 0
phishing_precision = tp / (tp + fp) if (tp + fp) else 0
false_alarm_rate = fp / (fp + tn) if (fp + tn) else 0
test_acc = (y_test == y_pred).mean()

print(f"      Test AUC: {test_auc:.4f}, AP: {test_ap:.4f}")

# =========================
# Feature importance (global model)
# =========================
print("[4/9] Extracting feature importance...")
feature_names = best_pipe.named_steps["prep"].get_feature_names_out()
coefficients = best_pipe.named_steps["clf"].coef_[0]

feat_importance = pd.DataFrame({
    "feature": feature_names,
    "coefficient": coefficients,
    "abs_coefficient": np.abs(coefficients)
}).sort_values("abs_coefficient", ascending=False)

# =========================
# Coefficient stability across folds
# (now safe: same feature space due to fixed categories)
# =========================
print("[5/9] Analyzing coefficient stability across folds...")
fold_coefficients = []

for train_idx, _ in cv_inner.split(X_train, y_train):
    X_fold_train = X_train.iloc[train_idx]
    y_fold_train = y_train.iloc[train_idx]

    pipe_fold = clone(best_pipe)
    pipe_fold.fit(X_fold_train, y_fold_train)

    fold_coef = pipe_fold.named_steps["clf"].coef_[0]
    fold_coefficients.append(fold_coef)

fold_coefficients = np.vstack(fold_coefficients)

coef_mean = fold_coefficients.mean(axis=0)
coef_std = fold_coefficients.std(axis=0)

EPS_MEAN = 0.05
STABILITY_RATIO = 0.5
IMPORTANCE_THRESHOLD = 0.2
UNSTABLE_MIN_ABS_MEAN = 0.1
NEAR_ZERO_THRESHOLD = 0.05

coef_cv = np.where(np.abs(coef_mean) > EPS_MEAN, np.abs(coef_std / coef_mean), np.nan)
is_stable = (coef_std <= STABILITY_RATIO * np.abs(coef_mean)) | (np.abs(coef_mean) < EPS_MEAN)

stability_analysis = pd.DataFrame({
    "feature": feature_names,
    "coef_mean": coef_mean,
    "coef_std": coef_std,
    "coef_cv": coef_cv,
    "abs_coef_mean": np.abs(coef_mean),
    "is_stable": is_stable,
    "is_important": np.abs(coef_mean) > IMPORTANCE_THRESHOLD
}).sort_values("abs_coef_mean", ascending=False)

stable_and_important = stability_analysis[
    (stability_analysis["is_stable"]) & (stability_analysis["is_important"])
]

unstable_features = stability_analysis[
    (~stability_analysis["is_stable"]) & (stability_analysis["abs_coef_mean"] > UNSTABLE_MIN_ABS_MEAN)
]

print(f"      Stable & important: {len(stable_and_important)}, Unstable: {len(unstable_features)}")

# =========================
# Visualizations
# =========================
print("[6/9] Generating visualizations...")

# ROC
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc_plot = auc(fpr, tpr)

plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, lw=2, label=f"ROC curve (AUC = {roc_auc_plot:.3f})")
plt.plot([0, 1], [0, 1], lw=1, linestyle="--", label="Random classifier")
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel("False Positive Rate", fontsize=12)
plt.ylabel("True Positive Rate (Recall)", fontsize=12)
plt.title("ROC Curve - Phishing Detection (Metadata-Centric)", fontsize=14, fontweight="bold")
plt.legend(loc="lower right", fontsize=11)
plt.grid(alpha=0.3)
plt.tight_layout()
roc_path = os.path.join(OUTPUT_DIR, "roc_curve.png")
plt.savefig(roc_path, dpi=300, bbox_inches="tight")
plt.close()

# PR + AP
precision, recall, _ = precision_recall_curve(y_test, y_prob)
pr_auc_plot = auc(recall, precision)

plt.figure(figsize=(10, 6))
plt.plot(recall, precision, lw=2, label=f"PR curve (AUC = {pr_auc_plot:.3f}, AP = {test_ap:.3f})")
plt.xlabel("Recall (Phishing Detection Rate)", fontsize=12)
plt.ylabel("Precision (Alert Accuracy)", fontsize=12)
plt.title("Precision-Recall Curve - Phishing Detection", fontsize=14, fontweight="bold")
plt.legend(loc="upper right", fontsize=11)
plt.grid(alpha=0.3)
plt.tight_layout()
pr_path = os.path.join(OUTPUT_DIR, "precision_recall_curve.png")
plt.savefig(pr_path, dpi=300, bbox_inches="tight")
plt.close()

# Stability scatter
plt.figure(figsize=(12, 8))
colors = stability_analysis["is_stable"].map({True: "green", False: "red"}).values

plt.scatter(
    stability_analysis["abs_coef_mean"],
    stability_analysis["coef_std"],
    c=colors,
    alpha=0.6,
    s=90,
    linewidth=0.4
)

top_20 = stability_analysis.head(20)
for _, row in top_20.iterrows():
    plt.annotate(
        row["feature"].split("__")[-1][:18],
        xy=(row["abs_coef_mean"], row["coef_std"]),
        xytext=(5, 5),
        textcoords="offset points",
        fontsize=8,
        alpha=0.75
    )

plt.xlabel("|Mean Coefficient|", fontsize=12)
plt.ylabel("Std Coefficient (across folds)", fontsize=12)
plt.title(
    f"Feature Stability Analysis\nGreen=Stable (std ≤ {STABILITY_RATIO}*|mean|), Red=Unstable",
    fontsize=14, fontweight="bold"
)
plt.grid(alpha=0.3)
plt.tight_layout()
stability_plot_path = os.path.join(OUTPUT_DIR, "feature_stability_plot.png")
plt.savefig(stability_plot_path, dpi=300, bbox_inches="tight")
plt.close()

# =========================
# Text report
# =========================
print("[7/9] Generating detailed analysis report...")

phishing_indicators = feat_importance.sort_values("coefficient", ascending=False).head(10)
legit_indicators = feat_importance.sort_values("coefficient", ascending=True).head(10)
near_zero = feat_importance[feat_importance["abs_coefficient"] < NEAR_ZERO_THRESHOLD] \
    .sort_values("abs_coefficient") \
    .head(10)

summary_path = os.path.join(OUTPUT_DIR, "feature_analysis_summary.txt")
with open(summary_path, "w") as f:
    f.write("=" * 80 + "\n")
    f.write("FEATURE ANALYSIS SUMMARY - LOGISTIC REGRESSION (FINAL)\n")
    f.write("Phishing Detection using Censys Metadata\n")
    f.write("=" * 80 + "\n\n")

    f.write(f"Dataset: {len(df)} samples ({(y==1).sum()} phishing, {(y==0).sum()} legit)\n")
    f.write(f"Features: {len(X.columns)} raw → {len(feature_names)} after encoding\n")
    f.write(f"Model: Logistic Regression (solver=saga, penalty=elasticnet)\n")
    f.write(f"Best hyperparams: C={best_C}, l1_ratio={best_l1r} (0=L2,1=L1)\n\n")

    f.write("Performance (test set):\n")
    f.write(f"  - ROC-AUC: {test_auc:.4f}\n")
    f.write(f"  - Average Precision (AP): {test_ap:.4f}\n")
    f.write(f"  - Accuracy: {test_acc:.4f}\n")
    f.write(f"  - Phishing Recall: {phishing_recall*100:.1f}%\n")
    f.write(f"  - Phishing Precision: {phishing_precision*100:.1f}%\n")
    f.write(f"  - False Alarm Rate: {false_alarm_rate*100:.1f}%\n\n")

    f.write("-" * 80 + "\n")
    f.write("TOP 10 PHISHING INDICATORS (highest positive coefficients)\n")
    f.write("-" * 80 + "\n")
    for _, row in phishing_indicators.iterrows():
        stability = stability_analysis.loc[stability_analysis["feature"] == row["feature"]].iloc[0]
        stable_mark = "[STABLE]" if stability["is_stable"] else "[UNSTABLE]"
        f.write(f"{stable_mark:12} {row['feature']:<55} {row['coefficient']:>8.4f}\n")

    f.write("\n" + "-" * 80 + "\n")
    f.write("TOP 10 LEGITIMACY INDICATORS (lowest negative coefficients)\n")
    f.write("-" * 80 + "\n")
    for _, row in legit_indicators.iterrows():
        stability = stability_analysis.loc[stability_analysis["feature"] == row["feature"]].iloc[0]
        stable_mark = "[STABLE]" if stability["is_stable"] else "[UNSTABLE]"
        f.write(f"{stable_mark:12} {row['feature']:<55} {row['coefficient']:>8.4f}\n")

    f.write("\n" + "-" * 80 + "\n")
    f.write(f"STABILITY ANALYSIS (criterion: std ≤ {STABILITY_RATIO} * |mean|)\n")
    f.write("-" * 80 + "\n")
    f.write(f"Stable & important (|mean|>{IMPORTANCE_THRESHOLD}): {len(stable_and_important)}\n")
    f.write(f"Unstable (|mean|>{UNSTABLE_MIN_ABS_MEAN}): {len(unstable_features)}\n\n")

    if len(unstable_features) > 0:
        f.write("Unstable features (candidates for removal/improvement):\n")
        for _, row in unstable_features.head(10).iterrows():
            cv_str = f"{row['coef_cv']:.2f}" if not np.isnan(row["coef_cv"]) else "N/A"
            f.write(f"  - {row['feature']:<55} (mean={row['coef_mean']:>7.3f}, std={row['coef_std']:>7.3f}, CV={cv_str})\n")

    f.write("\n" + "-" * 80 + "\n")
    f.write("RECOMMENDATIONS FOR NEXT ITERATION\n")
    f.write("-" * 80 + "\n")

    if len(unstable_features) > 0:
        f.write("1. Remove or re-engineer unstable features:\n")
        for _, row in unstable_features.head(5).iterrows():
            f.write(f"   - {row['feature']}\n")

    if len(near_zero) > 0:
        f.write("\n2. Remove near-zero features (minimal impact):\n")
        for _, row in near_zero.head(5).iterrows():
            f.write(f"   - {row['feature']} (coeff={row['coefficient']:.4f})\n")

    f.write("\n3. Prioritize stable & important features for interpretation:\n")
    for _, row in stable_and_important.head(10).iterrows():
        direction = "phishing" if row["coef_mean"] > 0 else "legit"
        f.write(f"   - {row['feature']:<55} → {direction}\n")

# =========================
# Save outputs
# =========================
print("[8/9] Saving results...")

results_summary = {
    "dataset_size": len(df),
    "train_size": len(X_train),
    "test_size": len(X_test),
    "num_features_raw": len(X.columns),
    "num_features_encoded": len(feature_names),
    "sample_to_feature_ratio": len(X_train) / len(feature_names),
    "best_C": best_C,
    "best_l1_ratio": best_l1r,
    "gridsearch_cv_roc_auc": grid.best_score_,
    "test_roc_auc": test_auc,
    "test_average_precision": test_ap,
    "test_accuracy": test_acc,
    "phishing_recall": phishing_recall,
    "phishing_precision": phishing_precision,
    "false_alarm_rate": false_alarm_rate,
    "num_stable_important_features": len(stable_and_important),
    "num_unstable_features": len(unstable_features)
}

pd.DataFrame([results_summary]).to_csv(os.path.join(OUTPUT_DIR, "model_results_summary.csv"), index=False)
feat_importance.to_csv(os.path.join(OUTPUT_DIR, "feature_importance.csv"), index=False)
stability_analysis.to_csv(os.path.join(OUTPUT_DIR, "feature_stability_analysis.csv"), index=False)
pd.DataFrame(grid.cv_results_).to_csv(os.path.join(OUTPUT_DIR, "gridsearch_results.csv"), index=False)


print(f"Results: {OUTPUT_DIR}")