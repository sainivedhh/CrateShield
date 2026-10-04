import json
import logging
import pickle
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut, StratifiedGroupKFold, GridSearchCV
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.utils import resample
import numpy as np
import pandas as pd
import xgboost as xgb
import warnings

from crateshield.config import RESULTS_DIR

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "has_build_rs",
    "build_network",
    "build_env",
    "build_spawn",
    "unsafe_blocks",
    "unsafe_kloc",
    "typo_score",
    "dep_count",
    "suspicious_deps",
]


def extract_features(signal: dict) -> list[float]:
    """Convert a structured signal dictionary into a flat numerical feature vector."""
    build = signal.get("build_rs", {})
    unsafe = signal.get("unsafe_ffi", {})
    typo = signal.get("typosquatting", {})
    deps = signal.get("dependencies", {})

    return [
        float(build.get("has_build_rs", False)),
        len(build.get("network_calls", [])),
        len(build.get("env_reads", [])),
        len(build.get("process_spawns", [])),
        float(unsafe.get("unsafe_block_count", 0)),
        float(unsafe.get("unsafe_per_kloc", 0) or 0),
        float(typo.get("score", 0) or 0),
        float(deps.get("count", 0)),
        len(deps.get("suspicious", [])),
    ]


def _load_dataset(
    dataset_path: Path, signals_dir: Path
) -> tuple[np.ndarray, np.ndarray, list[str], np.ndarray]:
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    X, y, names, groups = [], [], [], []

    for crate in dataset.get("crates", []):
        name = crate["name"]
        version = crate.get("version", "0.1.0")
        label = crate["label"]

        if version == "yanked" or not version:
            continue

        signal_file = signals_dir / f"{name}-{version}.json"
        if not signal_file.exists():
            continue

        signal = json.loads(signal_file.read_text(encoding="utf-8"))
        features = extract_features(signal)

        X.append(features)
        y.append(1 if label == "MALICIOUS" else 0)
        names.append(f"{name}@{version}")
        groups.append(name)  # Group by crate name

    return np.array(X), np.array(y), names, np.array(groups)


def _pick_cv(y: np.ndarray):
    min_class_count = min(np.bincount(y)) if len(y) > 0 else 0
    if min_class_count >= 2:
        n_splits = min(5, min_class_count)
        return StratifiedGroupKFold(
            n_splits=n_splits, shuffle=True, random_state=42
        ), f"StratifiedGroup {n_splits}-Fold CV"
    return LeaveOneOut(), "Leave-One-Out CV"


def bootstrap_metrics(y_true, y_pred, n_bootstraps=1000, random_state=42):
    np.random.seed(random_state)
    n = len(y_true)
    metrics = {"precision": [], "recall": [], "f1": [], "fpr": []}

    for _ in range(n_bootstraps):
        indices = np.random.randint(0, n, n)
        y_t = y_true[indices]
        y_p = y_pred[indices]

        # Avoid zero division when all bootstrap samples are negative
        if sum(y_p) > 0:
            metrics["precision"].append(precision_score(y_t, y_p, zero_division=0))
        if sum(y_t) > 0:
            metrics["recall"].append(recall_score(y_t, y_p, zero_division=0))
            metrics["f1"].append(f1_score(y_t, y_p, zero_division=0))

        tn, fp, fn, tp = confusion_matrix(y_t, y_p, labels=[0, 1]).ravel()
        if (fp + tn) > 0:
            metrics["fpr"].append(fp / (fp + tn))

    res = {}
    for k, v in metrics.items():
        if v:
            res[k] = (np.mean(v), np.percentile(v, 2.5), np.percentile(v, 97.5))
        else:
            res[k] = (0, 0, 0)
    return res


def train_and_evaluate(dataset_path: Path, signals_dir: Path) -> dict:
    X, y, names, groups = _load_dataset(dataset_path, signals_dir)

    if len(np.unique(y)) < 2:
        logger.error("Dataset needs both MALICIOUS and BENIGN examples to train.")
        return {}

    logger.info(
        f"Loaded {len(X)} crates for training ({sum(y)} Malicious, {len(y) - sum(y)} Benign)"
    )

    cv, cv_label = _pick_cv(y)

    param_grid = {
        "n_estimators": [100, 200],
        "max_depth": [None, 6],
        "min_samples_leaf": [1, 2],
    }

    y_pred = np.zeros_like(y)
    best_params_list = []

    # Proper nested CV to prevent data leakage from hyperparameter tuning
    for train_idx, test_idx in cv.split(X, y, groups):
        X_train, y_train, groups_train = X[train_idx], y[train_idx], groups[train_idx]
        X_test = X[test_idx]

        inner_cv_splits = min(3, min(np.bincount(y_train)) if len(y_train) > 0 else 3)
        inner_cv = (
            StratifiedGroupKFold(
                n_splits=inner_cv_splits, shuffle=True, random_state=42
            )
            if inner_cv_splits >= 2
            else 2
        )

        search = GridSearchCV(
            RandomForestClassifier(random_state=42, class_weight="balanced"),
            param_grid,
            scoring="f1",
            cv=inner_cv,
            n_jobs=-1,
        )

        # Suppress warnings if inner_cv splits have no minority class due to tiny datasets
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if inner_cv_splits >= 2:
                search.fit(X_train, y_train, groups=groups_train)
            else:
                search.fit(X_train, y_train)

        best_params_list.append(search.best_params_)

        rf = RandomForestClassifier(
            random_state=42, class_weight="balanced", **search.best_params_
        )
        rf.fit(X_train, y_train)
        y_pred[test_idx] = rf.predict(X_test)

    # Train final model on ALL data
    final_search = GridSearchCV(
        RandomForestClassifier(random_state=42, class_weight="balanced"),
        param_grid,
        scoring="f1",
        cv=cv,
        n_jobs=-1,
    )
    final_search.fit(X, y, groups=groups)
    best_params = final_search.best_params_

    rf = RandomForestClassifier(random_state=42, class_weight="balanced", **best_params)
    rf.fit(X, y)

    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    boot = bootstrap_metrics(y, y_pred)

    print("\n" + "=" * 50)
    print(f"Random Forest Evaluation ({cv_label})")
    print("=" * 50)
    print(f"Best params (final): {best_params}")
    print(
        f"Precision: {precision:.3f} (95% CI: {boot['precision'][1]:.3f}-{boot['precision'][2]:.3f})"
    )
    print(
        f"Recall:    {recall:.3f} (95% CI: {boot['recall'][1]:.3f}-{boot['recall'][2]:.3f})"
    )
    print(f"F1 Score:  {f1:.3f} (95% CI: {boot['f1'][1]:.3f}-{boot['f1'][2]:.3f})")
    print(f"FPR:       {fpr:.3f}")
    print("=" * 50)

    importances = list(zip(FEATURE_NAMES, rf.feature_importances_))
    importances.sort(key=lambda x: x[1], reverse=True)

    print("\nFeature Importances:")
    for name, imp in importances:
        print(f"  {name:15} {imp:.3f}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = RESULTS_DIR / "rf_model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(rf, f)
    print(f"\nSaved trained RF model to {model_path}")

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "best_params": best_params,
        "bootstrap": boot,
    }


def train_and_evaluate_xgb(dataset_path: Path, signals_dir: Path) -> dict:
    X, y, names, groups = _load_dataset(dataset_path, signals_dir)

    if len(np.unique(y)) < 2:
        logger.error("Dataset needs both MALICIOUS and BENIGN examples to train.")
        return {}

    num_pos = sum(y)
    num_neg = len(y) - num_pos
    scale_pos_weight = num_neg / num_pos if num_pos > 0 else 1.0

    cv, cv_label = _pick_cv(y)

    param_grid = {
        "n_estimators": [100, 150],
        "max_depth": [3, 4],
        "learning_rate": [0.05, 0.1],
    }

    y_pred = np.zeros_like(y)
    best_params_list = []

    # Proper nested CV for XGBoost
    for train_idx, test_idx in cv.split(X, y, groups):
        X_train, y_train, groups_train = X[train_idx], y[train_idx], groups[train_idx]
        X_test = X[test_idx]

        inner_cv_splits = min(3, min(np.bincount(y_train)) if len(y_train) > 0 else 3)
        inner_cv = (
            StratifiedGroupKFold(
                n_splits=inner_cv_splits, shuffle=True, random_state=42
            )
            if inner_cv_splits >= 2
            else 2
        )

        search = GridSearchCV(
            xgb.XGBClassifier(
                scale_pos_weight=scale_pos_weight,
                eval_metric="logloss",
                random_state=42,
            ),
            param_grid,
            scoring="f1",
            cv=inner_cv,
            n_jobs=-1,
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if inner_cv_splits >= 2:
                search.fit(X_train, y_train, groups=groups_train)
            else:
                search.fit(X_train, y_train)

        best_params_list.append(search.best_params_)

        model = xgb.XGBClassifier(
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=42,
            **search.best_params_,
        )
        model.fit(X_train, y_train)
        y_pred[test_idx] = model.predict(X_test)

    # Final search on all data
    final_search = GridSearchCV(
        xgb.XGBClassifier(
            scale_pos_weight=scale_pos_weight, eval_metric="logloss", random_state=42
        ),
        param_grid,
        scoring="f1",
        cv=cv,
        n_jobs=-1,
    )
    final_search.fit(X, y, groups=groups)
    best_params = final_search.best_params_

    model = xgb.XGBClassifier(
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=42,
        **best_params,
    )
    model.fit(X, y)

    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    boot = bootstrap_metrics(y, y_pred)

    print("\n" + "=" * 50)
    print(f"XGBoost Evaluation ({cv_label})")
    print("=" * 50)
    print(f"Best params (final): {best_params}")
    print(
        f"Precision: {precision:.3f} (95% CI: {boot['precision'][1]:.3f}-{boot['precision'][2]:.3f})"
    )
    print(
        f"Recall:    {recall:.3f} (95% CI: {boot['recall'][1]:.3f}-{boot['recall'][2]:.3f})"
    )
    print(f"F1 Score:  {f1:.3f} (95% CI: {boot['f1'][1]:.3f}-{boot['f1'][2]:.3f})")
    print(f"FPR:       {fpr:.3f}")
    print("=" * 50)

    importance_dict = model.get_booster().get_score(importance_type="gain")
    importances = [(FEATURE_NAMES[int(k[1:])], v) for k, v in importance_dict.items()]
    importances.sort(key=lambda x: x[1], reverse=True)

    print("\nXGBoost Feature Importances (Gain):")
    for name, imp in importances:
        print(f"  {name:15} {imp:.3f}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = RESULTS_DIR / "xgb_model.json"
    # Native JSON format is preferred for XGBoost over pickle for cross-language compatibility,
    # forward compatibility, and safer loading (no arbitrary code execution risk).
    model.save_model(model_path)
    print(f"\nSaved trained XGBoost model to {model_path}")

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "best_params": best_params,
        "bootstrap": boot,
    }


def compare_models(dataset_path: Path, signals_dir: Path) -> None:
    print("Training Random Forest...")
    rf_metrics = train_and_evaluate(dataset_path, signals_dir)
    print("\nTraining XGBoost...")
    xgb_metrics = train_and_evaluate_xgb(dataset_path, signals_dir)

    if not rf_metrics or not xgb_metrics:
        return

    print("\n" + "=" * 60)
    print(
        f"{'Model':<15} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'FPR':<10}"
    )
    print("-" * 60)
    print(
        f"{'Random Forest':<15} | {rf_metrics['precision']:<10.3f} | {rf_metrics['recall']:<10.3f} | {rf_metrics['f1']:<10.3f} | {rf_metrics['fpr']:<10.3f}"
    )
    print(
        f"{'XGBoost':<15} | {xgb_metrics['precision']:<10.3f} | {xgb_metrics['recall']:<10.3f} | {xgb_metrics['f1']:<10.3f} | {xgb_metrics['fpr']:<10.3f}"
    )
    print("=" * 60)


def predict_crate(name: str, version: str) -> None:
    from crateshield.pipeline import extract_only

    model_path = RESULTS_DIR / "rf_model.pkl"
    if not model_path.exists():
        print("Error: RF Model not found.")
        return

    with open(model_path, "rb") as f:
        rf = pickle.load(f)

    signal = extract_only(name, version)
    features = extract_features(signal)
    prediction = rf.predict([features])[0]
    label = "MALICIOUS" if prediction == 1 else "BENIGN"

    print("\n" + "=" * 40)
    print(f"RF Prediction for {name}@{version}: {label}")
    print("=" * 40)


def predict_crate_xgb(name: str, version: str) -> None:
    from crateshield.pipeline import extract_only

    model_path = RESULTS_DIR / "xgb_model.json"
    if not model_path.exists():
        print("Error: XGBoost Model not found.")
        return

    model = xgb.XGBClassifier()
    model.load_model(model_path)

    signal = extract_only(name, version)
    features = extract_features(signal)
    # XGBoost expects a 2D array and is sensitive to column names in some configurations,
    # but basic numpy arrays work fine.
    X_pred = np.array([features])
    prediction = model.predict(X_pred)[0]
    prob = model.predict_proba(X_pred)[0][1]

    label = "MALICIOUS" if prediction == 1 else "BENIGN"

    print("\n" + "=" * 40)
    print(f"XGBoost Prediction for {name}@{version}: {label} (Probability: {prob:.3f})")
    print("=" * 40)
    print("\nFeature values extracted:")
    for fn, val in zip(FEATURE_NAMES, features):
        print(f"  {fn:15}: {val}")


SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_severity_dataset(dataset_path: Path, signals_dir: Path) -> pd.DataFrame:
    from crateshield.evaluation.risk import _rule_based_score, _risk_level

    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))

    rows = []
    for crate in dataset.get("crates", []):
        name = crate["name"]
        version = crate.get("version", "0.1.0")
        label = crate["label"]

        if version == "yanked" or not version:
            continue

        signal_file = signals_dir / f"{name}-{version}.json"
        if not signal_file.exists():
            continue

        signal = json.loads(signal_file.read_text(encoding="utf-8"))
        features = extract_features(signal)

        # Compute existing rule-based score and severity
        rule_score, _ = _rule_based_score(signal)
        severity = _risk_level(rule_score)

        row = {
            "name": name,
            "version": version,
            "binary_label": label,
            "severity": severity,
        }

        for fname, fval in zip(FEATURE_NAMES, features):
            row[fname] = fval

        rows.append(row)

    df = pd.DataFrame(rows)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "severity_dataset.csv"

    # Presentable column order: metadata, severity, binary, then features
    cols = ["name", "version", "severity", "binary_label"] + FEATURE_NAMES
    df = df[cols]
    df.to_csv(out_path, index=False)

    print(f"Wrote {len(df)} rows to {out_path}")
    print("\nClass Balance (Severity):")
    print(df["severity"].value_counts())

    return df


def train_severity_xgb(dataset_path: Path, signals_dir: Path) -> dict:
    df = build_severity_dataset(dataset_path, signals_dir)

    X = df[FEATURE_NAMES].values

    # Map string severities to integers [0, 1, 2, 3]
    sev_map = {k: i for i, k in enumerate(SEVERITY_LEVELS)}
    y = df["severity"].map(sev_map).values
    groups = df["name"].values

    min_class_count = np.bincount(y).min()

    from sklearn.model_selection import LeaveOneOut, StratifiedGroupKFold

    if min_class_count >= 2:
        n_splits = min(5, min_class_count)
        cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
        print(
            f"\nUsing StratifiedGroupKFold with n_splits={n_splits} (limited by minority class size of {min_class_count})"
        )
    else:
        cv = LeaveOneOut()
        print(
            f"\nUsing Leave-One-Out CV because minority class size is {min_class_count} (< 2), making stratification impossible."
        )

    model = xgb.XGBClassifier(
        objective="multi:softmax",
        num_class=4,
        n_estimators=100,
        max_depth=3,
        eval_metric="mlogloss",
        random_state=42,
    )
    y_pred = np.zeros_like(y)

    for train_idx, test_idx in cv.split(
        X,
        y if min_class_count >= 2 else None,
        groups=groups if min_class_count >= 2 else None,
    ):
        model.fit(X[train_idx], y[train_idx])
        y_pred[test_idx] = model.predict(X[test_idx])

    model.fit(X, y)

    # Per-class metrics (use explicit labels so arrays are always length 4 even if HIGH/CRITICAL are missing)
    precision = precision_score(
        y, y_pred, labels=[0, 1, 2, 3], average=None, zero_division=0
    )
    recall = recall_score(y, y_pred, labels=[0, 1, 2, 3], average=None, zero_division=0)
    f1 = f1_score(y, y_pred, labels=[0, 1, 2, 3], average=None, zero_division=0)
    cm = confusion_matrix(y, y_pred, labels=[0, 1, 2, 3])

    print("\n" + "=" * 60)
    print("XGBoost Multiclass Severity Evaluation")
    print("=" * 60)
    print(f"{'Severity':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10}")
    print("-" * 60)
    for i, sev in enumerate(SEVERITY_LEVELS):
        print(
            f"{sev:<10} | {precision[i]:<10.3f} | {recall[i]:<10.3f} | {f1[i]:<10.3f}"
        )
    print("=" * 60)
    print("\nConfusion Matrix (Rows=True, Cols=Pred, Order=LOW,MED,HIGH,CRIT):")
    print(cm)

    try:
        importance_dict = model.get_booster().get_score(importance_type="gain")
        importances = [
            (FEATURE_NAMES[int(k[1:])], v) for k, v in importance_dict.items()
        ]
        importances.sort(key=lambda x: x[1], reverse=True)
        print("\nXGBoost Feature Importances (Gain - Overall):")
        for name, imp in importances:
            print(f"  {name:15} {imp:.3f}")
    except Exception as e:
        print("\nCould not extract gain importances:", e)

    model_path = RESULTS_DIR / "xgb_severity_model.json"
    model.save_model(model_path)
    print(f"\nSaved trained XGBoost severity model to {model_path}")

    return {
        "precision": precision.tolist(),
        "recall": recall.tolist(),
        "f1": f1.tolist(),
    }


def predict_severity(name: str, version: str) -> dict:
    from crateshield.pipeline import extract_only

    model_path = RESULTS_DIR / "xgb_severity_model.json"
    if not model_path.exists():
        print("Error: XGBoost Severity Model not found.")
        return {}

    model = xgb.XGBClassifier()
    model.load_model(model_path)

    signal = extract_only(name, version)
    features = extract_features(signal)

    X_pred = np.array([features])
    pred_idx = int(model.predict(X_pred)[0])
    probs = model.predict_proba(X_pred)[0]

    pred_severity = SEVERITY_LEVELS[pred_idx]

    print("\n" + "=" * 50)
    print(f"Severity Prediction for {name}@{version}: {pred_severity}")
    print("=" * 50)
    print("\nClass Probabilities:")
    for sev, p in zip(SEVERITY_LEVELS, probs):
        print(f"  {sev:<10}: {p:.3f}")

    return {"severity": pred_severity, "probabilities": probs.tolist()}
