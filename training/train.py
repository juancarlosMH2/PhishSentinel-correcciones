"""Compara 5 algoritmos y guarda el mejor en models/model_url.joblib.
Uso:  python -m training.train --mode multiclass --max-rows 60000"""
import argparse
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from phishsentinel.features_url import FEATURE_NAMES, extract_url_features, to_vector

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None


def build_models():
    m = {
        "RandomForest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42),
        "SVM": make_pipeline(StandardScaler(), SVC(probability=True, random_state=42)),
        "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5)),
        "LogReg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    }
    if XGBClassifier:
        # parámetros elegidos con validación cruzada (3 folds) sobre urls.csv completo
        m["XGBoost"] = XGBClassifier(n_estimators=600, max_depth=8, learning_rate=0.1, subsample=0.9,
                                     colsample_bytree=0.8, n_jobs=-1, random_state=42)
    return m


def to_portable(bundle):
    """Guarda un XGBoost en su formato nativo (UBJSON) en vez de pickle: así carga igual en
    Windows, Linux y con otra versión de Python (ver phishsentinel/engine.py: load_bundle)."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "model.ubj"
        bundle["model"].save_model(f)
        raw = f.read_bytes()
    return {**bundle, "model": None, "xgb_model": raw}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/urls.csv")
    ap.add_argument("--mode", choices=["binary", "multiclass"], default="multiclass")
    ap.add_argument("--max-rows", type=int, default=60000)    # SVM y KNN son lentos: baja esto para pruebas
    ap.add_argument("--cv", type=int, default=3)
    ap.add_argument("--models", default="",
                    help="lista separada por comas (p. ej. RandomForest,XGBoost); vacío = todos")
    a = ap.parse_args()

    df = pd.read_csv(a.data).dropna()
    if a.mode == "binary":
        df["label"] = df["label"].replace({"phishing": "malicious", "xss": "malicious"})
    if len(df) > a.max_rows:
        df = df.sample(a.max_rows, random_state=42)

    t0 = time.perf_counter()
    X = np.array([to_vector(extract_url_features(u)) for u in df["url"]])
    ms_feat = (time.perf_counter() - t0) / len(df) * 1000
    classes = sorted(df["label"].unique())
    y = df["label"].map({c: i for i, c in enumerate(classes)}).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    legit = classes.index("legitimate")

    rows, best = [], (None, -1.0, None)
    wanted = [m.strip() for m in a.models.split(",") if m.strip()]
    for name, clf in build_models().items():
        if wanted and name not in wanted:
            continue
        print(f"== {name}")
        cv = cross_val_score(clf, Xtr, ytr, cv=a.cv, scoring="f1_macro").mean()
        clf.fit(Xtr, ytr)
        t = time.perf_counter()
        pred = clf.predict(Xte)
        ms_pred = (time.perf_counter() - t) / len(Xte) * 1000
        p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="macro", zero_division=0)
        cm = confusion_matrix(yte, pred, labels=range(len(classes)))
        fpr = (cm[legit].sum() - cm[legit, legit]) / max(cm[legit].sum(), 1)   # legítimas marcadas como maliciosas
        rows.append({"modelo": name, "cv_f1": cv, "accuracy": accuracy_score(yte, pred), "precision": p,
                     "recall": r, "f1": f1, "falsos_positivos": fpr, "ms_prediccion": ms_pred})
        if cv > best[1]:                 # se elige con validación cruzada, NO con el conjunto de prueba
            best = (name, cv, clf)

    res = pd.DataFrame(rows).sort_values("cv_f1", ascending=False)
    Path("models").mkdir(exist_ok=True)
    mode = "binario" if a.mode == "binary" else "multiclase"
    res.to_csv(f"models/resultados_{mode}.csv", index=False)
    print(res.round(4).to_string(index=False))
    print(f"\nExtracción de características: {ms_feat:.2f} ms/URL · mejor modelo (por cv_f1): {best[0]}")
    bundle = {"model": best[2], "classes": classes, "features": FEATURE_NAMES, "name": best[0]}
    if XGBClassifier and isinstance(best[2], XGBClassifier):
        bundle = to_portable(bundle)
    joblib.dump(bundle, f"models/model_{mode}.joblib")
    if a.mode == "multiclass":            # la app usa el multiclase: así resultados.csv siempre es del modelo en uso
        joblib.dump(bundle, "models/model_url.joblib")
        res.to_csv("models/resultados.csv", index=False)


if __name__ == "__main__":
    main()
