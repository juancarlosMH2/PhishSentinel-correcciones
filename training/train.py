"""Entrena y guarda el modelo de la capa 1 en models/model_url.joblib.

Pasos:
  1. Compara 5 algoritmos con una muestra (por defecto 20,000 filas de entrenamiento; SVM y KNN no
     escalan a todo el set). La comparación se mide en VALIDACIÓN, no en prueba.
  2. Reentrena Random Forest y XGBoost con TODO el entrenamiento y elige el mejor por F1 en validación.
  3. Calibra los umbrales T_LOW / T_HIGH de la zona de duda con datos de validación aparte
     (validación real + bloque Tranco 15,001-20,000, que nunca se usa para entrenar).
  4. Guarda el modelo + umbrales. La evaluación final (con datos NO usados) es `training.evaluate`.

Uso:  python -m training.train                       (multiclase, 4 clases)
      python -m training.train --compare-rows 8000   (más rápido)
      python -m training.train --mode binary
"""
import argparse
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import GroupKFold, cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from phishsentinel.features_url import FEATURE_NAMES
from phishsentinel.model import UrlClassifier, make_hasher, text_of
from training.common import CLASSES, featurize, load_split, seen_domains, synthetic_long_legit, tranco_block

try:
    from xgboost import XGBClassifier
except ImportError:                                  # pragma: no cover
    XGBClassifier = None

FPR_HIGH_TARGET = 0.005     # T_HIGH: por encima, bloquea directo. Máx. 0.5% de legítimas de validación
RECALL_LOW_TARGET = 0.985   # T_LOW: por debajo, deja pasar. Máx. 1.5% de maliciosas de validación


def xgb(n=300, max_depth=7, lr=0.1, mcw=1, subsample=0.8, colsample=0.8, lam=1.0):
    return XGBClassifier(n_estimators=n, max_depth=max_depth, learning_rate=lr, min_child_weight=mcw,
                         subsample=subsample, colsample_bytree=colsample, reg_lambda=lam,
                         tree_method="hist", n_jobs=-1, random_state=42)


# Búsqueda pequeña (1 CPU): se elige por F1 macro en VALIDACIÓN, nunca en prueba.
TUNE_GRID = [
    dict(n=250, max_depth=6, lr=0.1, mcw=1),
    dict(n=250, max_depth=8, lr=0.1, mcw=3),
    dict(n=250, max_depth=10, lr=0.1, mcw=5, lam=3.0),
    dict(n=400, max_depth=7, lr=0.05, mcw=3, subsample=0.7, colsample=0.6),
    dict(n=300, max_depth=9, lr=0.08, mcw=5, subsample=0.7, colsample=0.7, lam=5.0),
]
PROTECTED_SOURCES = {"tranco_train", "synth_long_legit", "xss_synth"}     # generadas por nosotros: no se "limpian"


def find_noisy(X, y, df_train, n_splits=4, p_true_max=0.03, p_pred_min=0.97):
    """Etiquetas dudosas: filas REALES que un modelo entrenado en OTROS dominios clasifica con muchísima
    seguridad en otra clase. Solo se limpia el entrenamiento; validación y prueba quedan intactas."""
    oof = np.zeros((len(X), len(np.unique(y))), np.float32)
    for a, b in GroupKFold(n_splits).split(X, y, df_train["group"].values):
        oof[b] = xgb(120).fit(X[a], y[a]).predict_proba(X[b])
    p_true = oof[np.arange(len(y)), y]
    noisy = (p_true < p_true_max) & (oof.max(1) > p_pred_min) & (~df_train["source"].isin(PROTECTED_SOURCES).values)
    return noisy, oof


def small_models():
    m = {
        "RandomForest": RandomForestClassifier(n_estimators=200, min_samples_leaf=2, n_jobs=-1, random_state=42),
        "SVM": make_pipeline(StandardScaler(), SVC(probability=True, random_state=42)),
        "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5)),
        "LogReg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
    }
    if XGBClassifier:
        m["XGBoost"] = xgb(200)
    return m


def full_models():
    m = {"RandomForest": RandomForestClassifier(n_estimators=80, min_samples_leaf=8, max_features="sqrt",
                                                max_samples=0.5, n_jobs=-1, random_state=42)}
    if XGBClassifier:
        m["XGBoost"] = xgb(300, max_depth=8, mcw=3)
    return m


def metrics(y, pred, legit, n_classes):
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="macro", zero_division=0)
    cm = confusion_matrix(y, pred, labels=range(n_classes))
    fpr = (cm[legit].sum() - cm[legit, legit]) / max(cm[legit].sum(), 1)
    return dict(accuracy=accuracy_score(y, pred), precision=p, recall=r, f1=f1, falsos_positivos=fpr)


def text_stack(df, y, tr, n_splits=5):
    """Modelo de n-gramas + sus probabilidades FUERA DE MUESTRA para las filas de entrenamiento
    (GroupKFold por dominio). Val/test reciben las del modelo final, igual que en producción."""
    hv = make_hasher()
    H = hv.transform([text_of(u) for u in df["url"]])
    new = lambda: SGDClassifier(loss="log_loss", alpha=2e-6, max_iter=15, tol=None, random_state=0)
    idx = np.where(tr)[0]
    oof = np.zeros((len(df), len(set(y))), np.float32)
    for a, b in GroupKFold(n_splits).split(idx, y[idx], df["group"].values[idx]):
        oof[idx[b]] = new().fit(H[idx[a]], y[idx[a]]).predict_proba(H[idx[b]])
    final = new().fit(H[idx], y[idx])
    rest = np.where(~tr)[0]
    oof[rest] = final.predict_proba(H[rest])
    return hv, final, oof


def choose_thresholds(p_legit_rows, p_mal_rows):
    """p_* = probabilidad de ser maliciosa (1 - P(legítima)) en validación."""
    high = float(np.quantile(p_legit_rows, 1 - FPR_HIGH_TARGET))       # FPR(p >= high) ~ objetivo
    low = float(np.quantile(p_mal_rows, 1 - RECALL_LOW_TARGET))        # recall(p >= low) ~ objetivo
    low = min(low, high)
    return round(low, 4), round(high, 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/urls.csv")
    ap.add_argument("--mode", choices=["binary", "multiclass"], default="multiclass")
    ap.add_argument("--compare-rows", type=int, default=20000)
    ap.add_argument("--cv", type=int, default=3)
    ap.add_argument("--skip-compare", action="store_true")
    ap.add_argument("--clean", action="store_true", help="quita etiquetas dudosas del ENTRENAMIENTO")
    ap.add_argument("--tune", action="store_true", help="busca hiperparámetros de XGBoost (validación)")
    a = ap.parse_args()

    t0 = time.perf_counter()
    df, X, y = load_split(a.data)
    ms_feat = (time.perf_counter() - t0) / len(df) * 1000
    classes = list(CLASSES)
    if a.mode == "binary":
        y = np.where(y == classes.index("legitimate"), 0, 1)
        classes = ["legitimate", "malicious"]
    legit = classes.index("legitimate")
    tr, va = (df["split"] == "train").values, (df["split"] == "val").values
    t1 = time.perf_counter()
    hv, text_clf, text_p = text_stack(df, y, tr)
    print(f"modelo de n-gramas (stacking, fuera de muestra por dominio): {time.perf_counter() - t1:.0f} s")
    X = np.hstack([X, text_p])                      # 60 numéricas + 4 probabilidades del texto
    Xtr, ytr, Xva, yva = X[tr], y[tr], X[va], y[va]
    print(f"train {tr.sum()} · val {va.sum()} · test {(df['split'] == 'test').sum()} (test NO se toca aquí)")
    Path("models").mkdir(exist_ok=True)

    # ---------- 0. limpieza de etiquetas dudosas (solo entrenamiento) ----------
    if a.clean:
        t2 = time.perf_counter()
        dtr = df[tr].reset_index(drop=True)
        noisy, _ = find_noisy(Xtr, ytr, dtr)
        print(f"\nEtiquetas dudosas detectadas: {noisy.sum()} de {len(noisy)} "
              f"({noisy.mean():.2%}) en {time.perf_counter() - t2:.0f} s")
        print(pd.crosstab(dtr.loc[noisy, "label"], dtr.loc[noisy, "source"]).to_string())
        dtr.loc[noisy, ["url", "label", "source", "group"]].head(3000).to_csv("models/etiquetas_dudosas.csv", index=False)
        Xtr, ytr = Xtr[~noisy], ytr[~noisy]

    # ---------- 1. comparación de 5 algoritmos (muestra) ----------
    if not a.skip_compare:
        rng = np.random.RandomState(42)
        idx = rng.choice(len(Xtr), min(a.compare_rows, len(Xtr)), replace=False)
        rows = []
        for name, clf in small_models().items():
            print(f"== {name} ({len(idx)} filas)", flush=True)
            cv = cross_val_score(clf, Xtr[idx], ytr[idx], cv=a.cv, scoring="f1_macro").mean()
            clf.fit(Xtr[idx], ytr[idx])
            t = time.perf_counter()
            pred = clf.predict(Xva)
            ms_pred = (time.perf_counter() - t) / len(Xva) * 1000
            rows.append({"modelo": name, "cv_f1": cv, **metrics(yva, pred, legit, len(classes)), "ms_prediccion": ms_pred})
        res = pd.DataFrame(rows).sort_values("f1", ascending=False)
        res.to_csv("models/resultados.csv", index=False)
        print("\nComparación (muestra, medida en VALIDACIÓN):\n", res.round(4).to_string(index=False), flush=True)

    # ---------- 2. modelo final con todo el entrenamiento ----------
    best, rows = (None, -1.0, None), []
    models = full_models()
    if a.tune and XGBClassifier:
        models = {}
        tune_rows = []
        for i, params in enumerate(TUNE_GRID):
            t3 = time.perf_counter()
            clf = xgb(**params).fit(Xtr, ytr)
            m = metrics(yva, clf.predict(Xva), legit, len(classes))
            tune_rows.append({"config": i, **params, **m, "segundos": time.perf_counter() - t3})
            print(f"  config {i}: F1 val {m['f1']:.4f} ({time.perf_counter() - t3:.0f} s) {params}", flush=True)
            models[f"XGBoost[{i}]"] = clf
        pd.DataFrame(tune_rows).sort_values("f1", ascending=False).to_csv("models/ajuste_hiperparametros.csv", index=False)
    for name, clf in (models.items() if a.tune else full_models().items()):
        print(f"== {name} (entrenamiento completo: {len(Xtr)} filas)", flush=True)
        if not a.tune:
            clf.fit(Xtr, ytr)
        t = time.perf_counter()
        pred = clf.predict(Xva)
        ms_pred = (time.perf_counter() - t) / len(Xva) * 1000
        m = metrics(yva, pred, legit, len(classes))
        rows.append({"modelo": name, **m, "ms_prediccion": ms_pred})
        if m["f1"] > best[1]:
            best = (name, m["f1"], clf)
    pd.DataFrame(rows).sort_values("f1", ascending=False).to_csv("models/resultados_completo.csv", index=False)
    print("\nEntrenamiento completo (VALIDACIÓN):\n", pd.DataFrame(rows).round(4).to_string(index=False), flush=True)
    name, _, clf = best

    # ---------- 3. umbrales de la zona de duda ----------
    seen = seen_domains(df)
    tr_val = [d for d in tranco_block("val") if d not in seen]
    extra_legit = [f"https://{d}/" for d in tr_val] + synthetic_long_legit(tr_val, 3000, seed=99)
    Xl_extra = np.hstack([featurize(extra_legit),
                          text_clf.predict_proba(hv.transform([text_of(u) for u in extra_legit]))])
    legit_rows = np.vstack([Xva[yva == legit], Xl_extra])
    mal_rows = Xva[yva != legit]
    p_leg = 1.0 - clf.predict_proba(legit_rows)[:, legit]
    p_mal = 1.0 - clf.predict_proba(mal_rows)[:, legit]
    low, high = choose_thresholds(p_leg, p_mal)
    print(f"\nUmbrales calibrados en validación: T_LOW={low}  T_HIGH={high}")
    print(f"  legítimas usadas: {len(legit_rows)} (incl. {len(tr_val)} dominios Tranco no vistos + 3000 URLs largas)")
    print(f"  maliciosas usadas: {len(mal_rows)}")
    print(f"  FPR con p>=T_LOW: {(p_leg >= low).mean():.2%} · recall con p>=T_LOW: {(p_mal >= low).mean():.2%}")
    print(f"  FPR con p>=T_HIGH: {(p_leg >= high).mean():.2%} · recall con p>=T_HIGH: {(p_mal >= high).mean():.2%}")

    model = UrlClassifier(hv, text_clf, clf, classes)
    joblib.dump({"model": model, "classes": classes, "features": model.feature_names, "name": name,
                 "thresholds": {"low": low, "high": high}, "version": 2,
                 "trained_rows": int(len(Xtr)), "ms_features": ms_feat},
                "models/model_url.joblib", compress=3)
    print(f"\nGuardado models/model_url.joblib ({name}, {Path('models/model_url.joblib').stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
