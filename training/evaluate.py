"""Evaluación final de la capa 1 sobre datos que el modelo NO vio. Un solo comando:

    python -m training.evaluate

Escribe models/evaluacion_final.md y .json con:
  1. Partición de prueba (dominios distintos a los de entrenamiento): F1 por clase y matriz de confusión.
  2. Tranco 20,001-30,000 (fuente distinta, dominios solo-raíz): falsos positivos, todos y "no vistos".
  3. URLs legítimas LARGAS reales (>=100 caracteres) de dominios no vistos.
  4. URLs largas sintéticas sobre dominios Tranco de prueba (optimista: son plantillas).
  5. Recall por tipo: phishing (con ruta / solo dominio), malware, XSS.
  6. Zona de duda: qué porcentaje de URLs obliga a consultar la capa 2.
Todas las cifras usan los umbrales calibrados T_LOW / T_HIGH del modelo (guardados en el .joblib).
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from phishsentinel.features_url import FEATURE_NAMES
from training.common import (CLASSES, featurize, load_split, seen_domains, synthetic_long_legit,
                             tranco_block)

OUT = Path("models")
I_TAG, I_EVT = FEATURE_NAMES.index("xss_tag"), FEATURE_NAMES.index("xss_event")


def layer1_p_mal(model, classes, urls, numeric):
    """Misma lógica que Engine._url_proba (incluida la regla de inyección evidente)."""
    P = model.predict_proba(urls, numeric=numeric)
    p = 1.0 - P[:, classes.index("legitimate")]
    inj = (numeric[:, I_TAG] > 0) | (numeric[:, I_EVT] > 0)
    return np.where(inj, np.maximum(p, 0.85), p), P


def rates(p, low, high):
    return {"n": int(len(p)), "pasa_directo(p<T_LOW)": float((p < low).mean()),
            "zona_duda": float(((p >= low) & (p < high)).mean()),
            "bloqueo_directo(p>=T_HIGH)": float((p >= high).mean()),
            "marcada_con_umbral_0.5": float((p >= 0.5).mean())}


def pct(x):
    return f"{x:.2%}"


def main():
    b = joblib.load("models/model_url.joblib")
    model, classes = b["model"], b["classes"]
    low, high = b["thresholds"]["low"], b["thresholds"]["high"]
    df, X, y = load_split()
    te = (df["split"] == "test").values
    res, md = {"umbrales": {"T_LOW": low, "T_HIGH": high}, "modelo": b["name"]}, []
    md.append(f"# Evaluación final — modelo {b['name']} (v{b.get('version', '?')})\n")
    md.append(f"Umbrales calibrados en validación: **T_LOW={low}**, **T_HIGH={high}**. "
              f"Entrenado con {b.get('trained_rows')} URLs.\n")

    # ---------- 1. partición de prueba ----------
    dte = df[te].reset_index(drop=True)
    p, P = layer1_p_mal(model, classes, dte["url"].tolist(), X[te][:, :len(FEATURE_NAMES)])
    pred = P.argmax(1)
    yt = y[te]
    rep = classification_report(yt, pred, target_names=classes, digits=4, output_dict=True)
    cm = confusion_matrix(yt, pred)
    f1m = f1_score(yt, pred, average="macro")
    leg = classes.index("legitimate")
    fpr_arg = (cm[leg].sum() - cm[leg, leg]) / cm[leg].sum()
    res["prueba"] = {"f1_macro": f1m, "falsos_positivos_argmax": fpr_arg, "por_clase": rep}
    md.append("## 1. Partición de prueba (dominios que NO se usaron para entrenar)\n")
    md.append(f"F1 macro **{f1m:.4f}** · falsos positivos (argmax) {pct(fpr_arg)}\n")
    md.append("| clase | precisión | recall | F1 | n |\n|---|---|---|---|---|")
    for c in classes:
        r = rep[c]
        md.append(f"| {c} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1-score']:.3f} | {int(r['support'])} |")
    md.append("\nMatriz de confusión (filas = real, columnas = predicho): " + str(classes))
    md.append("```\n" + str(cm) + "\n```\n")

    # ---------- 2. Tranco 20,001-30,000 ----------
    seen = seen_domains(df)
    tr_all = tranco_block("test")
    tr_unseen = [d for d in tr_all if d not in seen]
    md.append("## 2. Tranco 20,001–30,000 (fuente distinta; solo dominios raíz)\n")
    md.append("| conjunto | n | pasa directo | zona de duda | bloqueo directo | marcada con 0.5 |\n|---|---|---|---|---|---|")
    for name, doms in (("todos", tr_all), ("no vistos en entrenamiento", tr_unseen)):
        urls = [f"https://{d}/" for d in doms]
        pp, _ = layer1_p_mal(model, classes, urls, featurize(urls))
        r = rates(pp, low, high)
        res[f"tranco_{name}"] = r
        md.append(f"| {name} | {r['n']} | {pct(r['pasa_directo(p<T_LOW)'])} | {pct(r['zona_duda'])} | "
                  f"{pct(r['bloqueo_directo(p>=T_HIGH)'])} | {pct(r['marcada_con_umbral_0.5'])} |")
    md.append("\nFalso positivo **sin capa 2** = 'bloqueo directo'. La zona de duda se resuelve con la capa 2 "
              "(descarga del HTML); su efecto real depende del sitio y debe medirse con "
              "`python -m training.tranco_layer2_test`.\n")

    # ---------- 3 y 4. URLs largas ----------
    md.append("## 3. URLs largas legítimas\n")
    md.append("| conjunto | n | pasa directo | zona de duda | bloqueo directo | marcada con 0.5 |\n|---|---|---|---|---|---|")
    leg_te = dte[(dte["label"] == "legitimate")]
    real_long = leg_te[leg_te["url"].str.replace(r"^https?://(www\.)?", "", regex=True).str.len() >= 100]
    sets = {"REALES >=100 car. (dominios no vistos)": real_long["url"].tolist(),
            "sintéticas sobre Tranco de prueba (optimista)": synthetic_long_legit(tr_unseen or tr_all, 3000, seed=2026)}
    for name, urls in sets.items():
        pp, _ = layer1_p_mal(model, classes, urls, featurize(urls))
        r = rates(pp, low, high)
        res[f"largas_{name}"] = r
        md.append(f"| {name} | {r['n']} | {pct(r['pasa_directo(p<T_LOW)'])} | {pct(r['zona_duda'])} | "
                  f"{pct(r['bloqueo_directo(p>=T_HIGH)'])} | {pct(r['marcada_con_umbral_0.5'])} |")
    short_leg = leg_te[~leg_te["url"].isin(real_long["url"])]
    pp, _ = layer1_p_mal(model, classes, short_leg["url"].tolist(), featurize(short_leg["url"]))
    r = rates(pp, low, high)
    res["legitimas_cortas_prueba"] = r
    md.append(f"| legítimas reales <100 car. (referencia) | {r['n']} | {pct(r['pasa_directo(p<T_LOW)'])} | "
              f"{pct(r['zona_duda'])} | {pct(r['bloqueo_directo(p>=T_HIGH)'])} | {pct(r['marcada_con_umbral_0.5'])} |\n")

    # ---------- 5. recall por tipo ----------
    md.append("## 4. Recall en amenazas de dominios no vistos\n")
    md.append("| tipo | n | pasa directo (se escapa sin capa 2) | zona de duda | bloqueo directo |\n|---|---|---|---|---|")
    bare_re = r"^https?://(www\.)?[^/?#]+/?$|^(?!https?://)(www\.)?[^/?#]+/?$"
    groups = {}
    for lab in ("phishing", "malware", "xss"):
        d = dte[dte["label"] == lab]
        is_bare = d["url"].str.match(bare_re)
        if lab == "phishing":
            groups["phishing con ruta"] = d[~is_bare]["url"].tolist()
            groups["phishing solo dominio"] = d[is_bare]["url"].tolist()
            for src in d["source"].unique():
                groups[f"phishing fuente {src}"] = d[d["source"] == src]["url"].tolist()
        else:
            groups[lab] = d["url"].tolist()
    for name, urls in groups.items():
        if not urls:
            continue
        pp, _ = layer1_p_mal(model, classes, urls, featurize(urls))
        r = rates(pp, low, high)
        res[f"recall_{name}"] = r
        md.append(f"| {name} | {r['n']} | {pct(r['pasa_directo(p<T_LOW)'])} | {pct(r['zona_duda'])} | "
                  f"{pct(r['bloqueo_directo(p>=T_HIGH)'])} |")
    md.append("\n'Pasa directo' = amenazas que la capa 1 deja pasar **sin** consultar la capa 2 (el hueco real del sistema).\n")

    (OUT / "evaluacion_final.md").write_text("\n".join(md), encoding="utf-8")
    (OUT / "evaluacion_final.json").write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    print("\n".join(md))
    print("\nGuardado en models/evaluacion_final.md y .json")


if __name__ == "__main__":
    main()
