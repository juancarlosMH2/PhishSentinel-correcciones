"""Generalización de XSS entre fuentes de payloads: entrena con una fuente y prueba con la otra.
Solo características numéricas (sin n-gramas), para medir si lo aprendido es estructural.
Uso:  python -m training.cross_source_test"""
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score

from phishsentinel.features_url import extract_url_features, to_vector
from training.synth import PARAMS, make_xss_urls

RAW = Path("data/raw")
N_PER_CLASS = 15_000


def payloads(kind):
    pays = []
    for p in sorted(RAW.iterdir()):
        n = p.name.lower()
        if "xss" not in n:
            continue
        if kind == "csv" and n.endswith(".csv"):
            d = pd.read_csv(p)
            col = "Sentence" if "Sentence" in d else d.columns[0]
            pays += d[d["Label"] == 1][col].dropna().astype(str).tolist() if "Label" in d else d[col].dropna().astype(str).tolist()
        if kind == "txt" and n.endswith(".txt"):
            pays += [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(pays))


def build(pays, legit, n, r):
    xss = make_xss_urls(pays, legit, n, r)
    leg = [r.choice(legit).split("?")[0] + f"?{r.choice(PARAMS)}={r.choice(['zapatos', 'libros', 'clima', 'python'])}"
           for _ in range(n)]
    X = np.array([to_vector(extract_url_features(u)) for u in xss + leg], dtype=np.float32)
    return X, np.array(["xss"] * len(xss) + ["legitimate"] * len(leg))


def main():
    r = random.Random(7)
    legit = pd.read_csv(RAW / "URL dataset.csv", usecols=["url", "type"])
    legit = legit[legit["type"] == "legitimate"]["url"].drop_duplicates().tolist()
    txt, csv = payloads("txt"), payloads("csv")
    print(f"payloads .txt: {len(txt)} | payloads .csv: {len(csv)}")
    for name, a, b in (("A: txt -> csv", txt, csv), ("B: csv -> txt", csv, txt)):
        Xtr, ytr = build(a, legit, N_PER_CLASS, r)
        Xte, yte = build(b, legit, N_PER_CLASS, r)
        clf = RandomForestClassifier(n_estimators=150, n_jobs=-1, random_state=42).fit(Xtr, ytr)
        pred = clf.predict(Xte)
        print(f"\n=== {name} ===\n{classification_report(yte, pred, digits=4)}F1 macro: {f1_score(yte, pred, average='macro'):.4f}")


if __name__ == "__main__":
    main()
