"""Falsos positivos de la capa 1 en URLs legítimas LARGAS (ruta y parámetros).
Usa dos conjuntos que no entran al entrenamiento:
  1. data/eval/urls_largas_legitimas.txt: patrones reales escritos a mano (Google, YouTube, OAuth, etc.).
  2. URLs legítimas de 'URL dataset.csv' con 100 o más caracteres que no quedaron en urls.csv.
Uso:  python -m training.long_url_fp_test --n 2000"""
import argparse
import random
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine
from phishsentinel.features_url import normalize_url

RAW = Path("data/raw")
CURATED = Path("data/eval/urls_largas_legitimas.txt")
PROCESSED = Path("data/processed/urls.csv")
MIN_LEN = 100


def evaluate(eng, urls, title, show=0, label="Falsos positivos"):
    lv, flagged = Counter(), []
    for u in urls:
        v = eng.analyze(u, fetch=False, log=False)
        lv[v.level] += 1
        if v.level != "segura":
            flagged.append((v.score, u))
    n = len(urls)
    fp = (n - lv["segura"]) / max(n, 1)
    print(f"\n== {title} ({n} URLs)")
    for k in ["segura", "sospechosa", "peligrosa"]:
        print(f"{k:>10}: {lv[k]:>5} ({lv[k] / max(n, 1):.2%})")
    print(f"{label} (no segura): {fp:.2%}")
    for s, u in sorted(flagged, reverse=True)[:show]:
        print(f"   {s:.2f}  {u[:110]}")
    return fp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    a = ap.parse_args()

    eng = Engine()
    print(f"Modelo: {eng.bundle['name'] if eng.bundle else 'SIN modelo (heurística)'}")

    curated = [l.strip() for l in CURATED.read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.startswith("#")]
    evaluate(eng, curated, "URLs largas legítimas escritas a mano", show=15)

    big = pd.read_csv(RAW / "URL dataset.csv", usecols=["url", "type"])
    used = set(map(normalize_url, pd.read_csv(PROCESSED, usecols=["url"])["url"]))
    pool = big.loc[(big["type"] == "legitimate") & (big["url"].str.len() >= MIN_LEN), "url"]
    pool = sorted(u for u in set(pool) if normalize_url(u) not in used)
    sample = random.Random(7).sample(pool, min(a.n, len(pool)))
    evaluate(eng, sample, f"URLs legítimas de {MIN_LEN}+ caracteres no vistas en el entrenamiento")

    # Control: bajar falsos positivos no puede costar dejar pasar el phishing largo.
    ph = big.loc[(big["type"] == "phishing") & (big["url"].str.len() >= MIN_LEN), "url"]
    ph = sorted(u for u in set(ph) if normalize_url(u) not in used)
    ph = random.Random(8).sample(ph, min(a.n, len(ph)))
    evaluate(eng, ph, f"CONTROL: phishing de {MIN_LEN}+ caracteres no visto (aquí 'segura' es un error)",
             label="Recall en phishing largo")


if __name__ == "__main__":
    main()
