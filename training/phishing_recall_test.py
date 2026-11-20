"""Recall de la capa 1 sobre phishing NO usado al entrenar Y de dominios que el modelo nunca vio.
Toma las URLs de phishing de los CSV originales, descarta las que (tras normalizar) ya están en
urls.csv y las de dominios presentes en el entrenamiento.
Uso:  python -m training.phishing_recall_test --n 5000"""
import argparse
import random
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine
from phishsentinel.features_url import group_domain, normalize_url

RAW, PROCESSED = Path("data/raw"), Path("data/processed/urls.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    a = ap.parse_args()
    used = pd.read_csv(PROCESSED, usecols=["url", "split", "group"])
    used_keys = set(used["url"].map(normalize_url))
    train_doms = set(used.loc[used["split"] == "train", "group"])
    pools = []
    big = pd.read_csv(RAW / "URL dataset.csv", usecols=["url", "type"])
    pools += big.loc[big["type"] == "phishing", "url"].tolist()
    mp = RAW / "malicious_phish.csv"
    if mp.exists():
        m = pd.read_csv(mp, usecols=["url", "type"])
        pools += m.loc[m["type"] == "phishing", "url"].tolist()
    cand = [u for u in dict.fromkeys(pools) if normalize_url(u) not in used_keys]
    print(f"phishing en los CSV: {len(pools)} · no usadas al preparar: {len(cand)}")
    sample = random.Random(5).sample(cand, min(a.n * 3, len(cand)))
    sample = [u for u in sample if group_domain(u) not in train_doms][:a.n]
    print(f"de dominios que el modelo nunca vio: {len(sample)}")
    eng, zones, levels = Engine(), Counter(), Counter()
    for u in sample:
        try:
            v = eng.analyze(u, fetch=False, log=False)
            zones[v.zone] += 1
            levels[v.level] += 1
        except Exception:
            zones["error"] += 1
    n = sum(zones.values()) - zones["error"]
    print(f"\nAnalizadas: {n}")
    for z in ("baja", "duda", "alta"):
        print(f"zona {z:>5}: {zones[z]:>5} ({zones[z] / n:.2%})")
    print(f"\nBloqueo directo por capa 1: {zones['alta'] / n:.2%}")
    print(f"Va a capa 2 (zona de duda): {zones['duda'] / n:.2%}")
    print(f"Se escapa sin capa 2 (zona baja): {zones['baja'] / n:.2%}   <- el hueco real de la capa 1")


if __name__ == "__main__":
    main()
