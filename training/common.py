"""Utilidades compartidas por train.py y evaluate.py."""
import hashlib
import random
from pathlib import Path

import numpy as np
import pandas as pd

from phishsentinel.features_url import FEATURE_NAMES, extract_url_features, to_vector, registered_domain
from training.prepare_data import TRANCO_VAL, TRANCO_TEST, load_tranco, split_of
from training.synth import long_legit_url

PROCESSED = Path("data/processed")
CACHE = PROCESSED / "features_cache"
CLASSES = ["legitimate", "malware", "phishing", "xss"]          # orden fijo (alfabético)


def featurize(urls, tag=None):
    """URLs -> matriz de características (con caché en disco si se pasa `tag`)."""
    urls = list(urls)
    if tag:
        CACHE.mkdir(parents=True, exist_ok=True)
        h = hashlib.md5(("|".join(FEATURE_NAMES) + str(len(urls)) + (urls[0] if urls else "")
                         + (urls[-1] if urls else "")).encode()).hexdigest()[:10]
        f = CACHE / f"{tag}_{h}.npy"
        if f.exists():
            return np.load(f)
    X = np.array([to_vector(extract_url_features(u)) for u in urls], dtype=np.float32)
    if tag:
        np.save(f, X)
    return X


def load_split(path="data/processed/urls.csv"):
    df = pd.read_csv(path).dropna(subset=["url", "label"])
    X = featurize(df["url"], "urls")
    y = df["label"].map({c: i for i, c in enumerate(CLASSES)}).values
    return df, X, y


def seen_domains(df):
    """Dominios que aparecen en la partición de ENTRENAMIENTO (para excluirlos de pruebas 'no vistas')."""
    return set(df.loc[df["split"] == "train", "group"])


def tranco_block(which):
    a, b = TRANCO_VAL if which == "val" else TRANCO_TEST
    return load_tranco(a, b)


def synthetic_long_legit(domains, n, seed):
    r = random.Random(seed)
    return [long_legit_url(r.choice(domains), r) for _ in range(n)]
