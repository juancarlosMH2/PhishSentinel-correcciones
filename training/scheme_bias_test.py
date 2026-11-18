"""Prueba del sesgo de esquema: en 'URL dataset.csv' casi todas las legítimas empiezan con
'https://www.' y casi ninguna de phishing usa https. Si el modelo aprendió ese atajo,
cambiar solo el esquema debería cambiar su respuesta.
  - Legítimas reescritas como http:// sin www  -> ¿aumentan los falsos positivos?
  - Phishing reescrito como https://           -> ¿cae el recall?
Uso:  python -m training.scheme_bias_test --n 2000"""
import argparse
import random
import re
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine

RAW = Path("data/raw")
PROCESSED = Path("data/processed/urls.csv")


def rate_flagged(eng, urls):
    return sum(eng.analyze(u, fetch=False).level != "segura" for u in urls) / max(len(urls), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    a = ap.parse_args()

    eng = Engine()
    big = pd.read_csv(RAW / "URL dataset.csv", usecols=["url", "type"])
    used = set(pd.read_csv(PROCESSED, usecols=["url"])["url"])
    rnd = random.Random(3)

    legit = sorted(set(big.loc[big["type"] == "legitimate", "url"]) - used)
    legit = rnd.sample(legit, min(a.n, len(legit)))
    phish = sorted(set(big.loc[big["type"] == "phishing", "url"]) - used)
    phish = [u for u in phish if u.startswith("http://")]
    phish = rnd.sample(phish, min(a.n, len(phish)))

    legit_http = [re.sub(r"^https://(www\.)?", "http://", u) for u in legit]
    phish_https = ["https://" + u[len("http://"):] for u in phish]

    print(f"Modelo: {eng.bundle['name'] if eng.bundle else 'SIN modelo (heurística)'}")
    print("\nLegítimas (falsos positivos, más bajo es mejor)")
    print(f"  original (https://www.):   {rate_flagged(eng, legit):.2%}")
    print(f"  reescrita (http://, sin www): {rate_flagged(eng, legit_http):.2%}")
    print("\nPhishing (recall, más alto es mejor)")
    print(f"  original (http://):  {rate_flagged(eng, phish):.2%}")
    print(f"  reescrito (https://): {rate_flagged(eng, phish_https):.2%}")


if __name__ == "__main__":
    main()
