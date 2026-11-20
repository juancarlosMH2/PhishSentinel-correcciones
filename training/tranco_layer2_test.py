"""Compara falsos positivos de la capa 1 sola vs capa 1 + capa 2 en una muestra de Tranco (descarga
páginas reales: necesita Internet y tarda). Los casos marcados se guardan con sus motivos para revisarlos
A MANO (p. ej. en VirusTotal) antes de reportar la cifra.
Uso:  python -m training.tranco_layer2_test --n 500"""
import argparse
import random
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine
from training.common import tranco_block


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--deep", action="store_true", help="consultar la capa 2 también fuera de la zona de duda")
    a = ap.parse_args()
    if not Path("data/raw/tranco.csv").exists():
        raise SystemExit("No existe data/raw/tranco.csv.")
    doms = random.Random(11).sample(tranco_block("test"), a.n)
    eng = Engine()
    only_l1, both, zones, fetched, flagged = Counter(), Counter(), Counter(), 0, []
    print(f"Analizando {len(doms)} dominios con HTML (puede tardar varios minutos)...")
    for i, d in enumerate(doms, 1):
        url = "https://" + d
        try:
            v1 = eng.analyze(url, fetch=False, log=False)
            v2 = eng.analyze(url, fetch=True, deep=a.deep, log=False)
        except Exception as exc:
            print(f"  [omitido] {d}: {exc}")
            continue
        only_l1[v1.level] += 1
        both[v2.level] += 1
        zones[v2.zone] += 1
        fetched += v2.content_checked
        if v2.level != "segura":
            flagged.append((d, v2.zone, v1.level, v2.level, v2.threat, v2.score, v2.decided_by,
                            " | ".join(v2.reasons[1:4])))
        if i % 50 == 0:
            print(f"  {i}/{len(doms)}")
    n = sum(only_l1.values())
    print("\n=== Falsos positivos (no segura) ===")
    print(f"Solo capa 1:      {n - only_l1['segura']:>4}  ({(n - only_l1['segura']) / n:.2%})")
    print(f"Capa 1 + capa 2:  {n - both['segura']:>4}  ({(n - both['segura']) / n:.2%})")
    print(f"Zonas: {dict(zones)} · páginas descargadas con éxito: {fetched}")
    if flagged:
        out = Path("models") / "falsos_positivos_capa2.csv"
        pd.DataFrame(flagged, columns=["dominio", "zona", "nivel_capa1", "nivel_final", "amenaza", "score",
                                       "decidio", "motivos"]).to_csv(out, index=False)
        print(f"Casos marcados guardados en {out}. Revísalos a mano antes de reportar la cifra.")


if __name__ == "__main__":
    main()
