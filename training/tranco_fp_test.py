"""Falsos positivos de la capa 1 sobre dominios populares reales (Tranco 20,001-30,000, nunca usados
para entrenar ni para calibrar). Todo dominio popular es, en principio, legítimo: cada alerta es un FP.
Uso:  python -m training.tranco_fp_test"""
from collections import Counter
from pathlib import Path

import pandas as pd

from phishsentinel.engine import Engine
from training.common import tranco_block


def main():
    if not Path("data/raw/tranco.csv").exists():
        raise SystemExit("No existe data/raw/tranco.csv. Descarga la lista Tranco y guárdala ahí.")
    doms = tranco_block("test")
    eng = Engine()
    print(f"Modelo: {eng.bundle['name'] if eng.bundle else 'SIN modelo (heurística)'} · "
          f"zona de duda {eng.t_low:.0%}–{eng.t_high:.0%}")
    print(f"Analizando {len(doms)} dominios, SOLO capa 1 (sin descargar HTML)...")
    zones, levels, flagged = Counter(), Counter(), []
    for d in doms:
        v = eng.analyze("https://" + d, fetch=False, log=False)
        zones[v.zone] += 1
        levels[v.level] += 1
        if v.level != "segura":
            flagged.append((d, v.zone, v.level, v.threat, v.score))
    n = len(doms)
    print("\n=== Resultados (solo capa 1) ===")
    for z in ("baja", "duda", "alta"):
        print(f"zona {z:>5}: {zones[z]:>6}  ({zones[z] / n:.2%})")
    print(f"\nBloqueo directo por capa 1 (peligrosa): {levels['peligrosa'] / n:.2%}")
    print(f"Marcadas 'no segura' sin capa 2 (peligrosa+sospechosa): {(n - levels['segura']) / n:.2%}")
    print("La zona de duda se resuelve con la capa 2: mídela con  python -m training.tranco_layer2_test")
    if flagged:
        out = Path("models") / "falsos_positivos_tranco.csv"
        pd.DataFrame(flagged, columns=["dominio", "zona", "nivel", "amenaza", "score"]).to_csv(out, index=False)
        print(f"Casos marcados guardados en {out}")


if __name__ == "__main__":
    main()
