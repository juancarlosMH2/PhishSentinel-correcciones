"""Genera phishsentinel/brand_allowlist.py: dominios del TOP 15.000 de Tranco (los mismos que se
usan para entrenar) que contienen el nombre de una marca y son de la propia marca o de servicios
reales (googleapis.com, amazonvideo.com, microsoft365.com...). Solo entran los que CONTIENEN la
marca tal cual; los que la disfrazan o la escriben casi igual nunca se permiten.
El rango 15.001-30.000 de Tranco queda fuera (validación y prueba), para seguir usándolo como prueba independiente.
Uso:  python -m training.build_brand_allowlist"""
from pathlib import Path

import pandas as pd

from phishsentinel import features_url as fu

N = 15_000


def main():
    fu.BRAND_OWNED_POPULAR = set()
    doms = pd.read_csv("data/raw/tranco.csv", header=None, names=["rank", "domain"], nrows=N)["domain"]
    labels = sorted({fu._EXTRACT(d).domain.lower() for d in doms if fu.brand_hit(fu._EXTRACT(d).domain) == "contiene"})
    out = Path("phishsentinel/brand_allowlist.py")
    out.write_text('"""Generado por training/build_brand_allowlist.py a partir del top 15.000 de Tranco. No editar a mano."""\n'
                   f"BRAND_OWNED_POPULAR = {{\n" + "".join(f'    "{l}",\n' for l in labels) + "}\n", encoding="utf-8")
    print(f"{len(labels)} dominios guardados en {out}")


if __name__ == "__main__":
    main()
