"""Descarga HTML ESTÁTICO (sin ejecutar JavaScript) para medir y entrenar la capa 2.

Genera:  data/html/<etiqueta>/<id>.html   y   data/html/manifest.csv  (archivo,url,etiqueta,fecha,estado)

  python -m training.collect_html --phish 3000 --legit 3000

Fuentes:  phishing -> PhishTank (más recientes) + OpenPhish (data/raw/phishtank.csv, openphish.txt)
          legítimas -> Tranco, mezclando rangos altos y bajos, y añade /login y /signin de cada dominio
                       (las páginas de acceso legítimas son los casos que más confunden a la capa 2)

SEGURIDAD: ejecútalo en una máquina virtual o con VPN (los sitios de phishing pueden registrar tu IP).
Solo guarda texto; NO abras los .html en el navegador. Muchas URLs de phishing ya estarán caídas: es normal
(parte de unas 3x más URLs de las que necesitas). Usa los MISMOS límites que la app (tamaño, redirecciones).
"""
import argparse
import csv
import random
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from phishsentinel.fetcher import fetch_page
from training.feeds import load_openphish, load_phishtank

OUT = Path("data/html")


def tranco_sample(n, seed=7):
    d = pd.read_csv("data/raw/tranco.csv", header=None, names=["rank", "domain"], nrows=200_000)
    r = random.Random(seed)
    doms = d["domain"].tolist()
    picked = r.sample(doms[:2000], n // 4) + r.sample(doms[2000:50_000], n // 2) + r.sample(doms[50_000:], n - 3 * (n // 4))
    urls = []
    for x in picked:
        urls.append(f"https://{x}/")
    login = r.sample(doms[:20_000], min(n // 3, 20_000))
    urls += [f"https://{x}/{r.choice(['login', 'signin', 'account/login'])}" for x in login]
    return urls


def fetch_one(args):
    i, url, label = args
    html, final = fetch_page(url)
    if not html or len(html) < 200:
        return {"id": i, "url": url, "label": label, "estado": "caida_o_no_html", "archivo": ""}
    path = OUT / label / f"{label}_{i:06d}.html"
    path.write_text(html, encoding="utf-8", errors="replace")
    return {"id": i, "url": url, "label": label, "estado": "ok", "archivo": str(path)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", type=int, default=2000, help="páginas de phishing deseadas (se prueban ~3x URLs)")
    ap.add_argument("--legit", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args()
    for lab in ("phishing", "legitimate"):
        (OUT / lab).mkdir(parents=True, exist_ok=True)
    pt = load_phishtank().sort_values("t", ascending=False)["url"].tolist()
    ph = list(dict.fromkeys(load_openphish() + pt))[: a.phish * 3]
    lg = tranco_sample(a.legit)[: int(a.legit * 1.3)]
    jobs = [(i, u, "phishing") for i, u in enumerate(ph)] + [(100_000 + i, u, "legitimate") for i, u in enumerate(lg)]
    random.Random(1).shuffle(jobs)
    print(f"Descargando {len(jobs)} URLs ({len(ph)} phishing, {len(lg)} legítimas)...")
    t0, rows = time.time(), []
    with ThreadPoolExecutor(a.workers) as ex:
        for k, r in enumerate(ex.map(fetch_one, jobs), 1):
            r["fecha"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            rows.append(r)
            if k % 200 == 0:
                print(f"  {k}/{len(jobs)} · ok: {sum(x['estado'] == 'ok' for x in rows)} · {time.time() - t0:.0f} s", flush=True)
    m = pd.DataFrame(rows)
    m.to_csv(OUT / "manifest.csv", index=False)
    print(m.groupby(["label", "estado"]).size())
    print("Manifiesto en", OUT / "manifest.csv")


if __name__ == "__main__":
    main()
