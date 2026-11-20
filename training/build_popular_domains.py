"""Genera phishsentinel/popular_domains.py: los 2.000 dominios más populares de Tranco (menos los hosts
donde cualquiera publica páginas). Se usa como señal de reputación: en estos dominios la URL por sí
sola NO basta para marcar 'peligrosa'; debe confirmarlo la capa 2 (contenido).
Solo usa los rangos 1-2.000 (entrenamiento); no toca los bloques de validación ni de prueba.
Uso:  python -m training.build_popular_domains"""
from pathlib import Path

import pandas as pd

from phishsentinel.features_url import registered_domain

N = 2000
# Dominios donde cualquiera puede publicar contenido: la reputación del dominio NO protege a la página
MULTI_TENANT = {"web.app", "firebaseapp.com", "github.io", "pages.dev", "netlify.app", "vercel.app",
                "weebly.com", "wixsite.com", "blogspot.com", "herokuapp.com", "glitch.me", "workers.dev",
                "wordpress.com", "tumblr.com", "000webhostapp.com", "azurewebsites.net", "appspot.com",
                "s3.amazonaws.com", "amazonaws.com", "cloudfront.net", "r2.dev", "onrender.com",
                "notion.site", "carrd.co", "webflow.io", "framer.website", "sites.google.com",
                "storage.googleapis.com", "googleusercontent.com", "ipfs.io", "bit.ly", "t.co",
                "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "duckdns.org", "no-ip.com"}


def main():
    doms = pd.read_csv("data/raw/tranco.csv", header=None, names=["rank", "domain"], nrows=N)["domain"]
    keep = sorted({registered_domain(d) for d in doms} - MULTI_TENANT - {""})
    out = Path("phishsentinel/popular_domains.py")
    out.write_text('"""Generado por training/build_popular_domains.py (top 2.000 de Tranco). No editar a mano."""\n'
                   "POPULAR_DOMAINS = frozenset({\n" + "".join(f'    "{d}",\n' for d in keep) + "})\n", encoding="utf-8")
    print(f"{len(keep)} dominios guardados en {out}")


if __name__ == "__main__":
    main()
