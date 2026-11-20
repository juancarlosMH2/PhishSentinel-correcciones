"""Sonda de SESGO DE PLATAFORMA: sitios legítimos (escritos a mano) alojados en github.io, vercel.app, pages.dev...
Si el modelo aprendiera "plataforma gratuita = phishing", esta prueba lo delata (en una versión intermedia
bloqueaba directo el 72% de estos sitios). Es una muestra pequeña y subjetiva: úsala como alarma, no como métrica.
Uso:  python -m training.platform_probe_test"""
import joblib
import numpy as np

from training.evaluate_future import p_mal


def main(path="models/model_url.joblib"):
    urls = [l.strip() for l in open("data/eval/urls_plataformas_legitimas.txt", encoding="utf-8") if l.strip()]
    b = joblib.load(path)
    p, (lo, hi) = p_mal(b, urls), (b["thresholds"]["low"], b["thresholds"]["high"])
    print(f"{len(urls)} sitios legítimos en plataformas gratuitas")
    print(f"  pasa directo {np.mean(p < lo):.0%} · zona de duda {np.mean((p >= lo) & (p < hi)):.0%} · "
          f"BLOQUEO DIRECTO {np.mean(p >= hi):.0%} · marcada con 0.5: {np.mean(p >= .5):.0%}")
    for u, x in sorted(zip(urls, p), key=lambda t: -t[1])[:5]:
        print(f"  {x:.2f} {u}")


if __name__ == "__main__":
    main()
