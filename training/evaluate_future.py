"""Prueba "del futuro": amenazas ACTUALES (PhishTank desde FUTURE_CUTOFF, OpenPhish, URLhaus) que el modelo
no vio, de hosts que NO están en el entrenamiento, con tope por plantilla (para que una campaña de 100
URLs casi iguales no infle el recall). Puede comparar varios modelos sobre exactamente las mismas URLs.

Uso:  python -m training.evaluate_future [modelo1.joblib modelo2.joblib ...]
"""
import sys

import joblib
import numpy as np
import pandas as pd

from phishsentinel.features_url import FEATURE_NAMES, group_domain, host_of
from training.common import featurize
from training.feeds import (FUTURE_CUTOFF, cap_per_pattern, is_shared_host, load_openphish, load_phishtank,
                            load_urlhaus)

I_TAG, I_EVT = FEATURE_NAMES.index("xss_tag"), FEATURE_NAMES.index("xss_event")
PLATFORMS = ("pages.dev", "github.io", "weebly.com", "weeblysite.com", "blogspot.com", "vercel.app", "netlify.app",
             "workers.dev", "typedream.app", "webflow.io", "gitbook.io", "framer.app", "web.app",
             "trycloudflare.com", "replit.app", "bolt.host")


def on_platform(u):
    h = host_of(u)
    return any(h == p or h.endswith("." + p) for p in PLATFORMS)


def build_sets(train_groups):
    pt = load_phishtank()
    pt = pt[pt["t"] >= FUTURE_CUTOFF]
    ok = lambda us: [u for u in us if group_domain(u) not in train_groups]
    pt_urls = cap_per_pattern(ok(pt["url"]), 3)
    op = cap_per_pattern(ok(load_openphish()), 3)
    uh = load_urlhaus()
    uh = cap_per_pattern(ok(uh[~uh["url"].map(is_shared_host)]["url"]), 5)
    sets = {"PhishTank reciente (todo)": pt_urls,
            "  · con HTTPS": [u for u in pt_urls if u.lower().startswith("https")],
            "  · en plataforma gratuita": [u for u in pt_urls if on_platform(u)],
            "  · dominio propio": [u for u in pt_urls if not on_platform(u)],
            "OpenPhish de hoy": op,
            "URLhaus malware (sin GitHub/hosts compartidos)": uh}
    return {k: v for k, v in sets.items() if v}


def p_mal(b, urls):
    m, classes = b["model"], b["classes"]
    num = featurize(urls)
    P = m.predict_proba(urls, numeric=num)
    p = 1.0 - P[:, classes.index("legitimate")]
    inj = (num[:, I_TAG] > 0) | (num[:, I_EVT] > 0)
    return np.where(inj, np.maximum(p, 0.85), p)


def main(paths):
    df = pd.read_csv("data/processed/urls.csv", usecols=["url", "split"])
    train_groups = {group_domain(u) for u in df.loc[df["split"] == "train", "url"]}
    sets = build_sets(train_groups)
    rows = []
    for path in paths:
        b = joblib.load(path)
        low, high = b["thresholds"]["low"], b["thresholds"]["high"]
        for name, urls in sets.items():
            p = p_mal(b, urls)
            rows.append({"modelo": path.split("/")[-1], "conjunto": name, "n": len(urls),
                         "se escapa (p<T_LOW)": (p < low).mean(), "zona de duda": ((p >= low) & (p < high)).mean(),
                         "bloqueo directo": (p >= high).mean(), "marcada (p>=0.5)": (p >= 0.5).mean()})
    out = pd.DataFrame(rows)
    pd.set_option("display.width", 200)
    fmt = {c: "{:.1%}".format for c in out.columns[3:]}
    print(out.to_string(index=False, formatters=fmt))
    out.to_csv("models/evaluacion_futuro.csv", index=False)


if __name__ == "__main__":
    main(sys.argv[1:] or ["models/model_url.joblib"])
