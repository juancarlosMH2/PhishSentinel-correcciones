"""Arma data/processed/urls.csv (url,label,group,source,split) a partir de data/raw/.

Cambios respecto a v1:
  * 4 clases: legitimate, phishing, malware, xss  (malware sale de malicious_phish.csv, datos reales).
    'defacement' NO se incluye: son páginas legítimas hackeadas, léxicamente idénticas a las benignas.
  * Legítimas de TRES fuentes (URL dataset, malicious_phish 'benign', Tranco) + URLs largas reales
    + URLs largas sintéticas sobre dominios Tranco (para quitar el sesgo "largo = sospechoso").
  * Se deduplica por URL NORMALIZADA (sin esquema ni www) y se descartan URLs con etiquetas en conflicto.
  * Cada fila lleva `group` (dominio registrado) y `split` (train/val/test) asignado POR DOMINIO:
    ningún dominio aparece en dos particiones. Así las métricas no se inflan por dominios repetidos.
  * Bloques de Tranco reservados (nunca entran al entrenamiento):
        ranks 15,001-20,000  -> validación (elige umbrales)
        ranks 20,001-30,000  -> prueba final (el mismo bloque que ya usabas)

Uso:  python -m training.prepare_data_v2
"""
import random
import re
import zlib
from pathlib import Path

import pandas as pd

from phishsentinel.features_url import group_domain, normalize_url
from training.feeds import (FUTURE_CUTOFF, cap_per_pattern, is_shared_host, load_phishtank, load_urlhaus)
from training.synth import long_legit_url, make_xss_urls, tracking_suffix

RAW, OUT = Path("data/raw"), Path("data/processed")
OUT.mkdir(parents=True, exist_ok=True)
SEED = 42
r = random.Random(SEED)

N_LEGIT_DS, N_LEGIT_BENIGN, N_LEGIT_LONG_REAL = 30_000, 30_000, 14_000
N_TRANCO_BARE, N_LEGIT_SYNTH_LONG = 35_000, 20_000
N_PHISH, N_MALWARE, N_XSS = 30_000, 32_000, 50_000   # N_PHISH: solo los datasets viejos; PhishTank se suma aparte
PT_FROM = pd.Timestamp("2021-01-01", tz="UTC")        # PhishTank: de 2021 hasta FUTURE_CUTOFF (después = solo prueba)
PT_CAP, UH_CAP = 5, 8                                  # máx. URLs por 'plantilla' de campaña
LONG_MIN = 100                      # "URL larga" = 100+ caracteres (ya normalizada)
TRACK_AUG = 0.08                    # fracción de URLs maliciosas reales con parámetros de rastreo
TRANCO_TRAIN_RANGES = [(0, 15_000), (30_000, 50_000)]   # 0-based [a, b)
TRANCO_VAL, TRANCO_TEST = (15_000, 20_000), (20_000, 30_000)


def load_tranco(a, b):
    d = pd.read_csv(RAW / "tranco.csv", header=None, names=["rank", "domain"], skiprows=a, nrows=b - a)
    return d["domain"].astype(str).tolist()


def load_real():
    frames = []
    p = RAW / "URL dataset.csv"
    if p.exists():
        d = pd.read_csv(p, usecols=["url", "type"]).rename(columns={"type": "label"})
        d["source"] = "urlds"
        frames.append(d)
    p = RAW / "malicious_phish.csv"
    if p.exists():
        d = pd.read_csv(p, usecols=["url", "type"]).rename(columns={"type": "label"})
        d["label"] = d["label"].map({"benign": "legitimate", "phishing": "phishing", "malware": "malware"})
        d["source"] = "mphish"
        frames.append(d.dropna())
    # --- feeds ACTUALES (aportados por el equipo): PhishTank (phishing, era HTTPS) y URLhaus (malware) ---
    pt = load_phishtank()
    pt = pt[(pt["t"] >= PT_FROM) & (pt["t"] < FUTURE_CUTOFF)]
    pt_urls = cap_per_pattern(pt["url"], PT_CAP)
    if pt_urls:
        frames.append(pd.DataFrame({"url": pt_urls, "label": "phishing", "source": "phishtank"}))
    uh = load_urlhaus()
    if len(uh):
        uh_urls = cap_per_pattern(uh[~uh["url"].map(is_shared_host)]["url"], UH_CAP)
        frames.append(pd.DataFrame({"url": uh_urls, "label": "malware", "source": "urlhaus"}))
        print(f"URLhaus: {len(uh_urls)} usables de {len(uh)} (se descartan GitHub y hosts compartidos)")
    print(f"PhishTank {PT_FROM.year}-corte: {len(pt_urls)} usables de {len(pt)} (tope {PT_CAP} por plantilla)")
    df = pd.concat(frames, ignore_index=True)
    df["url"] = df["url"].astype(str).str.strip()
    df["key"] = df["url"].map(normalize_url)
    nlab = df.groupby("key")["label"].nunique()
    conflict = set(nlab[nlab > 1].index)
    df = df[~df["key"].isin(conflict)].drop_duplicates("key")
    print(f"reales tras normalizar/deduplicar ({len(conflict)} conflictos eliminados):",
          df["label"].value_counts().to_dict())
    return df


def load_xss_payloads():
    """Todos los archivos con 'xss' en el nombre (sin distinguir mayúsculas: en Windows el glob
    ya lo hacía; en Linux/macOS no)."""
    pays = []
    for p in sorted(RAW.iterdir()):
        n = p.name.lower()
        if "xss" not in n:
            continue
        if n.endswith(".csv"):               # Kaggle XSS dataset: Sentence, Label (1 = XSS)
            d = pd.read_csv(p)
            col = "Sentence" if "Sentence" in d else d.columns[0]
            if "Label" in d:
                d = d[d["Label"] == 1]
            pays += d[col].dropna().astype(str).tolist()
        elif n.endswith(".txt"):
            pays += [l.strip() for l in p.read_text(errors="ignore").splitlines()
                     if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(pays))


def with_tracking(u):
    if r.random() >= TRACK_AUG:
        return u
    return u + ("&" if "?" in u else "?") + tracking_suffix(r)


def bare(dom):
    return f"https://{dom}" + ("/" if r.random() < 0.30 else "")


def split_of(group):
    """Partición determinista por dominio: el MISMO dominio cae siempre en la misma partición,
    sea cual sea la fuente (URL dataset, malicious_phish, Tranco, XSS generado)."""
    h = zlib.crc32(group.encode()) % 100
    return "train" if h < 75 else ("val" if h < 85 else "test")


def main():
    real = load_real()
    legit_pool = real[real.label == "legitimate"]
    legit_a = legit_pool[legit_pool.source == "urlds"].sample(N_LEGIT_DS, random_state=SEED)
    legit_b = legit_pool[legit_pool.source == "mphish"].sample(N_LEGIT_BENIGN, random_state=SEED)
    taken = set(legit_a.key) | set(legit_b.key)
    long_pool = legit_pool[(legit_pool.key.str.len() >= LONG_MIN) & ~legit_pool.key.isin(taken)]
    legit_long = long_pool.sample(min(N_LEGIT_LONG_REAL, len(long_pool)), random_state=SEED)
    legit_long = legit_long.assign(source="real_long_legit")
    print("legítimas reales largas añadidas:", len(legit_long))

    old = real[real.source.isin(["urlds", "mphish"])]
    phish = pd.concat([old[old.label == "phishing"].sample(N_PHISH, random_state=SEED),
                       real[real.source == "phishtank"]])
    malw_old = old[old.label == "malware"]
    malw = pd.concat([malw_old.sample(min(N_MALWARE, len(malw_old)), random_state=SEED),
                      real[real.source == "urlhaus"]])
    for d in (phish, malw):
        d["url"] = [with_tracking(u) for u in d["url"]]

    rows = []   # (url, label, source)
    for d in (legit_a, legit_b, legit_long, phish, malw):
        rows += list(zip(d["url"], d["label"], d["source"]))

    # --- Tranco entrenamiento: dominios desnudos + URLs largas sintéticas ---
    tr_train = []
    for a, b in TRANCO_TRAIN_RANGES:
        tr_train += load_tranco(a, b)
    # solo dominios cuyo hash cae en 'train' (así un dominio nunca queda en dos particiones)
    tr_train = [d for d in tr_train if split_of(group_domain(d) or "desconocido") == "train"]
    tr_bare = r.sample(tr_train, min(N_TRANCO_BARE, len(tr_train)))
    rows += [(bare(x), "legitimate", "tranco_train") for x in tr_bare]
    synth = [long_legit_url(r.choice(tr_train), r) for _ in range(N_LEGIT_SYNTH_LONG)]
    rows += [(u, "legitimate", "synth_long_legit") for u in synth]
    print(f"Tranco entrenamiento: {len(tr_bare)} dominios desnudos + {len(synth)} URLs largas sintéticas")

    # --- XSS: payloads sobre bases legítimas variadas (reales cortas/largas, dominios, sintéticas) ---
    payloads = load_xss_payloads()
    print("payloads XSS únicos:", len(payloads))
    bases = (legit_a["url"].sample(6000, random_state=1).tolist()
             + legit_b["url"].sample(6000, random_state=2).tolist()
             + legit_long["url"].sample(min(6000, len(legit_long)), random_state=3).tolist()
             + [bare(x) for x in r.sample(tr_train, 6000)]
             + synth[:6000])
    xss = make_xss_urls(payloads, bases, N_XSS, r)
    rows += [(u, "xss", "xss_synth") for u in xss]

    df = pd.DataFrame(rows, columns=["url", "label", "source"])
    df["key"] = df["url"].map(normalize_url)
    df = df.drop_duplicates(["key", "label"]).drop(columns="key")
    df["group"] = [group_domain(u) or "desconocido" for u in df["url"]]
    df["split"] = [split_of(g) for g in df["group"]]
    df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)
    df.to_csv(OUT / "urls.csv", index=False)

    print("\n=== data/processed/urls.csv ===")
    print(pd.crosstab(df["label"], df["split"], margins=True))
    print(pd.crosstab(df["label"], df["source"]))
    ov = df.groupby("group")["split"].nunique()
    print("dominios en más de una partición (debe ser 0):", int((ov > 1).sum()))


if __name__ == "__main__":
    main()
