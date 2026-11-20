"""Cargadores de los feeds ACTUALES de amenazas (PhishTank, OpenPhish, URLhaus).

  data/raw/phishtank.csv   verified_online.csv de PhishTank (phish_id,url,...,submission_time,...,target)
  data/raw/openphish.txt   feed.txt de OpenPhish (una URL por línea)
  data/raw/urlhaus.csv     URLhaus 'recent' (CSV con comentarios #)
"""
import io
import re
from pathlib import Path

import pandas as pd

from phishsentinel.features_url import group_domain, normalize_url
from phishsentinel.popular_domains import POPULAR_DOMAINS
from phishsentinel.features_url import registered_domain

RAW = Path("data/raw")
FUTURE_CUTOFF = pd.Timestamp("2026-09-01", tz="UTC")     # PhishTank desde esta fecha = "futuro" (solo prueba)
# Alojamiento de código/archivos donde el malware es una MINORÍA frente a miles de descargas legítimas:
# sin contraparte legítima en los datos, entrenar con ellos enseñaría "github + .zip = malware".
SHARED_HOSTS = ("github.com", "raw.githubusercontent.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
                "dropbox.com", "drive.google.com", "docs.google.com", "mediafire.com", "mega.nz", "discord.com",
                "discordapp.com", "cdn.discordapp.com", "sourceforge.net", "onedrive.live.com", "1drv.ms",
                "pastebin.com", "telegram.org", "t.me", "archive.org", "huggingface.co")


def load_phishtank():
    p = RAW / "phishtank.csv"
    if not p.exists():
        return pd.DataFrame(columns=["url", "t", "target"])
    d = pd.read_csv(p, usecols=["url", "submission_time", "target"])
    d["t"] = pd.to_datetime(d["submission_time"], utc=True, errors="coerce")
    return d.dropna(subset=["url", "t"]).drop(columns="submission_time").drop_duplicates("url")


def load_openphish():
    p = RAW / "openphish.txt"
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def load_urlhaus():
    p = RAW / "urlhaus.csv"
    if not p.exists():
        return pd.DataFrame(columns=["url"])
    lines = [l for l in p.read_text(encoding="utf-8").replace("\r", "").split("\n") if l and not l.startswith("#")]
    d = pd.read_csv(io.StringIO("\n".join(lines)), header=None, names=[
        "id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"])
    return d.dropna(subset=["url"]).drop_duplicates("url")


def is_shared_host(url):
    h = group_domain(url)
    rd = registered_domain(url)
    return any(rd == s or rd.endswith("." + s) or h.endswith(s) for s in SHARED_HOSTS) or rd in POPULAR_DOMAINS


_PAT_A, _PAT_D = re.compile(r"[a-z]+"), re.compile(r"\d+")


def pattern_key(url):
    """Firma de 'plantilla': letras -> a, números -> 9. Las campañas que generan cientos de URLs casi iguales
    (sp28ct5-xxxx-biz-yyyy.pages.dev) comparten firma; sirve para no dejar que una sola campaña domine."""
    return _PAT_D.sub("9", _PAT_A.sub("a", normalize_url(url).lower()))


def cap_per_pattern(urls, cap, seed=0):
    import random
    r, seen, out = random.Random(seed), {}, []
    urls = list(urls)
    r.shuffle(urls)
    for u in urls:
        k = pattern_key(u)
        seen[k] = seen.get(k, 0) + 1
        if seen[k] <= cap:
            out.append(u)
    return out
