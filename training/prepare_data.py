"""Arma data/processed/urls.csv (url,label) a partir de los datasets en data/raw/.
Uso:  python -m training.prepare_data"""
import random
from pathlib import Path
from urllib.parse import quote

import pandas as pd

RAW, OUT = Path("data/raw"), Path("data/processed")
OUT.mkdir(parents=True, exist_ok=True)
random.seed(42)
CAP_PER_CLASS = 50_000

# (archivo en data/raw, columna URL, columna etiqueta, mapa de etiquetas)
SOURCES = [
    ("URL dataset.csv", "url", "type", {"legitimate": "legitimate", "phishing": "phishing"}),
]
PARAMS = ["q", "search", "s", "query", "id", "name", "redirect", "url", "page", "msg"]
WORDS = ["zapatos", "libros", "mochila", "clima", "noticias", "python", "receta", "hotel"]

# URLs largas legítimas (corrección: el modelo marcaba como maliciosa casi toda URL larga).
LONG_LEN = 100            # desde cuántos caracteres se considera "larga"
LONG_CAP = 11_000         # cuántas largas se aseguran por clase (legítima y phishing)
SYNTH_LONG_LEGIT = 8_000  # de esas, cuántas legítimas se generan sobre dominios de Tranco (todas entran)
SYNTH_MIN_LEN = 60        # las generadas pueden ser algo más cortas: lo que importa son sus IDs largos
SUBDOMAINS = ["mail", "docs", "drive", "accounts", "login", "auth", "app", "portal", "campus", "campusvirtual",
              "m", "es", "shop", "store", "support", "help", "blog", "news", "web", "my", "api", "cdn", "id"]
SLUG_WORDS = ["noticias", "colombia", "producto", "oferta", "universidad", "estudiantes", "precio",
              "how", "to", "install", "python", "windows", "machine", "learning", "review", "best",
              "2025", "2026", "guia", "tutorial", "portatil", "lenovo", "samsung", "galaxy", "camiseta",
              "futbol", "receta", "pollo", "hotel", "cartagena", "medellin", "bogota", "news", "world",
              "election", "music", "video", "podcast", "episode", "chapter", "manual", "pdf", "data"]
TRACKING = ["utm_source=newsletter", "utm_source=facebook", "utm_medium=social", "utm_medium=email",
            "utm_campaign=promo_navidad", "utm_content=boton_azul", "fbclid=IwAR{tok}", "gclid=Cj0KCQiA{tok}",
            "ref=sr_1_{n}", "ref_src=twsrc%5Etfw", "si={hex}", "s=46&t={tok}", "igsh={tok}",
            "trk=public_profile", "source=email-{hex}", "sk={hex}", "usp=sharing", "dl=0", "lang=es",
            "hl=es-419", "page={n}", "sort=price_asc", "id={n}", "sid={hex}", "session={hex}",
            "q={words}", "search_query={words}", "keywords={words}", "t={n}s", "v={tok}", "list=PL{tok}",
            "client_id={uuid}", "response_type=code", "scope=openid%20profile%20email", "state={hex}",
            "nonce={n}", "id={longtok}", "pwd={longtok}", "resid={hex}!{n}", "cid={hex}", "token={longtok}",
            "dib={longtok}", "psc=1", "th=1", "sd=true", "rtpof=true", "redirect_uri=https%3A%2F%2F{host}%2Fauth%2Fcallback", "continue=https%3A%2F%2F{host}%2F"]

# URLs legítimas con rutas CORTAS (tiktok.com/es/, google.com/login): el dataset casi no las
# tenía en la clase legítima y el modelo aprendió "ruta corta = phishing". Sin palabras como
# login/account: con ellas el modelo dejaba de ver /login como señal y bajaba la detección de phishing.
SYNTH_SHORT_LEGIT = 1_200
SHORT_PATHS = ["es", "en", "co", "es-co", "es-419", "pt", "pt-br", "fr", "de", "it", "us", "mx", "ar",
               "help", "ayuda", "about", "acerca", "blog",
               "news", "noticias", "shop", "tienda", "store", "app", "apps", "download", "descargas",
               "explore", "trending", "music", "video", "videos", "live", "search", "buscar", "jobs",
               "empleos", "careers", "docs", "support", "soporte", "pricing", "precios", "contact",
               "contacto", "home", "inicio", "feed", "settings", "profile", "perfil", "privacy", "terms"]

TRANCO = RAW / "tranco.csv"
TRANCO_TRAIN_N = 20_000
TRANCO_TEST_START, TRANCO_TEST_END = 20_000, 30_000


def load_tranco_train():
    """Dominios raíz legítimos para entrenamiento (primeros 20,000 de Tranco)."""
    if not TRANCO.exists():
        print("[aviso] no está tranco.csv, se omite")
        return []
    d = pd.read_csv(TRANCO, header=None, names=["rank", "domain"], nrows=TRANCO_TRAIN_N)
    return [f"https://{x}/" for x in d["domain"].tolist()]

def load_sources():
    frames = []
    for fname, c_url, c_lab, mapping in SOURCES:
        p = RAW / fname
        if not p.exists():
            print(f"[aviso] no está {p}, se omite")
            continue
        d = pd.read_csv(p, usecols=[c_url, c_lab]).rename(columns={c_url: "url", c_lab: "label"})
        d["label"] = d["label"].map(mapping)
        frames.append(d.dropna())
    return pd.concat(frames) if frames else pd.DataFrame(columns=["url", "label"])


def load_xss_payloads():
    pays = []
    for p in RAW.glob("xss_*.csv"):        # Kaggle XSS dataset: columnas Sentence, Label (1 = XSS)
        d = pd.read_csv(p)
        col = "Sentence" if "Sentence" in d else d.columns[0]
        if "Label" in d:
            d = d[d["Label"] == 1]
        pays += d[col].dropna().astype(str).tolist()
    for p in RAW.glob("xss_*.txt"):        # PayloadsAllTheThings: un payload por línea
        pays += [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(pays))


def make_xss_urls(payloads, bases, n):
    """Genera hasta n URLs con payloads XSS en un parámetro.
    Sin parámetro aleatorio: así el modelo no aprende un atajo artificial."""
    out = set()
    attempts, max_attempts = 0, n * 10
    while len(out) < n and payloads and attempts < max_attempts:
        attempts += 1
        pl = random.choice(payloads)
        base = random.choice(bases).split("?")[0]
        val = quote(pl[:300]) if random.random() < 0.5 else pl[:300].replace(" ", "%20")
        out.add(f"{base}?{random.choice(PARAMS)}={val}")
    return list(out)


def _tok(n):
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", k=n))


def _slug(k):
    return "-".join(random.choices(SLUG_WORDS, k=k))


def make_long_legit(domains, n):
    """URLs legítimas largas con la forma de las reales: rutas con slugs e IDs y parámetros de
    búsqueda, seguimiento (utm, fbclid, gclid) o de inicio de sesión OAuth hacia el mismo sitio."""
    paths = [lambda: f"/{_slug(1)}/{_slug(random.randint(3, 8))}-{random.randint(10**5, 10**9)}.html",
             lambda: f"/{random.choice(['es', 'en', 'co', 'es-co'])}/{_slug(1)}/{_slug(random.randint(4, 9))}",
             lambda: f"/{random.choice(['p', 'd', 'dp', 'item', 'watch', 'status', 'video'])}/{_tok(random.randint(8, 34))}",
             lambda: f"/{random.randint(2018, 2026)}/{random.randint(1, 12):02d}/{random.randint(1, 28):02d}/{_slug(random.randint(4, 10))}",
             lambda: f"/{_slug(1)}/{_tok(10)}/{random.choice(['edit', 'view', 'details', 'checkout', 'cart'])}",
             lambda: f"/{random.choice(['search', 'results', 'buscar', 'shop'])}",
             lambda: f"/{random.choice(['oauth2', 'auth', 'signin', 'sso', 'account'])}/{random.choice(['authorize', 'v2.0/authorize', 'identifier', 'login'])}",
             # IDs largos y aleatorios, típicos de servicios modernos (documentos, correos, reuniones)
             lambda: f"/{_slug(1)}/d/{random.choice(['', 'e/'])}{_tok(random.randint(25, 60))}/{random.choice(['edit', 'view', 'viewform', 'preview'])}",
             lambda: f"/{_slug(1)}/u/{random.randint(0, 3)}/#{_slug(1)}/{_tok(random.randint(20, 45))}",
             lambda: f"/{_slug(1)}/{random.choice(['id', 'item', 'file', 'folders'])}/{_tok(random.randint(30, 80))}",
             lambda: "/" + "/".join(_slug(1) for _ in range(random.randint(3, 8))) + f"/!ut/p/z1/{_tok(random.randint(40, 90))}/",
             lambda: f"/{random.choice(['j', 'meet', 'join', 's'])}/{random.randint(10**8, 10**11)}",
             lambda: f"/{_slug(1)}/{random.choice(['view.php', 'index.php', 'course/view.php', 'login/index.php'])}"]
    out = set()
    while len(out) < n and domains:
        host = random.choice(domains)
        params = []
        for _ in range(random.randint(0, 7)):
            params.append(random.choice(TRACKING).format(
                tok=_tok(random.randint(8, 28)), longtok=_tok(random.randint(25, 70)), hex="%x" % random.getrandbits(64), n=random.randint(1, 99999),
                words="+".join(random.choices(SLUG_WORDS, k=random.randint(2, 6))),
                uuid="%08x-%04x-%04x-%04x-%012x" % tuple(random.getrandbits(b) for b in (32, 16, 16, 16, 48)),
                host=host))
        sub = random.choice(SUBDOMAINS) + "." if random.random() < 0.5 else random.choice(["", "www."])
        url = f"{random.choice(['https://', 'http://'])}{sub}{host}{random.choice(paths)()}"
        if params:
            url += "?" + "&".join(dict.fromkeys(params))
        if len(url) >= SYNTH_MIN_LEN:
            out.add(url)
    return list(out)


def make_short_legit(domains, n):
    """URLs legítimas de ruta corta sobre dominios populares: tiktok.com/es/, ejemplo.com/login."""
    out = set()
    while len(out) < n and domains:
        sub = random.choice(["", "www.", "www.", "m.", "es."])
        path = "/".join(random.sample(SHORT_PATHS, random.choice([1, 1, 1, 2])))
        out.add(f"{random.choice(['https://', 'http://'])}{sub}{random.choice(domains)}/{path}{random.choice(['', '/'])}")
    return list(out)


def balance(df, n, synth_legit=(), synth_short=()):
    """n URLs por clase. En legítimas y phishing se aseguran LONG_CAP largas, para que la longitud
    deje de ser por sí sola una señal de phishing (ni de legitimidad). Entre las legítimas largas
    entran todas las generadas (synth_legit) y el resto son reales."""
    parts = []
    for label, g in df.groupby("label"):
        if label not in ("legitimate", "phishing"):
            parts.append(g.sample(min(len(g), n), random_state=42))
            continue
        legit = label == "legitimate"
        synth = pd.DataFrame({"url": list(synth_legit) if legit else [], "label": label})
        short = pd.DataFrame({"url": list(synth_short) if legit else [], "label": label})
        long_ = g[g["url"].str.len() >= LONG_LEN]
        long_ = long_.sample(min(len(long_), max(LONG_CAP - len(synth), 0)), random_state=42)
        rest = g.drop(long_.index)
        rest = rest.sample(min(len(rest), max(n - len(long_) - len(synth) - len(short), 0)), random_state=42)
        parts.append(pd.concat([synth, short, long_, rest]))
    return pd.concat(parts, ignore_index=True)


def main():
    df = load_sources().drop_duplicates("url")
    print("tras cargar:", df.label.value_counts().to_dict())
    legit = df.loc[df.label == "legitimate", "url"].tolist()
    payloads = load_xss_payloads()
    print("payloads xss:", len(payloads))

    extra = []
    tranco_train = load_tranco_train()
    extra += [(u, "legitimate") for u in tranco_train]
    hosts = [u.split("/")[2] for u in tranco_train]
    synth = make_long_legit(hosts, SYNTH_LONG_LEGIT)
    synth_short = make_short_legit(hosts, SYNTH_SHORT_LEGIT)
    if legit and payloads:
        extra += [(u, "xss") for u in make_xss_urls(payloads, legit, CAP_PER_CLASS)]
        # negativos difíciles: URLs legítimas con parámetros normales (reduce falsos positivos)
        extra += [(random.choice(legit).split("?")[0] + f"?{random.choice(PARAMS)}={random.choice(WORDS)}", "legitimate")
                  for _ in range(5000)]
    else:
        print("[aviso] sin payloads XSS o sin URLs legítimas: no se generan ejemplos de XSS")

    df = pd.concat([df, pd.DataFrame(extra, columns=["url", "label"])])
    df = df.drop_duplicates(["url", "label"])
    print("antes de balancear:", df.label.value_counts().to_dict())

    df = df.reset_index(drop=True)
    n = min(df.label.value_counts().min(), CAP_PER_CLASS)
    df = balance(df, n, synth, synth_short)
    df.to_csv(OUT / "urls.csv", index=False)
    print(df.label.value_counts())
    print(f"URLs de {LONG_LEN}+ caracteres por clase:",
          df[df["url"].str.len() >= LONG_LEN].label.value_counts().to_dict())


if __name__ == "__main__":
    main()