"""Generadores de URLs sintéticas.

Solo se usan donde NO hay datos reales suficientes:
  * URLs legítimas largas/complejas sobre dominios reales (Tranco): rutas profundas,
    parámetros de rastreo, tokens, URLs codificadas dentro de la consulta, páginas de login legítimas.
  * URLs con payloads XSS (los datasets públicos son payloads sueltos, no URLs).

Limitación honesta: son plantillas. Sirven para que el modelo no asocie "largo = sospechoso", pero
las métricas medidas sobre ellas son optimistas; por eso la evaluación de URLs largas usa
sobre todo URLs REALES de dominios que no se vieron al entrenar.
"""
import base64
import random
import string
import uuid
from urllib.parse import quote

WORDS_EN = ("best cheap guide review how to new latest top sale deal free shipping official store "
            "news world today video music games sports weather travel hotel flights recipe health "
            "science technology business finance market price list compare phone laptop camera "
            "shoes watch dress book movie series season episode download update release notes").split()
WORDS_ES = ("mejor barato guia opinion como nuevo ultimo oferta gratis envio tienda noticias mundo hoy "
            "musica juegos deportes clima viajes hotel vuelos receta salud ciencia tecnologia negocios "
            "mercado precio lista comparar celular portatil camara zapatos reloj vestido libro pelicula "
            "temporada capitulo cancion niño año canción").split()
SECTIONS = ["news", "blog", "articles", "p", "products", "item", "dp", "store", "category", "docs",
            "en", "es", "help", "support", "videos", "watch", "wiki", "forum", "topics", "users"]
SEARCH_PARAMS = ["q", "query", "search", "s", "keywords", "term", "text"]
UTM = ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"]
UTM_VAL = ["newsletter", "email", "facebook", "twitter", "google", "cpc", "social", "spring_sale", "home"]
OTHER_DOMAINS = ["example.org", "wikipedia.org", "github.com", "youtube.com", "nytimes.com"]


def _slug(r, n=None):
    n = n or r.randint(3, 12)
    ws = WORDS_EN if r.random() < 0.6 else WORDS_ES
    return "-".join(r.choice(ws) for _ in range(n))


def _rand(r, n, alphabet=string.ascii_letters + string.digits):
    return "".join(r.choice(alphabet) for _ in range(n))


def _tracking(r):
    ks = r.sample(UTM, r.randint(1, 4))
    q = [f"{k}={r.choice(UTM_VAL)}" for k in ks]
    if r.random() < 0.4:
        q.append("gclid=" + _rand(r, r.randint(20, 60)))
    if r.random() < 0.3:
        q.append("fbclid=" + _rand(r, r.randint(30, 70)))
    return q


def long_legit_url(domain, r=random):
    """Una URL legítima 'del mundo real' (larga, con parámetros) sobre `domain`."""
    base = f"https://{'www.' if r.random() < .5 else ''}{domain}"
    kind = r.randrange(14)
    if kind == 0:      # noticia con fecha y slug largo
        path = f"/{r.choice(SECTIONS)}/{r.randint(2015, 2026)}/{r.randint(1, 12):02d}/{r.randint(1, 28):02d}/{_slug(r)}.html"
        return base + path + ("?" + "&".join(_tracking(r)) if r.random() < .5 else "")
    if kind == 1:      # e-commerce
        return (f"{base}/{_slug(r, 4)}/dp/{_rand(r, 10, string.ascii_uppercase + string.digits)}"
                f"/ref=sr_1_{r.randint(1, 30)}?keywords={quote(_slug(r, 3).replace('-', ' '))}"
                f"&qid={r.randint(10**9, 2 * 10**9)}&sr=8-{r.randint(1, 30)}")
    if kind == 2:      # búsqueda con filtros
        q = "&".join([f"{r.choice(SEARCH_PARAMS)}={quote(_slug(r, 3).replace('-', ' '))}", f"page={r.randint(1, 50)}",
                      "sort=" + r.choice(["relevance", "price_asc", "newest"]),
                      f"filter[category]={r.choice(SECTIONS)}", f"per_page={r.choice([10, 20, 50])}"])
        return f"{base}/search?{q}"
    if kind == 3:      # solo rastreo
        return f"{base}/{_slug(r, r.randint(1, 4))}?" + "&".join(_tracking(r))
    if kind == 4:      # sesión/token
        tok = base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode().rstrip("=")
        return f"{base}/account/orders?session={uuid.uuid4()}&token={tok}&lang={r.choice(['en', 'es', 'pt'])}"
    if kind == 5:      # documentación profunda con ancla
        segs = "/".join(_rand(r, r.randint(3, 10), string.ascii_lowercase) for _ in range(r.randint(3, 7)))
        return f"{base}/docs/{r.choice(['en', 'es'])}/v{r.randint(1, 9)}.{r.randint(0, 20)}/{segs}/index.html#{_slug(r, 2)}"
    if kind == 6:      # vídeo/lista
        return f"{base}/watch?v={_rand(r, 11, string.ascii_letters + string.digits + '-_')}&list=PL{_rand(r, 24)}&t={r.randint(1, 5000)}s"
    if kind == 7:      # redirección con URL codificada en la consulta (legítima: login social, enlaces de salida)
        tgt = quote(f"https://{r.choice(OTHER_DOMAINS)}/{_slug(r, 3)}?a={r.randint(1, 99)}", safe="")
        return f"{base}/{r.choice(['redirect', 'out', 'away', 'l', 'url'])}?{r.choice(['url', 'u', 'target', 'to'])}={tgt}"
    if kind == 8:      # API con JSON codificado (comillas codificadas, llaves, etc.)
        js = quote('{"id":%d,"tags":["%s","%s"],"page":%d}' % (r.randint(1, 9999), r.choice(WORDS_EN),
                                                              r.choice(WORDS_ES), r.randint(1, 9)), safe="")
        return f"{base}/api/v{r.randint(1, 3)}/{r.choice(['items', 'posts', 'search'])}?filter={js}"
    if kind == 9:      # login legítimo (para que 'login'/'account' no signifique phishing por sí solo)
        nxt = quote("/" + _slug(r, 2).replace("-", "/"), safe="")
        return f"{base}/{r.choice(['login', 'signin', 'account/login', 'auth/login', 'secure/account'])}?next={nxt}&lang={r.choice(['en', 'es'])}"
    if kind == 11:     # identificador opaco en la ruta (documentos/archivos compartidos, publicaciones)
        idc = _rand(r, r.randint(10, 44), string.ascii_letters + string.digits + "-_")
        usp = r.choice(["", "?usp=sharing", "?usp=drive_link", f"?id={_rand(r, 8)}"])
        return f"{base}/{r.choice(['d', 'file', 'folders', 'p', 's', 'view', 'doc', 'j'])}/{idc}/{r.choice(['edit', 'view', 'preview', ''])}{usp}"
    if kind == 12:     # identificador opaco en el fragmento (aplicaciones de una sola página)
        return f"{base}/{r.choice(['mail', 'app', 'inbox', 'files'])}/u/{r.randint(0, 3)}/#{r.choice(['inbox', 'sent', 'folder', 'item'])}/{_rand(r, r.randint(20, 40))}"
    if kind == 13:     # token base64 con relleno codificado y parámetros opacos
        tok = _rand(r, r.randint(28, 60), string.ascii_letters + string.digits)
        return (f"{base}/{r.choice(['mail', 'messages', 'item', 'scl/fi'])}/id/{tok}%3D"
                f"?{r.choice(['rlkey', 'ocid', 'igsh', 'ref'])}={_rand(r, r.randint(10, 26))}&st={_rand(r, 8)}")
    # kind == 10: ruta con id numérico y varios parámetros
    return (f"{base}/{r.choice(SECTIONS)}/{r.randint(1, 10**8)}/{_slug(r, r.randint(2, 6))}"
            f"?id={r.randint(1, 10**7)}&ref={r.choice(['home', 'nav', 'footer'])}&cat={r.randint(1, 99)}")


def tracking_suffix(r=random):
    """Parámetros de rastreo para 'ensuciar' una fracción de URLs maliciosas reales (anti-atajo)."""
    return "&".join(_tracking(r))


PARAMS = ["q", "search", "s", "query", "id", "name", "redirect", "url", "page", "msg", "keyword",
          "term", "comment", "text", "input", "data", "ref", "lang", "title", "email", "user", "cat"]


def make_xss_urls(payloads, bases, n, r=random, seed_tag=None):
    """Hasta n URLs únicas con un payload XSS en un parámetro, la ruta o el fragmento.
    Sin parámetro aleatorio exclusivo de XSS: así el modelo no aprende un atajo artificial."""
    out, attempts, max_attempts = set(), 0, n * 12
    while len(out) < n and payloads and attempts < max_attempts:
        attempts += 1
        pl = r.choice(payloads)[:300]
        base = r.choice(bases)
        enc = r.random()
        val = quote(pl) if enc < 0.45 else (pl.replace(" ", "%20") if enc < 0.8 else quote(quote(pl)))
        where = r.random()
        if where < 0.72:       # parámetro de consulta (en bases que ya traen '?', se añade con '&')
            sep = "&" if "?" in base else "?"
            out.add(f"{base}{sep}{r.choice(PARAMS)}={val}")
        elif where < 0.87:     # fragmento (XSS basado en DOM)
            out.add(f"{base.split('#')[0]}#{val}")
        else:                  # segmento de ruta
            out.add(f"{base.split('?')[0].rstrip('/')}/{val}")
    return list(out)
