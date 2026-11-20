"""Capa 1: características léxicas/estructurales de la URL (+ señales de XSS).

Se usa IGUAL en entrenamiento y en el .exe (así no hay desajuste entre ambos).

IMPORTANTE (v2): la URL se NORMALIZA antes de medirla: se quita el esquema
(http/https) y el prefijo "www.". En los datasets públicos el 100% de las URLs
legítimas son https://www... y el 94% del phishing es http://, así que si el modelo
ve esos prefijos aprende el formato del dataset y no la amenaza. El esquema sigue
disponible como dato informativo (`https`), pero NO entra al vector del modelo.
"""
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import urlparse, parse_qsl, unquote

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())   # usa la lista incluida, sin red

SUSP_WORDS = ("login", "signin", "verify", "secure", "account", "update", "bank",
              "confirm", "password", "paypal", "wallet", "suspend")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}

# TLD muy usados en campañas de abuso (lista corta, conservadora)
SUSP_TLDS = {"club", "online", "site", "link", "fit", "cyou", "monster", "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "loan", "work",
             "support", "live", "icu", "buzz", "cfd", "sbs", "rest", "country", "stream",
             "review", "download", "men", "party", "trade", "date", "racing", "win", "bid"}

RISKY_EXT = {"exe", "apk", "scr", "bat", "jar", "msi", "dll", "vbs", "ps1", "cmd", "com", "pif",
             "zip", "rar", "7z", "iso", "img", "dmg", "m68k", "sh", "bin", "lnk", "hta", "js"}
SCRIPT_EXT = {"php", "asp", "aspx", "jsp", "cgi", "pl", "cfm"}

# Marcas muy suplantadas -> etiquetas de dominio legítimas asociadas
BRANDS = {
    "paypal": {"paypal", "paypalobjects"},
    "google": {"google", "googleapis", "googleusercontent", "gstatic", "googlevideo",
               "googletagmanager", "googlesyndication"},
    "apple": {"apple", "icloud", "mzstatic"},
    "microsoft": {"microsoft", "microsoftonline", "windows", "live", "office", "msn", "bing",
                  "azure", "msedge"},
    "amazon": {"amazon", "amazonaws", "media-amazon", "ssl-images-amazon"},
    "facebook": {"facebook", "fbcdn", "fb"}, "instagram": {"instagram", "cdninstagram"},
    "netflix": {"netflix", "nflxext", "nflximg"}, "whatsapp": {"whatsapp"},
    "linkedin": {"linkedin", "licdn"}, "twitter": {"twitter", "twimg"},
    "dropbox": {"dropbox", "dropboxusercontent"}, "adobe": {"adobe"},
    "ebay": {"ebay", "ebaystatic"}, "spotify": {"spotify", "scdn"},
    "steam": {"steampowered", "steamcommunity", "steamstatic"},
    "binance": {"binance"}, "coinbase": {"coinbase"}, "metamask": {"metamask"},
    "chase": {"chase"}, "wellsfargo": {"wellsfargo"}, "bankofamerica": {"bankofamerica"},
    "citibank": {"citibank"}, "hsbc": {"hsbc"}, "dhl": {"dhl"}, "fedex": {"fedex"},
    "usps": {"usps"}, "outlook": {"outlook"}, "office365": {"office365"},
    "yahoo": {"yahoo", "yimg"}, "docusign": {"docusign"},
    "bancolombia": {"bancolombia", "grupobancolombia"}, "davivienda": {"davivienda"},
    "nequi": {"nequi"}, "bbva": {"bbva"},
    "mercadolibre": {"mercadolibre", "mercadopago", "mlstatic"},
    "santander": {"santander"}, "scotiabank": {"scotiabank"}, "itau": {"itau"},
    "daviplata": {"daviplata"}, "bancodebogota": {"bancodebogota"},
    "telegram": {"telegram"}, "tiktok": {"tiktok", "tiktokcdn"},
}
# --- Marcas suplantadas con frecuencia (globales y de Colombia): typosquatting y disfraces ---
# Aporte de la versión del compañero, integrado aquí.
LOOKALIKE_BRANDS = ("paypal", "apple", "icloud", "microsoft", "office365", "outlook", "hotmail", "google",
                    "gmail", "facebook", "instagram", "whatsapp", "netflix", "amazon", "ebay", "dropbox",
                    "docusign", "linkedin", "dhl", "fedex", "binance", "coinbase", "bancolombia",
                    "davivienda", "nequi", "daviplata", "bbva", "itau", "dian", "servientrega")
BRAND_OWNED = {"office", "live", "microsoftonline", "windows", "sharepoint", "office365", "msn",
               "google", "youtube", "gstatic", "googleusercontent", "blogger", "apple", "icloud",
               "facebook", "fb", "instagram", "whatsapp", "meta", "amazon", "amazonaws", "paypal",
               "ebay", "dropbox", "linkedin", "netflix", "dhl", "fedex", "bancolombia",
               "grupobancolombia", "davivienda", "nequi", "bbva", "itau", "dian"}
BRAND_OWNED |= {lab for labs in BRANDS.values() for lab in labs}
try:   # dominios populares de las propias marcas (googleapis.com, amazonvideo.com...)
    from .brand_allowlist import BRAND_OWNED_POPULAR
except ImportError:
    BRAND_OWNED_POPULAR = set()
_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})
_BRAND_RE = re.compile("(" + "|".join(sorted(BRANDS, key=len, reverse=True)) + ")")

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_INT_IP_RE = re.compile(r"^(0x[0-9a-f]+|\d{8,10})$")
_TAG_RE = re.compile(r"<\s*/?\s*(script|img|svg|iframe|body|input|details|video|audio|object|embed)\b")
_EVENT_RE = re.compile(r"(?<![a-z])on(error|load|click|mouse\w+|focus|blur|key\w+|pointer\w+|toggle|begin|start)\s*=")
_JS_RE = re.compile(r"(javascript|vbscript|data)\s*:")
_FUNC_RE = re.compile(r"\b(alert|prompt|confirm|eval)\s*\(|document\.cookie|document\.write|fromcharcode")
_SCHEME_RE = re.compile(r"^\s*([a-z][a-z0-9+.\-]*)://", re.I)
_WWW_RE = re.compile(r"^www\d{0,3}\.", re.I)
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_HEX_RE = re.compile(r"[0-9a-f]{16,}")
_CONS_RE = re.compile(r"[^aeiou0-9\-]{5,}")
_DIGRUN_RE = re.compile(r"\d+")
_URLVAL_RE = re.compile(r"\s*(https?:|//|www\.)")

XSS_KEYS = ("xss_tag", "xss_event", "xss_js_scheme", "xss_func")

FEATURE_NAMES = [
    # --- v1 (sin `https`, que era una fuga del dataset) ---
    "url_len", "host_len", "path_len", "query_len", "n_dots", "n_hyphens_host", "n_slashes",
    "n_digits", "digit_ratio", "n_special", "has_at", "has_ip", "n_subdomains",
    "odd_port", "path_depth", "entropy", "punycode", "susp_words", "shortener", "n_params",
    "xss_tag", "xss_event", "xss_js_scheme", "xss_func", "n_angle", "n_encoded",
    "double_enc", "n_quotes",
    # --- v2: composición ---
    "letter_ratio", "upper_ratio", "special_ratio", "n_underscores", "n_dots_path",
    "longest_token", "hex_token", "max_param_len",
    # --- v2: dominio ---
    "domain_len", "subdomain_len", "tld_len", "susp_tld", "domain_digit_ratio",
    "domain_vowel_ratio", "domain_max_cons_run", "max_digit_run_host", "n_host_tokens",
    "host_entropy", "domain_entropy", "susp_words_host", "int_ip",
    # --- v2: ruta/consulta ---
    "ext_risky", "ext_script", "n_embedded_http", "query_has_url", "path_double_slash",
    "path_entropy", "query_entropy", "has_port",
    # --- v2: suplantación de marca ---
    "brand_in_subdomain", "brand_in_path", "brand_in_domain_mismatch",
    "brand_contains", "brand_disguised", "brand_typo",
]


# Plataformas donde cualquiera publica una página en su propio subdominio. Hay muchísimo phishing en ellas
# pero también muchísimos sitios legítimos (portafolios, blogs, proyectos de curso). Como en los datos hay
# phishing allí y casi ningún legítimo, el modelo aprendía "plataforma = phishing" y bloqueaba sitios
# legítimos. Por eso la plataforma se NEUTRALIZA: usuario.github.io se mide como usuario.com.
PLATFORM_SUFFIXES = ("pages.dev", "github.io", "vercel.app", "netlify.app", "workers.dev", "weebly.com",
                     "weeblysite.com", "blogspot.com", "typedream.app", "webflow.io", "gitbook.io", "framer.app",
                     "framer.website", "web.app", "firebaseapp.com", "herokuapp.com", "wixsite.com",
                     "trycloudflare.com", "replit.app", "repl.co", "bolt.host", "glitch.me", "onrender.com",
                     "azurewebsites.net", "000webhostapp.com", "myshopify.com", "notion.site", "carrd.co",
                     "ngrok.io", "ngrok-free.app", "surge.sh", "wordpress.com", "godaddysites.com",
                     "square.site", "r2.dev", "contaboserver.net", "cprapid.com")
_PLATFORM_RE = re.compile(r"^([^/?#:@]+)\.(?:" + "|".join(re.escape(x) for x in PLATFORM_SUFFIXES) + r")(?=[:/?#]|$)", re.I)


def normalize_url(url: str) -> str:
    """Quita esquema y 'www.' (ver nota del módulo). Devuelve la URL 'desnuda' (sin la barra final de un dominio solo)."""
    u = (url or "").strip()
    u = _SCHEME_RE.sub("", u, count=1)
    u = _WWW_RE.sub("", u, count=1)
    u = _PLATFORM_RE.sub(r"\1.com", u, count=1)          # neutraliza la plataforma de alojamiento
    u = _WWW_RE.sub("", u, count=1)
    if u.endswith("/") and "/" not in u[:-1] and "?" not in u and "#" not in u:
        u = u[:-1]                       # 'dominio.com/' == 'dominio.com' (la barra final era un atajo)
    return u


def has_https(url: str) -> bool:
    m = _SCHEME_RE.match(url or "")
    return bool(m and m.group(1).lower() == "https")


def host_of(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def registered_domain(url_or_host: str) -> str:
    """dominio.tld (p. ej. 'login.example.co.uk' -> 'example.co.uk')."""
    h = host_of(url_or_host) or (url_or_host or "").lower()
    e = _EXTRACT(h)
    return ".".join(p for p in (e.domain, e.suffix) if p)


_EXTRACT_PRIV = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
# Plataformas donde cada cliente tiene su subdominio y que la lista pública no separa
_TENANT_SUFFIX = ("weebly.com", "weeblysite.com", "typedream.app", "blogspot.com", "gitbook.io", "framer.app",
                  "framer.website", "webflow.io", "bolt.host", "replit.app", "wixsite.com", "trycloudflare.com",
                  "cprapid.com", "contaboserver.net")


def is_platform_host(url_or_host: str) -> bool:
    """¿Está alojada en una plataforma donde cualquiera publica páginas (usuario.github.io, x.pages.dev)?"""
    h = host_of(url_or_host) or (url_or_host or "").lower()
    return any(h.endswith("." + t) for t in PLATFORM_SUFFIXES)


def group_domain(url_or_host: str) -> str:
    """Dominio para AGRUPAR al separar entrenamiento/prueba. A diferencia de `registered_domain`,
    cada subdominio de una plataforma compartida (x.pages.dev, x.vercel.app, x.weebly.com) es su propio
    grupo; si no, todo pages.dev caería en una sola partición."""
    h = host_of(url_or_host) or (url_or_host or "").lower()
    for t in _TENANT_SUFFIX:
        if h.endswith("." + t):
            return ".".join(h.split(".")[-(t.count(".") + 2):])
    e = _EXTRACT_PRIV(h)
    return ".".join(p for p in (e.domain, e.suffix) if p)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _decode(s: str) -> str:
    for _ in range(2):                      # decodifica hasta 2 veces (doble codificación)
        d = unquote(s)
        if d == s:
            break
        s = d
    return s


def normalize_label(label: str) -> str:
    """Pasa un dominio a la forma en que se 'lee': decodifica punycode, quita tildes y cambia
    números parecidos a letras (bancol0mbia -> bancolombia)."""
    label = (label or "").lower()
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass
    label = "".join(c for c in unicodedata.normalize("NFKD", label) if not unicodedata.combining(c))
    return label.translate(_LOOKALIKE)


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Levenshtein con corte temprano en `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def brand_hit(domain: str) -> str:
    """Cómo usa una marca el dominio registrado: "" (no la usa o es el oficial), "contiene"
    (nequi-premios), "disfraza" (bancol0mbia, paypa1, punycode) o "casi_igual" (gogle: typosquatting).
    Las marcas de 5 letras o menos solo cuentan como palabra completa entre guiones
    (así no se marca applebees.com ni guardian.com)."""
    raw = (domain or "").lower()
    if raw in BRAND_OWNED or raw in BRAND_OWNED_POPULAR:
        return ""
    norm = normalize_label(raw)
    tokens = [t for t in re.split(r"[-_.]", norm) if t]
    for b in LOOKALIKE_BRANDS:
        if norm == b:
            return "disfraza" if raw != b else ""
        if b in tokens or (len(b) > 5 and b in norm):
            return "contiene" if b in raw else "disfraza"
    for b in LOOKALIKE_BRANDS:
        if len(b) >= 6:
            limit = 1 if len(b) <= 8 else 2
            if any(t[0] == b[0] and _edit_distance(t, b, limit) <= limit for t in tokens + [norm] if len(t) >= 5):
                return "casi_igual"
    return ""


def _brand_mismatch(text: str, dom: str) -> int:
    m = _BRAND_RE.search(text)
    if not m:
        return 0
    b = m.group(1)
    return int(dom != b and dom not in BRANDS.get(b, ()))


def has_xss_signal(f: dict) -> bool:
    return any(f[k] for k in XSS_KEYS)


def extract_url_features(url: str) -> dict:
    raw = (url or "").strip()
    n_url = normalize_url(raw)
    try:
        p = urlparse("http://" + n_url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        p, host, port = urlparse("http://invalido"), "", None
    ext = _EXTRACT(host)
    low = _decode(n_url).lower()
    low_path = _decode(p.path or "").lower()
    low_query = _decode(p.query or "").lower()
    n = max(len(n_url), 1)
    digits = sum(ch.isdigit() for ch in n_url)
    letters = sum(ch.isalpha() for ch in n_url)
    uppers = sum(ch.isupper() for ch in n_url)
    n_other_special = sum(1 for ch in n_url if not ch.isalnum() and ch not in "./-")

    dom, sub, tld = ext.domain or "", ext.subdomain or "", ext.suffix or ""
    dom_l = dom.lower()
    host_tokens = [t for t in re.split(r"[.\-]", host) if t]
    tokens = _TOKEN_RE.findall(n_url)
    last = (p.path or "").rstrip("/").rsplit("/", 1)[-1]
    fext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
    try:
        params = parse_qsl(p.query, keep_blank_values=True)
    except ValueError:
        params = []

    bk = brand_hit(dom_l)
    return {
        "_brand_kind": bk,                                  # solo para los motivos; no entra al modelo
        "url_len": len(n_url), "host_len": len(host), "path_len": len(p.path or ""),
        "query_len": len(p.query or ""), "n_dots": host.count("."),
        "n_hyphens_host": host.count("-"), "n_slashes": n_url.count("/"),
        "n_digits": digits, "digit_ratio": digits / n,
        "n_special": sum(n_url.count(c) for c in "@?&=%;"),
        "has_at": int("@" in (p.netloc or "")), "has_ip": int(bool(_IP_RE.match(host))),
        "n_subdomains": len([s for s in sub.split(".") if s]),
        "https": int(has_https(raw)),                       # informativo; NO entra al modelo
        "odd_port": int(port not in (None, 80, 443)),
        "path_depth": len([s for s in (p.path or "").split("/") if s]),
        "entropy": entropy(n_url), "punycode": int("xn--" in host),
        "susp_words": sum(w in low for w in SUSP_WORDS), "shortener": int(host in SHORTENERS),
        "n_params": len(params),
        "xss_tag": int(bool(_TAG_RE.search(low))), "xss_event": int(bool(_EVENT_RE.search(low))),
        "xss_js_scheme": int(bool(_JS_RE.search(low))), "xss_func": int(bool(_FUNC_RE.search(low))),
        "n_angle": low.count("<") + low.count(">"), "n_encoded": n_url.count("%"),
        "double_enc": int("%25" in n_url), "n_quotes": low.count('"') + low.count("'"),
        # v2 composición
        "letter_ratio": letters / n, "upper_ratio": uppers / n, "special_ratio": n_other_special / n,
        "n_underscores": n_url.count("_"), "n_dots_path": (p.path or "").count("."),
        "longest_token": max((len(t) for t in tokens), default=0),
        "hex_token": int(bool(_HEX_RE.search(low))),
        "max_param_len": max((len(v) for _, v in params), default=0),
        # v2 dominio
        "domain_len": len(dom), "subdomain_len": len(sub), "tld_len": len(tld),
        "susp_tld": int(tld.split(".")[-1] in SUSP_TLDS),
        "domain_digit_ratio": sum(ch.isdigit() for ch in dom) / max(len(dom), 1),
        "domain_vowel_ratio": sum(ch in "aeiou" for ch in dom_l) / max(len(dom), 1),
        "domain_max_cons_run": max((len(m.group(0)) for m in _CONS_RE.finditer(dom_l)), default=0),
        "max_digit_run_host": max((len(m.group(0)) for m in _DIGRUN_RE.finditer(host)), default=0),
        "n_host_tokens": len(host_tokens),
        "host_entropy": entropy(host), "domain_entropy": entropy(dom),
        "susp_words_host": sum(w in host for w in SUSP_WORDS),
        "int_ip": int(bool(_INT_IP_RE.match(host))),
        # v2 ruta/consulta
        "ext_risky": int(fext in RISKY_EXT), "ext_script": int(fext in SCRIPT_EXT),
        "n_embedded_http": len(re.findall(r"https?:", low_path + "?" + low_query)),
        "query_has_url": int(any(_URLVAL_RE.match(_decode(v).lower()) for _, v in params)),
        "path_double_slash": int("//" in (p.path or "")),
        "path_entropy": entropy(low_path), "query_entropy": entropy(low_query),
        "has_port": int(port is not None),
        # v2 marca suplantada
        "brand_in_subdomain": _brand_mismatch(sub.lower(), dom_l),
        "brand_in_path": _brand_mismatch(low_path, dom_l),
        "brand_in_domain_mismatch": _brand_mismatch(dom_l, dom_l),
        "brand_contains": int(bk == "contiene"), "brand_disguised": int(bk == "disfraza"),
        "brand_typo": int(bk == "casi_igual"),
    }


def to_vector(feats: dict) -> list:
    return [feats[k] for k in FEATURE_NAMES]
