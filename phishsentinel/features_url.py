"""Capa 1: características léxicas/estructurales de la URL (+ señales de XSS).
Se usa IGUAL en entrenamiento y en el .exe (así no hay desajuste entre ambos).

Las características se calculan sobre la URL canónica: sin esquema (http/https) y sin
'www.' al inicio. En el dataset original casi todas las legítimas empiezan con
'https://www.' y casi ninguna de phishing, así que el modelo aprendía ese atajo en vez de
mirar la URL. 'https' se sigue calculando para la heurística y los motivos, pero NO entra
al vector del modelo."""
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
# Marcas suplantadas con frecuencia (globales y de Colombia). Si aparecen en el subdominio o la
# ruta pero el dominio registrado NO es de la marca, es una señal fuerte de suplantación.
BRANDS = ("paypal", "apple", "icloud", "microsoft", "office365", "outlook", "hotmail", "google",
          "gmail", "facebook", "instagram", "whatsapp", "netflix", "amazon", "ebay", "dropbox",
          "docusign", "linkedin", "dhl", "fedex", "binance", "coinbase", "bancolombia",
          "davivienda", "nequi", "daviplata", "bbva", "itau", "dian", "servientrega")
# TLD baratos o gratuitos muy usados en campañas de phishing.
SUSP_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site", "icu", "buzz",
             "live", "rest", "click", "link", "work", "fit", "cyou", "monster", "sbs", "cfd", "zip"}
# Dominios propios de esas marcas (subdominios como outlook.office.com o mail.google.com).
BRAND_OWNED = {"office", "live", "microsoftonline", "windows", "sharepoint", "office365", "msn",
               "google", "youtube", "gstatic", "googleusercontent", "blogger", "apple", "icloud",
               "facebook", "fb", "instagram", "whatsapp", "meta", "amazon", "amazonaws", "paypal",
               "ebay", "dropbox", "linkedin", "netflix", "dhl", "fedex", "bancolombia",
               "grupobancolombia", "davivienda", "nequi", "bbva", "itau", "dian"}
try:   # dominios populares de las propias marcas (googleapis.com, amazonvideo.com...): ver brand_allowlist.py
    from .brand_allowlist import BRAND_OWNED_POPULAR
except ImportError:
    BRAND_OWNED_POPULAR = set()
# Sustituciones típicas para disfrazar una marca: bancol0mbia, paypa1, micr0soft, app1e.
_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})
RISKY_EXT = (".exe", ".scr", ".zip", ".rar", ".apk", ".msi", ".bat", ".js")

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_TAG_RE = re.compile(r"<\s*/?\s*(script|img|svg|iframe|body|input|details|video|audio|object|embed)\b")
_EVENT_RE = re.compile(r"(?<![a-z])on(error|load|click|mouse\w+|focus|blur|key\w+|pointer\w+|toggle|begin|start)\s*=")
_JS_RE = re.compile(r"(javascript|vbscript|data)\s*:")
_FUNC_RE = re.compile(r"\b(alert|prompt|confirm|eval)\s*\(|document\.cookie|document\.write|fromcharcode")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_EMBEDDED_DOMAIN_RE = re.compile(r"(www\.|\.(com|net|org|co|info|biz|io)\b)")
_TOKEN_RE = re.compile(r"[/?&=._\-:@+~#]+")

# Grupos de características: permiten comparar qué combinación da mejor resultado
# (pregunta de investigación del proyecto).
FEATURE_GROUPS = {
    "lexicas": ["url_len", "path_len", "query_len", "n_slashes", "n_digits", "digit_ratio",
                "n_special", "path_depth", "entropy", "susp_words", "n_params",
                "longest_token", "n_http_inside", "embedded_domain", "risky_ext", "php_ext",
                "brand_out_of_domain"],
    "dominio": ["host_len", "n_dots", "n_hyphens_host", "has_at", "has_ip", "n_subdomains",
                "odd_port", "punycode", "shortener", "domain_len", "domain_digits",
                "domain_hyphens", "domain_entropy", "susp_tld", "brand_in_domain"],
    "xss": ["xss_tag", "xss_event", "xss_js_scheme", "xss_func", "n_angle", "n_encoded",
            "double_enc", "n_quotes"],
}
FEATURE_NAMES = [name for group in FEATURE_GROUPS.values() for name in group]


def host_of(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def canonical(url: str) -> str:
    """URL sin esquema, sin 'www.' inicial y sin '/' final: 'https://www.a.com/x/' -> 'a.com/x'."""
    u = _SCHEME_RE.sub("", (url or "").strip()).rstrip("/")
    return u[4:] if u.lower().startswith("www.") else u


def normalize_label(label: str) -> str:
    """Pasa un dominio a la forma en que se 'lee': decodifica punycode (xn--bancolmbia-l8a ->
    bancolómbia), quita tildes y cambia números parecidos a letras (bancol0mbia -> bancolombia)."""
    label = (label or "").lower()
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass
    label = "".join(c for c in unicodedata.normalize("NFKD", label) if not unicodedata.combining(c))
    return label.translate(_LOOKALIKE)


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Distancia de Levenshtein, cortando apenas supera 'limit' (para que sea rápida)."""
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
    (nequi-premios, soporte-apple-id), "disfraza" (bancol0mbia, paypa1, punycode) o "casi_igual"
    (baincolmbia, gogle: typosquatting). Las marcas de 5 letras o menos (apple, nequi, dhl, bbva,
    dian) solo cuentan como palabra completa entre guiones: así no se marca applebees.com,
    pineapple.com ni guardian.com."""
    raw = (domain or "").lower()
    if raw in BRAND_OWNED or raw in BRAND_OWNED_POPULAR:
        return ""
    norm = normalize_label(raw)
    tokens = [t for t in re.split(r"[-_.]", norm) if t]
    for b in BRANDS:
        if norm == b:
            return "disfraza" if raw != b else ""
        if b in tokens or (len(b) > 5 and b in norm):
            return "contiene" if b in raw else "disfraza"
    for b in BRANDS:
        if len(b) >= 6:                          # una o dos letras de diferencia, misma inicial
            limit = 1 if len(b) <= 8 else 2
            if any(t[0] == b[0] and _edit_distance(t, b, limit) <= limit for t in tokens + [norm] if len(t) >= 5):
                return "casi_igual"
    return ""


def brand_in_domain(domain: str) -> int:
    return int(bool(brand_hit(domain)))


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


def extract_url_features(url: str) -> dict:
    url = (url or "").strip()
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        p, host, port = urlparse("http://invalido"), "", None
    host_nw = host[4:] if host.startswith("www.") else host
    ext = _EXTRACT(host_nw)
    domain = ext.domain.lower()
    cu = canonical(url)                     # lo que miden las características de texto
    try:                                    # ruta y consulta también sobre la canónica (sin '/' final)
        pc = urlparse("http://" + cu)
        pc.port
    except ValueError:
        pc = p
    low = _decode(cu).lower()
    rest = low[len(host_nw):]               # todo lo que va después del host (ruta + consulta)
    path_low = unquote(pc.path or "").lower()
    n = max(len(cu), 1)
    digits = sum(ch.isdigit() for ch in cu)
    sub_and_path = ext.subdomain.lower() + " " + path_low   # sin la consulta: utm_source=facebook es normal
    return {
        "url_len": len(cu), "host_len": len(host_nw), "path_len": len(pc.path or ""),
        "query_len": len(pc.query or ""), "n_dots": host_nw.count("."),
        "n_hyphens_host": host_nw.count("-"), "n_slashes": cu.count("/"),
        "n_digits": digits, "digit_ratio": digits / n,
        "n_special": sum(cu.count(c) for c in "@?&=%;"),
        "has_at": int("@" in (p.netloc or "")), "has_ip": int(bool(_IP_RE.match(host))),
        "n_subdomains": len([s for s in ext.subdomain.split(".") if s]),
        "https": int(p.scheme == "https"), "odd_port": int(port not in (None, 80, 443)),
        "path_depth": len([s for s in (pc.path or "").split("/") if s]),
        "entropy": entropy(cu), "punycode": int("xn--" in host),
        "susp_words": sum(w in low for w in SUSP_WORDS), "shortener": int(host_nw in SHORTENERS),
        "n_params": len(parse_qsl(pc.query)),
        # --- nuevas (corrección: más características) ---
        "domain_len": len(domain),
        "domain_digits": sum(ch.isdigit() for ch in domain),
        "domain_hyphens": domain.count("-"),
        "domain_entropy": entropy(domain),
        "susp_tld": int(ext.suffix.split(".")[-1] in SUSP_TLDS) if ext.suffix else 0,
        "brand_in_domain": int(bool(brand_kind := brand_hit(domain))),
        "_brand_kind": brand_kind,          # solo para los motivos; no entra al modelo
        "_official_brand": int(domain in BRAND_OWNED or domain in BRAND_OWNED_POPULAR),
        "brand_out_of_domain": int(domain not in BRAND_OWNED
                                   and any(b in sub_and_path for b in BRANDS if b not in domain)),
        "embedded_domain": int(bool(_EMBEDDED_DOMAIN_RE.search(path_low))),
        "n_http_inside": low.count("http"),   # la URL canónica ya no trae su propio esquema
        "longest_token": max((len(t) for t in _TOKEN_RE.split(rest) if t), default=0),
        "risky_ext": int(path_low.endswith(RISKY_EXT)),
        "php_ext": int(".php" in path_low),
        # --- señales de XSS ---
        "xss_tag": int(bool(_TAG_RE.search(low))), "xss_event": int(bool(_EVENT_RE.search(low))),
        "xss_js_scheme": int(bool(_JS_RE.search(low))), "xss_func": int(bool(_FUNC_RE.search(low))),
        "n_angle": low.count("<") + low.count(">"), "n_encoded": cu.count("%"),
        "double_enc": int("%25" in cu), "n_quotes": low.count('"') + low.count("'"),
    }


def to_vector(feats: dict, names=None) -> list:
    return [feats[k] for k in (names or FEATURE_NAMES)]
