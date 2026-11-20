"""Capa 2 (v2): análisis del HTML estático. Reglas con peso por evidencia (no ejecuta JavaScript).

Qué cambió respecto a v1 (a partir de los falsos positivos revisados a mano en VirusTotal):
  * El dominio de destino de un formulario se compara por DOMINIO REGISTRADO (login.x.com == www.x.com)
    y se aceptan proveedores de inicio de sesión conocidos (Google, Microsoft, Apple, GitHub...).
  * Los <iframe> ocultos de analítica (Google Tag Manager, DoubleClick, Facebook Pixel...) ya no cuentan.
  * "Muchos scripts externos" se eliminó (es normal en sitios con analítica/publicidad) y `eval`/`atob`
    solo cuentan si aparecen COMBINADOS (ofuscación), no por separado.
  * Señales nuevas de phishing: marca en el título que no coincide con el dominio, logos/estilos
    enganchados desde el dominio de la marca, redirección <meta refresh> a otro dominio, formulario
    de contraseña hacia una IP, página casi sin contenido con formulario de acceso, enlaces vacíos,
    campos de tarjeta/PIN.

Devuelve (score 0-1, características, motivos). Cada señal suma su peso; una sola señal fuerte
(>= 0.5) basta para marcar, las débiles solo suman en conjunto.
"""
import re
from urllib.parse import urlparse, parse_qsl, unquote, urljoin

from bs4 import BeautifulSoup

from .features_url import BRANDS, has_https, registered_domain

_PW = re.compile(r"^password$", re.I)
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_BRAND_RE = re.compile("(" + "|".join(sorted(BRANDS, key=len, reverse=True)) + ")", re.I)
_SENSITIVE = re.compile(r"cvv|cvc|card.?n(um|o)|ccnum|cc-number|\bssn\b|\bpin\b|iban|clabe|c[eé]dula|tarjeta", re.I)
_DECODERS = ("atob(", "unescape(", "fromcharcode", "string.fromcharcode")
_RISKY_FILE = re.compile(r"\.(exe|scr|apk|msi|bat|jar|vbs|ps1|lnk|hta)(\?|$)", re.I)

# Inicio de sesión de terceros legítimo: un formulario con contraseña puede apuntar a ellos
TRUSTED_AUTH = {"google.com", "accounts.google.com", "microsoftonline.com", "live.com", "microsoft.com",
                "apple.com", "facebook.com", "github.com", "okta.com", "auth0.com", "amazon.com",
                "twitter.com", "x.com", "linkedin.com", "paypal.com", "salesforce.com", "force.com",
                "atlassian.com", "slack.com", "zoom.us", "dropbox.com", "yahoo.com", "adobe.com"}
# Píxeles/analítica cuyos <iframe> ocultos son normales
TRACKER_HOSTS = ("googletagmanager.com", "google-analytics.com", "doubleclick.net", "facebook.com",
                 "facebook.net", "hotjar.com", "clarity.ms", "googlesyndication.com", "bing.com",
                 "linkedin.com", "adsrvr.org", "criteo.com", "tiktok.com")


def _reg(url_or_host: str) -> str:
    return registered_domain(url_or_host or "")


def _brand_of(text: str):
    m = _BRAND_RE.search(text or "")
    return m.group(1).lower() if m else None


def analyze_content(html: str, page_url: str):
    """Devuelve (score 0-1, características, motivos)."""
    soup = BeautifulSoup(html, "lxml")
    page_url = page_url if "://" in page_url else "http://" + page_url
    host = (urlparse(page_url).hostname or "").lower()
    page_dom = _reg(host)
    dom_label = page_dom.split(".")[0] if page_dom else ""
    reasons, f = [], {}

    pw_inputs = soup.find_all("input", {"type": _PW})
    has_pw = bool(pw_inputs)
    f["has_password"] = int(has_pw)
    names = " ".join((i.get("name") or "") + " " + (i.get("id") or "") + " " + (i.get("autocomplete") or "")
                     for i in soup.find_all("input"))
    f["sensitive_fields"] = int(len(set(_SENSITIVE.findall(names))) >= 2 or len(_SENSITIVE.findall(names)) >= 2)

    # ---- formularios con contraseña ----
    ext_pw = ip_pw = 0
    ext_hosts = set()
    for fm in soup.find_all("form"):
        if fm.find("input", {"type": _PW}) is None:
            continue
        act = (fm.get("action") or "").strip()
        if not act.startswith(("http://", "https://", "//")):
            continue                                     # ruta relativa / vacío / javascript: -> mismo sitio
        a_host = (urlparse(urljoin(page_url, act)).hostname or "").lower()
        a_dom = _reg(a_host)
        if _IP.match(a_host) and a_host != host:
            ip_pw += 1
        elif a_dom and a_dom != page_dom and a_dom not in TRUSTED_AUTH and a_host not in TRUSTED_AUTH:
            ext_pw += 1
            ext_hosts.add(a_dom)
    f["pw_form_external"], f["pw_form_ip"] = ext_pw, ip_pw

    # ---- marca en título/metadatos que no coincide con el dominio ----
    title = (soup.title.string or "") if soup.title and soup.title.string else ""
    metas = " ".join((m.get("content") or "") for m in soup.find_all("meta", {"property": re.compile("og:(title|site_name)")}))
    brand = _brand_of(title + " " + metas)
    brand_mismatch = int(bool(brand and (has_pw or f["sensitive_fields"]) and dom_label != brand and dom_label not in BRANDS.get(brand, ())))
    f["brand_title_mismatch"] = brand_mismatch

    # ---- recursos (logos/estilos) enganchados desde el dominio de una marca ajena ----
    hotlink = 0
    if has_pw:
        for t, attr in (("img", "src"), ("link", "href"), ("script", "src")):
            for el in soup.find_all(t):
                src = (el.get(attr) or "").strip()
                if src.startswith(("http://", "https://", "//")):
                    r_dom = _reg(urlparse(urljoin(page_url, src)).hostname or "")
                    b = _brand_of(r_dom.split(".")[0] if r_dom else "")
                    if b and r_dom != page_dom and dom_label != b and dom_label not in BRANDS.get(b, ()):
                        hotlink += 1
    f["brand_hotlink"] = int(hotlink >= 2)

    # ---- iframes ocultos (sin contar analítica) ----
    hidden = 0
    for fr in soup.find_all("iframe"):
        st = (fr.get("style") or "").replace(" ", "").lower()
        src = (fr.get("src") or "").lower()
        is_hidden = (fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1")
                     or "display:none" in st or "visibility:hidden" in st)
        if not is_hidden:
            continue
        s_host = (urlparse(urljoin(page_url, src)).hostname or "").lower() if src else ""
        if any(s_host.endswith(t) for t in TRACKER_HOSTS) or not s_host or _reg(s_host) == page_dom:
            continue
        hidden += 1
    f["hidden_iframes"] = hidden

    # ---- JavaScript ofuscado (eval + decodificador, combinados) ----
    inline_js = " ".join((s.string or "") for s in soup.find_all("script") if not s.get("src")).lower()
    n_eval = inline_js.count("eval(") + inline_js.count("new function(")
    n_dec = sum(inline_js.count(k) for k in _DECODERS)
    f["obfuscated_js"] = int(n_eval >= 1 and n_dec >= 1 and (n_eval + n_dec) >= 3)
    f["doc_write_unescape"] = int("document.write(unescape(" in inline_js)
    f["no_rightclick"] = int(bool(re.search(r"oncontextmenu\s*=\s*[\"']?\s*return\s+false|addEventListener\(\s*[\"']contextmenu", html, re.I)))

    # ---- redirección <meta refresh> o location a otro dominio ----
    redir = 0
    for m in soup.find_all("meta", {"http-equiv": re.compile("refresh", re.I)}):
        mm = re.search(r"url\s*=\s*['\"]?([^'\";]+)", m.get("content") or "", re.I)
        if mm:
            t_dom = _reg(urlparse(urljoin(page_url, mm.group(1).strip())).hostname or "")
            redir += int(bool(t_dom and t_dom != page_dom))
    f["meta_refresh_external"] = redir

    # ---- contenido escaso + formulario de acceso, enlaces vacíos, campos sensibles ----
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    words = len(soup.get_text(" ", strip=True).split())
    anchors = soup.find_all("a")
    empty = sum(1 for a in anchors if (a.get("href") or "#").strip() in ("#", "", "javascript:void(0)", "javascript:;"))
    f["thin_login_page"] = int(has_pw and words < 80 and len(anchors) < 6)
    f["empty_links"] = int(has_pw and len(anchors) >= 5 and empty / len(anchors) >= 0.5)
    f["risky_download"] = int(any(_RISKY_FILE.search(a.get("href") or "") for a in anchors))
    f["pw_over_http"] = int(has_pw and not has_https(page_url))

    # ---- XSS reflejado (parámetro con < > " ' que vuelve sin codificar) ----
    reflected = 0
    for _, v in parse_qsl(urlparse(page_url).query):
        v = unquote(v)
        if len(v) >= 4 and re.search(r"[<>\"']", v) and v in html:
            reflected += 1
    f["reflected_params"] = reflected

    # ---- puntaje: suma de pesos por evidencia ----
    W = [
        (ext_pw, 0.55, "Formulario de contraseña que envía los datos a otro dominio"),
        (ip_pw, 0.45, "Formulario de contraseña que envía los datos a una dirección IP"),
        (brand_mismatch, 0.50, f"El título menciona '{brand}' pero el dominio no es el de esa marca"),
        (f["brand_hotlink"], 0.30, "Carga logos/estilos desde el dominio de una marca que no es la de este sitio"),
        (reflected, 0.60, "Un parámetro de la URL se refleja sin codificar en la página (posible XSS)"),
        (min(hidden, 2), 0.20, "iframe(s) oculto(s) que cargan contenido de otro dominio"),
        (f["obfuscated_js"], 0.20, "JavaScript ofuscado (eval combinado con decodificadores)"),
        (f["doc_write_unescape"], 0.20, "Escribe código decodificado con document.write(unescape(...))"),
        (min(redir, 1), 0.30, "Redirige automáticamente (meta refresh) a otro dominio"),
        (f["thin_login_page"], 0.15, "Página casi sin contenido cuyo centro es un formulario de acceso"),
        (f["empty_links"], 0.10, "La mayoría de enlaces están vacíos ('#')"),
        (f["sensitive_fields"], 0.20, "Pide datos sensibles (tarjeta, CVV, PIN, cédula...)"),
        (f["no_rightclick"] and has_pw, 0.10, "Bloquea el clic derecho en una página de acceso"),
        (f["pw_over_http"], 0.15, "Pide contraseña sin usar HTTPS"),
        (f["risky_download"], 0.10, "Enlaza a ejecutables/instaladores"),
    ]
    score = 0.0
    for n, w, msg in W:
        if n:
            score += w
            reasons.append(msg)
    f["content_score"] = min(score, 1.0)
    return f["content_score"], f, reasons
