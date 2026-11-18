"""Capa 2: análisis del contenido HTML con reglas. Es la capa con MÁS peso en la decisión final
(ver engine.py y config.py): mira lo que la página realmente hace, no solo cómo se ve la URL."""
import re
from urllib.parse import urlparse, parse_qsl, unquote

from bs4 import BeautifulSoup

from .features_url import BRANDS, BRAND_OWNED, _EXTRACT

RISKY_JS = ("eval(", "document.write(", "unescape(", "atob(", "fromcharcode", ".innerhtml", "document.cookie")
_PW = re.compile(r"^password$", re.I)
_SENSITIVE = re.compile(r"(card|tarjeta|cvv|cvc|ccnum|expir|vencim|pin|otp|token|clave|cedula|ssn)", re.I)
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)
_NO_RIGHT_CLICK = re.compile(r"oncontextmenu\s*=\s*['\"]?\s*return\s+false|event\.button\s*==\s*2", re.I)

# (característica, peso, motivo). El puntaje de la capa es la suma de pesos, máximo 1.
RULES = [
    ("pw_form_external", 0.60, "Formulario de contraseña que envía los datos a otro dominio"),
    ("brand_impersonation", 0.55, "La página usa el nombre de una marca que no corresponde al dominio y pide datos de acceso"),
    ("reflected_params", 0.60, "Un parámetro de la URL se refleja sin codificar en la página (posible XSS)"),
    ("form_suspicious_action", 0.35, "Un formulario envía los datos a un correo, a una dirección vacía o a JavaScript"),
    ("sensitive_inputs", 0.30, "Pide datos sensibles (tarjeta, CVV, PIN, código o documento)"),
    ("meta_refresh_external", 0.30, "Redirige automáticamente a otro dominio"),
    ("has_password", 0.15, "Tiene un campo de contraseña"),
    ("hidden_iframes", 0.20, "Tiene iframes ocultos"),
    ("risky_js", 0.20, "Scripts con funciones de riesgo (eval, document.write, atob...)"),
    ("external_favicon", 0.15, "El ícono de la página se carga desde otro dominio"),
    ("mostly_external_links", 0.15, "Casi todos los enlaces apuntan a otro dominio"),
    ("null_links", 0.15, "Muchos enlaces vacíos o que no llevan a ningún lado (#, javascript:void)"),
    ("no_right_click", 0.10, "Bloquea el clic derecho"),
    ("ext_scripts", 0.10, "Carga muchos scripts desde dominios externos"),
]


def _reg_domain(host: str) -> str:
    e = _EXTRACT(host or "")
    return f"{e.domain}.{e.suffix}".lower() if e.suffix else (host or "").lower()


def _other_site(link: str, reg: str) -> bool:
    """True si el enlace apunta a un dominio registrado distinto al de la página."""
    if not link.startswith(("http://", "https://", "//")):
        return False
    h = urlparse(link if not link.startswith("//") else "http:" + link).hostname or ""
    return bool(h) and _reg_domain(h) != reg


def analyze_content(html: str, page_url: str):
    """Devuelve (score 0-1, características, motivos)."""
    soup = BeautifulSoup(html, "lxml")
    host = (urlparse(page_url if "://" in page_url else "http://" + page_url).hostname or "").lower()
    reg = _reg_domain(host)
    domain = _EXTRACT(host).domain.lower()
    f = {}

    # --- formularios ---
    ext_pw = susp_action = 0
    for fm in soup.find_all("form"):
        has_pw = fm.find("input", {"type": _PW}) is not None
        act = (fm.get("action") or "").strip().lower()
        if has_pw and _other_site(act, reg):
            ext_pw += 1
        if act.startswith(("mailto:", "javascript:", "about:blank")) or (has_pw and act in ("", "#")
                                                                       and fm.get("onsubmit")):
            susp_action += 1
    f["pw_form_external"] = ext_pw
    f["form_suspicious_action"] = susp_action
    f["has_password"] = int(soup.find("input", {"type": _PW}) is not None)
    f["sensitive_inputs"] = int(any(_SENSITIVE.search(" ".join(str(i.get(a, "")) for a in ("name", "id", "placeholder")))
                                    for i in soup.find_all("input") if i.get("type", "text").lower() != "hidden"))

    # --- suplantación de marca: nombre de marca en título/encabezados/logo, dominio ajeno y pide datos ---
    visible = " ".join([soup.title.get_text(" ") if soup.title else ""]
                       + [h.get_text(" ") for h in soup.find_all(["h1", "h2"])[:5]]
                       + [im.get("alt", "") for im in soup.find_all("img")[:20]]).lower()
    brands_seen = [b for b in BRANDS if b in visible and b not in domain]
    f["brand_impersonation"] = int(bool(brands_seen) and domain not in BRAND_OWNED
                                   and (f["has_password"] or f["sensitive_inputs"]))

    # --- iframes, redirecciones y scripts ---
    hidden = 0
    for fr in soup.find_all("iframe"):
        st = (fr.get("style") or "").replace(" ", "").lower()
        if fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1") \
                or "display:none" in st or "visibility:hidden" in st:
            hidden += 1
    f["hidden_iframes"] = hidden

    refresh = 0
    for m in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        u = _REFRESH_URL.search(m.get("content", ""))
        if u and _other_site(u.group(1).strip(), reg):
            refresh += 1
    f["meta_refresh_external"] = refresh

    scripts = soup.find_all("script")
    inline_js = " ".join((s.string or "") for s in scripts if not s.get("src")).lower()
    f["risky_js"] = int(sum(inline_js.count(k) for k in RISKY_JS) >= 3)
    f["ext_scripts"] = int(sum(_other_site(s.get("src", ""), reg) for s in scripts) >= 4)
    f["no_right_click"] = int(bool(_NO_RIGHT_CLICK.search(html[:200_000])))
    f["inline_handlers"] = sum(1 for t in soup.find_all(True) for a in t.attrs if a.lower().startswith("on"))

    icons = [l.get("href", "") for l in soup.find_all("link", rel=True)
             if any("icon" in r.lower() for r in l.get("rel", []))]
    f["external_favicon"] = int(any(_other_site(h, reg) for h in icons))

    # --- enlaces ---
    hrefs = [(a.get("href") or "").strip().lower() for a in soup.find_all("a")]
    n = len(hrefs)
    null = sum(h in ("", "#", "#!") or h.startswith("javascript:") for h in hrefs)
    ext = sum(_other_site(h, reg) for h in hrefs)
    f["n_links"] = n
    f["null_links"] = int(n >= 5 and null / n >= 0.5)
    f["mostly_external_links"] = int(n >= 5 and ext / n >= 0.8)

    # --- XSS reflejado ---
    reflected = 0
    for _, v in parse_qsl(urlparse(page_url).query):
        v = unquote(v)
        if len(v) >= 4 and re.search(r"[<>\"']", v) and v in html:   # vuelve sin codificar
            reflected += 1
    f["reflected_params"] = reflected

    score, reasons = 0.0, []
    for name, weight, reason in RULES:
        if f[name]:
            score += weight
            reasons.append(reason + (f" ({', '.join(brands_seen)})" if name == "brand_impersonation" else ""))
    f["content_score"] = min(score, 1.0)
    return f["content_score"], f, reasons
