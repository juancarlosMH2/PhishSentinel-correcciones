"""Motor de decisión v2: capa 1 (URL + ML) y capa 2 (contenido) con zona de duda.

    p1 = probabilidad de que la URL sea maliciosa (capa 1)

      p1 <  T_LOW        ──►  segura       (la capa 1 deja pasar; no se contacta el sitio)
      p1 >= T_HIGH       ──►  peligrosa    (la capa 1 bloquea directo; no se contacta el sitio)
      T_LOW <= p1 < T_HIGH ─►  ZONA DE DUDA: se descarga el HTML y MANDA LA CAPA 2
                              puntaje = 0.35*p1 + 0.65*contenido

    T_LOW y T_HIGH están calibrados con datos de validación y guardados dentro del modelo.
    "Análisis profundo": además consulta la capa 2 fuera de la zona de duda (solo puede SUBIR el puntaje).
    Un código inyectado en la URL (XSS) NUNCA se anula con una excepción de dominio.
"""
import time
from dataclasses import dataclass, field

import joblib

from . import config, storage
from .features_content import analyze_content
from .features_url import extract_url_features, has_xss_signal, host_of, is_platform_host, registered_domain
from .popular_domains import POPULAR_DOMAINS
from .domain_age import age_bonus, domain_age_days
from .fetcher import fetch_page


@dataclass
class Verdict:
    url: str
    level: str                 # segura | sospechosa | peligrosa
    threat: str                # ninguna | phishing | malware | xss
    score: float
    reasons: list = field(default_factory=list)
    ms_url: float = 0.0
    ms_content: float = 0.0
    used_model: bool = False
    url_score: float = 0.0     # probabilidad de la capa 1 (0-1)
    content_score: float = None  # riesgo de contenido de la capa 2 (None = no consultada)
    zone: str = ""             # baja | duda | alta | excepcion
    decided_by: str = ""       # capa 1 | capa 2 | excepcion | ambas
    content_checked: bool = False


def _heuristic(f: dict) -> float:
    """Respaldo cuando todavía no hay modelo entrenado."""
    s = 0.35 * f["has_ip"] + 0.25 * f["has_at"] + 0.15 * f["punycode"] + 0.10 * min(f["susp_words"], 3) / 3
    s += 0.15 * (f["n_subdomains"] >= 3) + 0.10 * f["shortener"] + 0.20 * f["brand_in_subdomain"]
    s += 0.5 * max(f["xss_tag"], f["xss_event"], f["xss_js_scheme"])
    return min(s, 1.0)


def _reasons_url(f: dict) -> list:
    r = []
    if f["has_ip"]: r.append("Usa una dirección IP en lugar de un dominio")
    if f["has_at"]: r.append("Contiene '@' en la dirección (suele ocultar el destino real)")
    if f["punycode"]: r.append("Dominio con punycode (posible suplantación visual)")
    if f["shortener"]: r.append("Acortador de enlaces: no se ve el destino real")
    if f["n_subdomains"] >= 3: r.append("Demasiados subdominios")
    if f["susp_words"] >= 2: r.append("Palabras típicas de phishing en la URL (login, verify, secure...)")
    kind = f.get("_brand_kind", "")
    if kind == "disfraza":
        r.append("Imita el nombre de una marca con números, símbolos o punycode (p. ej. bancol0mbia)")
    elif kind == "casi_igual":
        r.append("Nombre casi igual al de una marca conocida (posible typosquatting)")
    elif kind == "contiene":
        r.append("Usa el nombre de una marca conocida, pero el dominio no es el oficial")
    elif f["brand_in_subdomain"] or f["brand_in_path"] or f["brand_in_domain_mismatch"]:
        r.append("Menciona una marca conocida pero el dominio real es otro (posible suplantación)")
    if f["susp_tld"]: r.append("Extensión de dominio muy usada en campañas de abuso")
    if f["ext_risky"]: r.append("Apunta a un archivo ejecutable o comprimido")
    if f["query_has_url"]: r.append("Lleva otra dirección web dentro de los parámetros (redirección)")
    if has_xss_signal(f): r.append("La URL contiene código que parece JavaScript/HTML inyectado")
    if f["double_enc"]: r.append("Doble codificación de caracteres (técnica de ofuscación)")
    return r


class Engine:
    def __init__(self):
        self.bundle = joblib.load(config.MODEL_PATH) if config.MODEL_PATH.exists() else None
        th = (self.bundle or {}).get("thresholds") or {}
        self.t_low = float(th.get("low", config.T_LOW_DEFAULT))
        self.t_high = float(th.get("high", config.T_HIGH_DEFAULT))

    # ---- capa 1 ----
    def _url_proba(self, url: str, f: dict):
        """Devuelve (probabilidad de ser maliciosa, amenaza más probable)."""
        xss_sig = has_xss_signal(f)
        if self.bundle is None:
            return _heuristic(f), ("xss" if xss_sig else "phishing")
        classes = self.bundle["classes"]
        proba = self.bundle["model"].predict_one(url, f)
        p_mal = 1.0 - proba[classes.index("legitimate")]
        mal = {c: p for c, p in zip(classes, proba) if c != "legitimate"}
        top = max(mal, key=mal.get)
        if top == "malicious":                         # modelo binario: inferimos el tipo
            top = "xss" if xss_sig else "phishing"
        # una etiqueta <script> o un manejador onerror=... dentro de la URL es inyección casi siempre
        if f["xss_tag"] or f["xss_event"]:
            p_mal, top = max(p_mal, 0.85), "xss"
        return float(p_mal), top

    @staticmethod
    def _whitelisted(host: str) -> bool:
        parts = host.split(".")
        return any(storage.is_whitelisted(".".join(parts[i:])) for i in range(max(len(parts) - 1, 1)))

    def zone_of(self, p1: float) -> str:
        return "alta" if p1 >= self.t_high else "baja" if p1 < self.t_low else "duda"

    def analyze(self, url: str, html: str = None, fetch: bool = True, deep: bool = False,
                log: bool = True) -> Verdict:
        host = host_of(url)
        t0 = time.perf_counter()
        f = extract_url_features(url)
        xss_sig = has_xss_signal(f)
        if host and not xss_sig and self._whitelisted(host):
            return Verdict(url, "segura", "ninguna", 0.0, ["Dominio en tu lista de excepciones"],
                           zone="excepcion", decided_by="excepcion")
        p1, threat = self._url_proba(url, f)
        zone = self.zone_of(p1)
        # Reputación: en un dominio muy popular la URL sola no basta para bloquear (suele ser un
        # identificador opaco de un documento/correo). Debe confirmarlo la capa 2.
        platform = is_platform_host(host)
        popular = (zone == "alta" and not xss_sig and not f["has_ip"] and not f["_brand_kind"]
                   and (platform or registered_domain(host) in POPULAR_DOMAINS))
        if popular:
            zone = "duda"
        url_reasons = _reasons_url(f)
        if self.bundle:
            head1 = (f"Capa 1 (URL): {p1:.0%} de probabilidad de ser maliciosa "
                     f"(zona {zone}; la duda va de {self.t_low:.0%} a {self.t_high:.0%})")
        else:
            head1 = "Capa 1 (URL): reglas heurísticas (sin modelo entrenado)"
        layer1 = [head1] + ["    " + r for r in url_reasons]
        ms_url = (time.perf_counter() - t0) * 1000

        html_was_allowed = html is None and (zone == "duda" or deep)     # modo en vivo (no con HTML dado)
        score, ms_content, decided, content_ok, c_score = p1, 0.0, "capa 1", False, None
        layer2 = []
        final_url, want_fetch = url, html is None and fetch and (zone == "duda" or deep)
        if want_fetch:
            html, final_url = fetch_page(url)
            final_url = final_url or url
            if not html:
                layer2 = ["Capa 2 (contenido): no se pudo descargar la página (sitio caído, bloqueado o no es HTML); "
                          "decide solo la capa 1"]
        elif html is None:
            layer2 = ["Capa 2 (contenido): no se descargó la página: la URL ya es claramente maliciosa"
                      if zone == "alta" else
                      "Capa 2 (contenido): no se consultó: la URL no muestra señales de riesgo "
                      "(activa el análisis profundo para revisarla igual)"]
        if html:
            t1 = time.perf_counter()
            c_score, cf, c_reasons = analyze_content(html, final_url)
            content_ok = True
            mixed = config.W_URL_GRAY * p1 + config.W_CONTENT_GRAY * c_score
            if zone == "duda":                         # AQUÍ MANDA LA CAPA 2
                score, decided = mixed, "capa 2"
                if c_score >= config.CONTENT_CERTAIN:
                    score = max(score, config.T_DANGEROUS)
                elif c_score >= config.CONTENT_STRONG:
                    score = max(score, config.T_SUSPICIOUS + 0.05)
            else:                                      # extremos: el contenido solo puede subir el puntaje
                score = max(p1, mixed)
                if score > p1:
                    decided = "ambas"
            if cf["reflected_params"]:
                score, threat, decided = max(score, 0.85), "xss", "capa 2"
            if cf["pw_form_external"] or cf["pw_form_ip"] or cf["brand_title_mismatch"]:
                threat = "phishing"
            if c_reasons:
                layer2 = [f"Capa 2 (contenido): riesgo {c_score:.2f}; señales encontradas en la página"] + \
                         ["    " + r for r in c_reasons]
            else:
                layer2 = ["Capa 2 (contenido): la página no muestra señales de ataque"
                          + ("; reduce la sospecha de la capa 1" if zone == "duda" and p1 >= 0.3 else "")]
            ms_content = (time.perf_counter() - t1) * 1000

        # antigüedad del dominio: solo en la zona de duda (o análisis profundo), solo puede subir el puntaje
        if config.USE_DOMAIN_AGE and fetch and html_was_allowed and zone != "alta" and not popular \
                and host and not f["has_ip"]:
            t2 = time.perf_counter()
            bonus, why = age_bonus(domain_age_days(registered_domain(host)))
            ms_content += (time.perf_counter() - t2) * 1000
            if bonus:
                score = min(1.0, score + bonus)
                if layer2:
                    layer2.append("    " + why)
                else:
                    layer2 = ["Capa 2 (contenido): antigüedad del dominio", "    " + why]
                if decided == "capa 1":
                    decided = "ambas"
        if popular and not (content_ok and c_score is not None and c_score >= config.CONTENT_STRONG):
            score = min(score, config.T_DANGEROUS - 0.01)       # sin evidencia de contenido: a lo sumo 'sospechosa'
        if zone == "alta":
            level = "peligrosa"
        else:
            level = ("peligrosa" if score >= config.T_DANGEROUS
                     else "sospechosa" if score >= config.T_SUSPICIOUS else "segura")
        lead = []
        if zone == "duda" and content_ok:
            lead.append(f"Zona de duda de la capa 1: decidió la capa 2 (contenido), con más peso "
                        f"({config.W_CONTENT_GRAY:.0%} contenido · {config.W_URL_GRAY:.0%} URL)")
        elif popular:
            lead.append("Plataforma de alojamiento gratuita (cualquiera publica ahí): la URL sola no basta para "
                        "bloquear; la confirma el contenido" if platform else
                        "Dominio muy popular: la URL por sí sola no basta para bloquear; la confirma el contenido")
        elif zone == "alta":
            lead.append("La capa 1 es suficiente: la URL es claramente maliciosa")
        if level == "segura" and score >= config.T_NEAR:
            lead.append(f"Puntaje cercano al límite de 'sospechosa' ({config.T_SUSPICIOUS:.2f}): "
                        "abre el enlace con cuidado")
        v = Verdict(url, level, threat if level != "segura" else "ninguna", round(float(score), 3),
                    lead + layer1 + layer2, ms_url, ms_content, self.bundle is not None, round(p1, 3),
                    None if c_score is None else round(float(c_score), 3), zone, decided, content_ok)
        if log:
            storage.log_detection(v)
        return v
