"""Motor de decisión: combina capa 1 (URL + ML) y capa 2 (contenido)."""
import time
from dataclasses import dataclass, field

import joblib

from . import config, storage
from .features_content import analyze_content
from .features_url import FEATURE_NAMES, extract_url_features, host_of, to_vector
from .fetcher import fetch_html


@dataclass
class Verdict:
    url: str
    level: str                 # segura | sospechosa | peligrosa
    threat: str                # ninguna | phishing | xss
    score: float
    reasons: list = field(default_factory=list)
    ms_url: float = 0.0
    ms_content: float = 0.0
    used_model: bool = False
    url_score: float = 0.0             # lo que dijo la capa 1 sola (0-1)
    content_score: float = None        # lo que dijo la capa 2 sola; None si no se revisó la página


def _heuristic(f: dict) -> float:
    """Respaldo cuando todavía no hay modelo entrenado."""
    s = 0.35 * f["has_ip"] + 0.25 * f["has_at"] + 0.15 * f["punycode"] + 0.10 * min(f["susp_words"], 3) / 3
    s += 0.15 * (f["n_subdomains"] >= 3) + 0.10 * (not f["https"]) + 0.10 * f["shortener"]
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
    if not f["https"]: r.append("No usa HTTPS")
    if f["xss_tag"] or f["xss_event"] or f["xss_js_scheme"] or f["xss_func"]:
        r.append("La URL contiene código que parece JavaScript/HTML inyectado")
    if f["double_enc"]: r.append("Doble codificación de caracteres (técnica de ofuscación)")
    kind = f.get("_brand_kind", "")
    if kind == "contiene": r.append("El dominio usa el nombre de una marca, pero no es el dominio oficial de esa marca")
    if kind == "disfraza": r.append("El dominio imita una marca con letras o números parecidos (p. ej. 0 en vez de o)")
    if kind == "casi_igual": r.append("El dominio está escrito casi igual que el de una marca conocida (typosquatting)")
    return r


def _level(score: float) -> str:
    return ("peligrosa" if score >= config.T_DANGEROUS
            else "sospechosa" if score >= config.T_SUSPICIOUS else "segura")


_RANK = {"segura": 0, "sospechosa": 1, "peligrosa": 2}


def load_bundle(path):
    """Carga el modelo. Los XGBoost se guardan en su formato nativo (UBJSON) dentro del bundle,
    porque el pickle de XGBoost puede fallar al pasar de una máquina o versión de Python a otra."""
    bundle = joblib.load(path)
    if bundle.get("xgb_model") is not None:
        from xgboost import XGBClassifier
        clf = XGBClassifier()
        clf.load_model(bytearray(bundle["xgb_model"]))
        bundle["model"] = clf
    return bundle


class Engine:
    def __init__(self):
        self.bundle = load_bundle(config.MODEL_PATH) if config.MODEL_PATH.exists() else None
        if self.bundle and list(self.bundle.get("features", [])) != FEATURE_NAMES:
            # Modelo entrenado con otra versión de las características: usarlo daría basura.
            print("[aviso] el modelo no coincide con las características actuales; "
                  "reentrena con: python -m training.train. Se usan las reglas heurísticas.")
            self.bundle = None

    def _url_proba(self, f: dict):
        """Devuelve (probabilidad de ser maliciosa, amenaza más probable)."""
        xss_sig = any(f[k] for k in ("xss_tag", "xss_event", "xss_js_scheme", "xss_func"))
        if self.bundle is None:
            return _heuristic(f), ("xss" if xss_sig else "phishing")
        classes = self.bundle["classes"]
        proba = self.bundle["model"].predict_proba([to_vector(f)])[0]
        p_mal = 1.0 - proba[classes.index("legitimate")]
        mal = {c: p for c, p in zip(classes, proba) if c != "legitimate"}
        top = max(mal, key=mal.get)
        if top == "malicious":                         # modelo binario: inferimos el tipo
            top = "xss" if xss_sig else "phishing"
        return float(p_mal), top

    def analyze(self, url: str, html: str = None, fetch: bool = True) -> Verdict:
        host = host_of(url)
        t0 = time.perf_counter()
        f = extract_url_features(url)
        xss_sig = any(f[k] for k in ("xss_tag", "xss_event", "xss_js_scheme", "xss_func"))
        if host and storage.is_whitelisted(host) and not xss_sig:
            return Verdict(url, "segura", "ninguna", 0.0, ["Dominio en tu lista de excepciones"])
        p_url, threat = self._url_proba(f)
        url_reasons = _reasons_url(f)
        ms_url = (time.perf_counter() - t0) * 1000

        score, ms_content, c_reasons, extra, c_score = p_url, 0.0, None, [], None
        skipped = html is None and fetch and p_url >= config.SKIP_FETCH_ABOVE
        if html is None and fetch and not skipped:
            html = fetch_html(url)
        if html:
            t1 = time.perf_counter()
            c_score, cf, c_reasons = analyze_content(html, url)
            # Prioridad a la capa 2: el contenido manda. Una página limpia SÍ puede bajar el
            # puntaje de una URL que solo "se ve rara" (p. ej. URLs largas legítimas).
            score = config.W_URL * p_url + config.W_CONTENT * c_score
            if cf["reflected_params"]:
                score, threat = max(score, 0.85), "xss"
            elif cf["pw_form_external"] or cf["brand_impersonation"]:
                score, threat = max(score, 0.85), "phishing"
            elif p_url >= config.URL_ALONE_FLOOR and score < config.T_SUSPICIOUS and not f["_official_brand"]:
                # (no aplica a dominios oficiales de marcas: ahí no hay suplantación que esconder)
                score = config.T_SUSPICIOUS               # la capa 1 sola solo advierte
                extra.append(f"La URL es muy sospechosa ({p_url:.0%}) y el contenido no confirmó el ataque: "
                             "queda como sospechosa, no como peligrosa")
            ms_content = (time.perf_counter() - t1) * 1000

        level = _level(score)
        # ---- motivos: primero la conclusión, luego qué dijo cada capa ----
        reasons = []
        if level == "segura" and score >= config.T_NEAR:
            reasons.append(f"Puntaje cercano al límite ({score:.2f}): revisa el enlace antes de ingresar datos")
        url_level = _level(p_url)
        if c_reasons is not None and _RANK[url_level] > _RANK[level] and not extra:
            reasons.append(f"La URL sola parece {url_level} ({p_url:.0%}), pero el contenido de la página no lo "
                           f"confirma. Decide el contenido, que pesa el {config.W_CONTENT:.0%}")
        elif c_reasons is not None and _RANK[level] > _RANK[url_level]:
            reasons.append("El contenido de la página mostró señales de ataque que la URL sola no tenía")
        reasons += extra
        what = (f"el modelo estima {p_url:.0%} de probabilidad de que sea maliciosa" if self.bundle
                else f"reglas heurísticas, puntaje {p_url:.2f}")
        reasons.append(f"Capa 1 (URL): {what}")
        reasons += [f"    {r}" for r in url_reasons]
        if c_reasons is None:
            reasons.append("Capa 2 (contenido): no se descargó la página porque la URL ya es claramente maliciosa"
                           if skipped else
                           "Capa 2 (contenido): no se pudo revisar la página, así que decide solo la URL")
        elif c_reasons:
            reasons.append(f"Capa 2 (contenido): {len(c_reasons)} señal(es) de riesgo en la página")
            reasons += [f"    {r}" for r in c_reasons]
        else:
            reasons.append("Capa 2 (contenido): la página no mostró señales de ataque")
        v = Verdict(url, level, threat if level != "segura" else "ninguna", round(score, 3),
                    reasons, ms_url, ms_content, self.bundle is not None, round(p_url, 3),
                    None if c_score is None else round(c_score, 3))
        storage.log_detection(v)
        return v
