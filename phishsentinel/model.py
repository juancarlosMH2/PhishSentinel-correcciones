"""Clasificador de la capa 1: n-gramas de caracteres (texto de la URL) + características numéricas.

  URL ──┬─► 60 características numéricas ─────────────┐
        └─► n-gramas de caracteres ► SGD ► 4 prob. ───┴─► XGBoost / Random Forest ► P(clase)

Las 4 probabilidades del modelo de texto entran al árbol como características extra (stacking).
En entrenamiento se calculan FUERA DE MUESTRA y agrupadas por dominio (ver training/train.py),
para que el árbol no confíe en un modelo de texto que ya vio esas mismas URLs.
"""
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

try:
    from xgboost import XGBClassifier
except ImportError:                                  # pragma: no cover
    XGBClassifier = None

from .features_url import FEATURE_NAMES, extract_url_features, normalize_url, to_vector

TEXT_MAX_CHARS = 300


def make_hasher():
    return HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5), n_features=2 ** 20,
                             alternate_sign=False, norm="l2", dtype=np.float32)


def text_of(url: str) -> str:
    return normalize_url(url).lower()[:TEXT_MAX_CHARS]


class UrlClassifier:
    def __init__(self, hasher, text_clf, tree, classes):
        self.hasher, self.text_clf, self.tree, self.classes = hasher, text_clf, tree, list(classes)
        self.text_feature_names = [f"ng_p_{c}" for c in self.classes]
        self.feature_names = FEATURE_NAMES + self.text_feature_names

    # ---- serialización: XGBoost va en su formato nativo (portable entre versiones/equipos) ----
    def __getstate__(self):
        st = self.__dict__.copy()
        if XGBClassifier is not None and isinstance(st["tree"], XGBClassifier):
            st["_xgb_raw"] = bytes(st["tree"].get_booster().save_raw("ubj"))
            st["tree"] = None
        return st

    def __setstate__(self, st):
        raw = st.pop("_xgb_raw", None)
        self.__dict__.update(st)
        if raw is not None:
            m = XGBClassifier()
            m.load_model(bytearray(raw))
            self.tree = m

    # ---- texto ----
    def text_proba(self, urls):
        return self.text_clf.predict_proba(self.hasher.transform([text_of(u) for u in urls]))

    # ---- vector completo ----
    def vectors(self, urls, numeric=None, text_p=None):
        numeric = numeric if numeric is not None else np.array(
            [to_vector(extract_url_features(u)) for u in urls], dtype=np.float32)
        text_p = text_p if text_p is not None else self.text_proba(urls)
        return np.hstack([numeric, text_p]).astype(np.float32)

    def predict_proba(self, urls, numeric=None, text_p=None):
        return self.tree.predict_proba(self.vectors(urls, numeric, text_p))

    def predict_one(self, url: str, feats: dict = None):
        """Probabilidades de UNA url. `feats` evita recalcular las características numéricas."""
        numeric = np.array([to_vector(feats or extract_url_features(url))], dtype=np.float32)
        return self.predict_proba([url], numeric=numeric)[0]
