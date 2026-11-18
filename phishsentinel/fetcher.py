"""Descarga el HTML estático de la página. NO ejecuta JavaScript."""
import threading

import requests

from .config import FETCH_TIMEOUT, MAX_HTML_BYTES

HEADERS = {"User-Agent": "Mozilla/5.0 PhishSentinel/0.1"}
TOTAL_LIMIT = FETCH_TIMEOUT * 2   # segundos máximos para TODA la descarga (no por pedazo)


def _download(url, state):
    with requests.get(url, headers=HEADERS, timeout=(FETCH_TIMEOUT, FETCH_TIMEOUT), stream=True) as r:
        state["resp"] = r
        if "html" not in r.headers.get("Content-Type", "").lower():
            return
        state["encoding"] = r.encoding or "utf-8"
        size = 0
        for chunk in r.iter_content(4096):
            state["chunks"].append(chunk)
            size += len(chunk)
            if size > MAX_HTML_BYTES or state["stop"]:
                break


def fetch_html(url: str):
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    state = {"chunks": [], "encoding": "utf-8", "resp": None, "stop": False}

    def run():
        try:
            _download(url, state)
        except Exception:      # URLs malformadas, DNS, SSL, timeouts: la capa 2 no debe tumbar la app
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(TOTAL_LIMIT)
    if t.is_alive():           # el sitio envía demasiado lento: se usa lo recibido y la descarga
        state["stop"] = True   # se detiene sola en el siguiente pedazo (no se espera a cerrarla)
    data = b"".join(list(state["chunks"]))
    return data.decode(state["encoding"], errors="replace") if data else None
