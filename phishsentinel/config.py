import os
import sys
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)                       # True dentro del .exe
BASE_DIR = Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "model_url.joblib"

DATA_DIR = Path(os.getenv("APPDATA", Path.home())) / "PhishSentinel"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "phishsentinel.db"

T_SUSPICIOUS = 0.50      # >= sospechosa
T_DANGEROUS = 0.80       # >= peligrosa
# Zona dudosa: de T_NEAR a T_SUSPICIOUS la URL sigue siendo "segura" (sin alerta emergente), pero
# se avisa que está cerca del límite. En esa franja el modelo casi no distingue legítimas de phishing
# (~3 % de las legítimas y ~2 % del phishing caen ahí); bajar el corte a 0.40 sumaba ~2 puntos de
# phishing detectado a cambio de ~3 puntos más de falsos positivos.
T_NEAR = 0.40
# Prioridad de las capas (corrección): la capa 2 (contenido) pesa más que la capa 1 (URL).
# Con HTML disponible:  puntaje = 0.3 * capa1 + 0.7 * capa2
W_URL, W_CONTENT = 0.3, 0.7
# Sin evidencia en el contenido, la capa 1 sola puede ADVERTIR (sospechosa) pero no CONDENAR:
# si la URL es muy dudosa (>= este valor) y la página no muestra nada, queda en "sospechosa".
URL_ALONE_FLOOR = 0.95
# Casi siempre se descarga la página para que decida la capa 2; solo se omite si la capa 1
# está prácticamente segura (así no se contacta un sitio claramente malicioso).
SKIP_FETCH_ABOVE = 0.99
FETCH_TIMEOUT = 5
MAX_HTML_BYTES = 1_500_000
