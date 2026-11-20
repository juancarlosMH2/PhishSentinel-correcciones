import os
import sys
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)                       # True dentro del .exe
BASE_DIR = Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "model_url.joblib"

# Carpeta de datos del usuario (historial y excepciones). PHISHSENTINEL_DATA permite cambiarla (pruebas).
DATA_DIR = Path(os.getenv("PHISHSENTINEL_DATA") or Path(os.getenv("APPDATA", Path.home())) / "PhishSentinel")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "phishsentinel.db"

# ---- Niveles finales (sobre el puntaje combinado, 0-1) ----
T_SUSPICIOUS = 0.50      # >= sospechosa
T_DANGEROUS = 0.80       # >= peligrosa

# ---- Zona de duda de la capa 1 ----
# T_LOW / T_HIGH reales vienen CALIBRADOS dentro del modelo (models/model_url.joblib); estos son
# solo valores de respaldo para el modo heurístico (sin modelo).
#   p1 <  T_LOW  -> la capa 1 deja pasar (no se descarga la página, salvo "análisis profundo")
#   p1 >= T_HIGH -> la capa 1 bloquea directo (no se contacta el sitio)
#   entre ambos  -> MANDA LA CAPA 2 (se descarga el HTML y pesa más que la URL)
T_LOW_DEFAULT, T_HIGH_DEFAULT = 0.20, 0.90
W_URL_GRAY, W_CONTENT_GRAY = 0.35, 0.65     # en la zona de duda la capa 2 pesa casi el doble
CONTENT_STRONG = 0.50    # evidencia de contenido >= esto: nunca queda 'segura' (mínimo 'sospechosa')
CONTENT_CERTAIN = 0.80   # evidencia >= esto: 'peligrosa'

FETCH_TIMEOUT = 5
MAX_HTML_BYTES = 1_500_000
MAX_REDIRECTS = 5

T_NEAR = 0.40            # aviso "cerca del límite" cuando una URL segura roza 'sospechosa'
W_URL, W_CONTENT = W_URL_GRAY, W_CONTENT_GRAY    # nombres que usa la interfaz (pesos en la zona de duda)

# ---- Antigüedad del dominio (RDAP) ----
USE_DOMAIN_AGE = True
AGE_TIMEOUT = 3                 # segundos
AGE_BONUS_NEW = 0.25            # dominio de menos de 30 días
AGE_BONUS_YOUNG = 0.10          # menos de 90 días
