"""Antigüedad del dominio por RDAP (el sucesor público de WHOIS). Un dominio registrado hace pocos días es
una de las señales más fuertes de phishing y NO se ve en la URL.

  * Solo se consulta en la zona de duda de la capa 1 (o en análisis profundo), nunca en dominios populares.
  * Solo puede SUBIR el puntaje: un dominio viejo no demuestra que sea seguro.
  * Si el registro no responde, no tiene RDAP (muchos ccTLD) o hay error, no pasa nada (devuelve None).
  * Resultados guardados 7 días en la base local para no repetir consultas.
Limitación: no se pudo entrenar ni medir con datos reales (los datasets son antiguos y esos dominios ya
no existen), por eso es una regla con pesos fijos y no una característica del modelo.
"""
import time
from datetime import datetime, timezone

import requests

from . import config, storage

RDAP_URL = "https://rdap.org/domain/{}"
CACHE_SECONDS = 7 * 24 * 3600


def _parse_registration(data: dict):
    for ev in data.get("events", []):
        if str(ev.get("eventAction", "")).lower() == "registration" and ev.get("eventDate"):
            try:
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - (d if d.tzinfo else d.replace(tzinfo=timezone.utc))).days
            except ValueError:
                return None
    return None


def domain_age_days(domain: str):
    """Días desde el registro del dominio, o None si no se pudo saber."""
    if not domain or "." not in domain:
        return None
    cached = storage.get_age(domain)
    if cached is not None and time.time() - cached[1] < CACHE_SECONDS:
        return cached[0]
    try:
        r = requests.get(RDAP_URL.format(domain), timeout=config.AGE_TIMEOUT,
                         headers={"Accept": "application/rdap+json", "User-Agent": "PhishSentinel/2.0"})
        if r.status_code != 200:
            return None
        age = _parse_registration(r.json())
    except Exception:           # sin red, timeout, JSON raro: la señal simplemente no se usa
        return None
    if age is not None:
        storage.set_age(domain, age)
    return age


def age_bonus(days):
    """(puntos que se suman al puntaje, motivo). Nunca resta."""
    if days is None:
        return 0.0, ""
    if days < 30:
        return config.AGE_BONUS_NEW, f"El dominio se registró hace solo {max(days, 0)} días (dominio muy nuevo)"
    if days < 90:
        return config.AGE_BONUS_YOUNG, f"El dominio se registró hace {days} días (dominio reciente)"
    return 0.0, ""
