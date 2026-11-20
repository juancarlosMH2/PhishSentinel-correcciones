"""Prueba rápida sin interfaz:  python -m phishsentinel.cli <url> [--deep] [--no-fetch]"""
import argparse

from .engine import Engine


def main():
    ap = argparse.ArgumentParser(description="Analiza una URL con PhishSentinel")
    ap.add_argument("url")
    ap.add_argument("--deep", action="store_true", help="consultar siempre la capa 2")
    ap.add_argument("--no-fetch", action="store_true", help="solo capa 1 (no descarga la página)")
    a = ap.parse_args()
    v = Engine().analyze(a.url, fetch=not a.no_fetch, deep=a.deep, log=False)
    print(f"{v.level.upper()} · amenaza: {v.threat} · puntaje {v.score:.2f} · p(capa 1) {v.url_score:.2f} · "
          f"zona {v.zone} · decidió: {v.decided_by}")
    for r in v.reasons:
        print(" •", r)


if __name__ == "__main__":
    main()
