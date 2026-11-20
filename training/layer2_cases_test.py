"""Casos de prueba de la capa 2 sin internet: cada caso es una URL más una página HTML guardada
en data/eval/html/. Muestra qué decide la capa 1 sola y qué decide el motor completo, para
comprobar que el contenido tiene prioridad sobre la URL.
Uso:  python -m training.layer2_cases_test"""
from pathlib import Path

from phishsentinel.engine import Engine

HTML = Path("data/eval/html")

# (URL, archivo HTML, nivel esperado)
CASES = [
    ("https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F"
     "&emr=1&followup=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&ifkv=AcMMx-cR2f8&osid=1&passive=1209600"
     "&service=mail&flowName=GlifWebSignIn&flowEntry=ServiceLogin", "legit_login_google.html", "segura"),
    ("https://www.eltiempo.com/colombia/otras-ciudades/universidad-de-pamplona-anuncia-nuevas-fechas-de-matricula"
     "-para-el-segundo-semestre-de-2026-123456?utm_source=facebook&utm_medium=social&utm_campaign=eltiempo"
     "&fbclid=IwAR3xYzAbCdEf123456789", "legit_articulo_largo.html", "segura"),
    ("https://github.com/scikit-learn/scikit-learn/blob/main/sklearn/ensemble/_forest.py#L1150-L1210",
     "legit_github.html", "segura"),
    ("http://bancolombia-seguridad-verificacion.xyz/sucursal/personas/login.php", "phish_banco_kit.html", "peligrosa"),
    ("https://docs-share-onedrive.web.app/view?id=8f2c1d3e4a5b", "phish_office_externo.html", "peligrosa"),
    ("https://secure-account-update.com/membership/billing", "phish_netflix_tarjeta.html", "peligrosa"),
    ("https://tienda.example.com/buscar?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
     "xss_reflejado.html", "peligrosa"),
    ("http://185.234.72.19/paypal.com/webapps/signin/verify-account/login.php", "pagina_vacia.html", "sospechosa"),
]


def main():
    eng = Engine()
    print(f"Modelo: {eng.bundle['name'] if eng.bundle else 'SIN modelo (heurística)'}\n")
    ok = 0
    for url, fname, expected in CASES:
        html = (HTML / fname).read_text(encoding="utf-8")
        v1 = eng.analyze(url, fetch=False, log=False)
        v2 = eng.analyze(url, html=html, log=False)
        hit = v2.level == expected
        ok += hit
        print(f"{'OK ' if hit else 'MAL'} {fname:<28} capa1={v1.level:<10} ({v1.score:.2f})  "
              f"final={v2.level:<10} ({v2.score:.2f})  esperado={expected}")
        if not hit:
            for r in v2.reasons:
                print(f"      - {r}")
    print(f"\n{ok}/{len(CASES)} casos con el nivel esperado")


if __name__ == "__main__":
    main()
