"""PhishSentinel - app de escritorio (CustomTkinter).
Analiza una URL pegada o vigila el portapapeles. El diseño sigue el archivo de Figma
"PhishSentinel – Diseño de interfaz" (pantallas por estado, historial y alerta)."""
import logging
import queue
import re
import threading
import time
import tkinter as tk
import tkinter.font as tkfont

import customtkinter as ctk
from PIL import Image

from phishsentinel import config, storage
from phishsentinel.engine import Engine
from phishsentinel.features_url import host_of

URL_RE = re.compile(r"^(https?://|www\.)\S+$", re.I)
logging.basicConfig(filename=str(config.DATA_DIR / "phishsentinel.log"), level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s", encoding="utf-8")
log = logging.getLogger("phishsentinel")
ANALYSIS_LIMIT = config.FETCH_TIMEOUT * 4 + 10   # segundos máximos esperando un análisis
ICON_DIR = config.BASE_DIR / "assets" / "icons"

# ---- tokens (mismos nombres y valores que las variables de Figma) ----
BG = "#EEF1F5"            # color/fondo
CARD = "#FFFFFF"          # color/superficie
BORDER = "#D9DEE6"        # color/borde
TRACK = "#E5E9F0"         # color/pista
TEXT = "#1F2937"          # color/texto
MUTED = "#6B7280"         # color/texto-suave
HEADER = "#0F1B2D"        # color/encabezado
HEADER_CHIP = "#1B2A40"   # color/encabezado-chip
HEADER_TEXT = "#9FB0C8"   # color/encabezado-texto
ACCENT = "#2563EB"        # color/acento
ACCENT_DARK = "#1D4ED8"   # color/acento-oscuro
ACCENT_SOFT = "#E8EFFD"   # color/acento-suave
AVISO_TEXT = "#92400E"    # nivel/aviso-texto
LEVELS = {   # nivel: (fuerte, suave, barra, ícono, título)
    "segura": ("#15803D", "#E8F6EE", "#22A05A", "check", "SEGURA"),
    "sospechosa": ("#B45309", "#FDF3E3", "#E59A1B", "alerta", "SOSPECHOSA"),
    "peligrosa": ("#B91C1C", "#FDEAEA", "#D64545", "x", "PELIGROSA"),
}
THREATS = {"ninguna": "ninguna", "phishing": "phishing", "xss": "XSS (código inyectado)"}


def zone_color(score):
    if score < config.T_SUSPICIOUS:
        return LEVELS["segura"][2]
    if score < config.T_DANGEROUS:
        return LEVELS["sospechosa"][2]
    return LEVELS["peligrosa"][2]


def fmt(x):
    return f"{x:.2f}".replace(".", ",")


def pretty_reason(r):
    """'Capa 1 (URL): …' -> 'Capa 1 · URL — …' (como en el diseño)."""
    return (r.replace("Capa 1 (URL): ", "Capa 1 · URL — ")
             .replace("Capa 2 (contenido): ", "Capa 2 · Contenido — "))


class Icons:
    """Carga los íconos (máscaras PNG) y los colorea según se necesiten."""
    def __init__(self):
        self.cache = {}

    def get(self, name, color, size=20):
        key = (name, color, size)
        if key not in self.cache:
            try:
                mask = Image.open(ICON_DIR / f"{name}.png").getchannel("A")
                img = Image.new("RGBA", mask.size, color)
                img.putalpha(mask)
                self.cache[key] = ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
            except (OSError, ValueError):
                self.cache[key] = None          # sin el ícono la app sigue funcionando
        return self.cache[key]


class Gauge(tk.Canvas):
    """Barra de puntaje con las tres zonas, las marcas 0,50 / 0,80 y un marcador redondo."""
    def __init__(self, parent, font):
        super().__init__(parent, height=42, highlightthickness=0, bd=0, bg=CARD)
        self.value, self.font = None, font
        self.bind("<Configure>", lambda _e: self.draw())

    def set(self, value, bg):
        self.value = value
        self.configure(bg=bg)
        self.draw()

    def draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 40)
        pad, y = 8, 14
        span = w - 2 * pad
        zones = [(0, config.T_SUSPICIOUS, LEVELS["segura"][2]),
                 (config.T_SUSPICIOUS, config.T_DANGEROUS, LEVELS["sospechosa"][2]),
                 (config.T_DANGEROUS, 1, LEVELS["peligrosa"][2])]
        for i, (a, b, color) in enumerate(zones):
            x0, x1 = pad + a * span + (2 if i else 0), pad + b * span
            cap = "round" if i in (0, 2) else "butt"
            self.create_line(x0 + (4 if i == 0 else 0), y, x1 - (4 if i == 2 else 0), y, fill=color, width=8, capstyle=cap)
        for t in (config.T_SUSPICIOUS, config.T_DANGEROUS):
            self.create_text(pad + t * span, y + 20, text=fmt(t), fill=MUTED, font=self.font)
        if self.value is not None:
            x = pad + min(max(self.value, 0), 1) * span
            self.create_oval(x - 8, y - 8, x + 8, y + 8, fill=CARD, outline=TEXT, width=3)


class App(ctk.CTk):
    def __init__(self):
        ctk.set_appearance_mode("light")
        super().__init__(fg_color=BG)
        self.title("PhishSentinel")
        self.geometry("900x880")
        self.minsize(780, 760)
        fams = set(tkfont.families(self))
        fam = next((f for f in ("Segoe UI", "Inter", "Helvetica Neue", "DejaVu Sans") if f in fams), "TkDefaultFont")
        mono = next((f for f in ("Consolas", "JetBrains Mono", "DejaVu Sans Mono", "Courier New") if f in fams), "TkFixedFont")
        F = lambda size, weight="normal", family=fam: ctk.CTkFont(family=family, size=size, weight=weight)
        self.f = {"title": F(18, "bold"), "level": F(26, "bold"), "score": F(30, "bold"), "h": F(13, "bold"),
                  "value": F(15, "bold"), "body": F(13), "bodyb": F(13, "bold"), "small": F(12), "tag": F(11, "bold"),
                  "entry": F(15), "url": F(12, family=mono)}
        self.gauge_font = (fam, 9)
        self.ic = Icons()
        self.engine = Engine()
        self.q = queue.Queue()
        self.last_clip, self.current, self.busy, self.alert = "", None, False, None
        self.url_var, self.watch_var = tk.StringVar(), tk.BooleanVar(value=False)
        self.wrap_labels = []

        self._header()
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=20)
        self._input(body)
        self._result(body)
        self._layers(body)
        self._footer(body)           # antes que los motivos: siempre queda visible abajo
        self._reasons(body)
        self.show_empty()
        self.started_at = 0.0
        self._set_window_icon()
        self.after(200, self.poll)
        self.after(1000, self.watch_clipboard)

    # ================= construcción =================
    def card(self, parent, **kw):
        return ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER, **kw)

    def chip(self, parent, text, fg, color, font=None):
        return ctk.CTkLabel(parent, text=f"  {text.upper()}  ", fg_color=fg, text_color=color, corner_radius=10,
                            height=22, font=font or self.f["tag"])

    def _set_window_icon(self):
        try:
            from PIL import ImageTk
            mask = Image.open(ICON_DIR / "escudo-check.png").getchannel("A")
            img = Image.new("RGBA", mask.size, ACCENT)
            img.putalpha(mask)
            self._icon_photo = ImageTk.PhotoImage(img)
            self.after(300, lambda: self.iconphoto(False, self._icon_photo))
        except (OSError, ValueError, tk.TclError):
            pass

    def _header(self):
        bar = ctk.CTkFrame(self, fg_color=HEADER, corner_radius=0, height=68)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        logo = ctk.CTkFrame(bar, width=38, height=38, corner_radius=9, fg_color=ACCENT)
        logo.pack(side="left", padx=(22, 12))
        logo.pack_propagate(False)
        ctk.CTkLabel(logo, text="", image=self.ic.get("escudo-check", "#FFFFFF", 22)).place(relx=0.5, rely=0.5, anchor="center")
        titles = ctk.CTkFrame(bar, fg_color="transparent")
        titles.pack(side="left")
        ctk.CTkLabel(titles, text="PhishSentinel", font=self.f["title"], text_color="#FFFFFF", height=24).pack(anchor="w")
        ctk.CTkLabel(titles, text="Detector de phishing y XSS en dos capas · URL + contenido", font=self.f["small"],
                     text_color=HEADER_TEXT, height=16).pack(anchor="w")
        ok = self.engine.bundle is not None
        status = ctk.CTkFrame(bar, fg_color=HEADER_CHIP, corner_radius=14, height=30)
        status.pack(side="right", padx=22)
        dot = ctk.CTkFrame(status, width=8, height=8, corner_radius=4, fg_color="#86EFAC" if ok else "#FCD34D")
        dot.pack(side="left", padx=(12, 6), pady=11)
        name = self.engine.bundle.get("name", "ML") if ok else ""
        ctk.CTkLabel(status, text=f"Modelo {name} cargado" if ok else "Sin modelo: reglas heurísticas",
                     font=self.f["small"], text_color="#FFFFFF", height=20).pack(side="left", padx=(0, 12))

    def _input(self, parent):
        card = self.card(parent)
        card.pack(fill="x")
        ctk.CTkLabel(card, text="Enlace a analizar", font=self.f["h"], text_color=TEXT, height=18).pack(anchor="w", padx=18, pady=(16, 10))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=18)
        self.field = ctk.CTkFrame(row, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER, height=46)
        self.field.pack(side="left", fill="x", expand=True)
        self.field.pack_propagate(False)
        ctk.CTkLabel(self.field, text="", image=self.ic.get("enlace", MUTED, 18), width=18).pack(side="left", padx=(12, 6))
        self.entry = ctk.CTkEntry(self.field, textvariable=self.url_var, font=self.f["entry"], border_width=0,
                                  fg_color=CARD, text_color=TEXT, placeholder_text="Pega aquí el enlace (https://…)",
                                  placeholder_text_color=MUTED, height=40)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry.bind("<Return>", lambda _e: self.on_analyze())
        self.entry.bind("<FocusIn>", lambda _e: self.field.configure(border_color=ACCENT, border_width=2))
        self.entry.bind("<FocusOut>", lambda _e: self.field.configure(border_color=BORDER, border_width=1))
        self.btn = ctk.CTkButton(row, text="Analizar", image=self.ic.get("buscar", "#FFFFFF", 16), compound="left",
                                 font=self.f["bodyb"], fg_color=ACCENT, hover_color=ACCENT_DARK, text_color="#FFFFFF",
                                 text_color_disabled="#FFFFFF", corner_radius=8, height=46, width=132, command=self.on_analyze)
        self.btn.pack(side="left", padx=(10, 0))
        ctk.CTkSwitch(card, text="Vigilar portapapeles: analiza cada enlace que copies y avisa si es riesgoso",
                      variable=self.watch_var, onvalue=True, offvalue=False, font=self.f["small"], text_color=MUTED,
                      progress_color=ACCENT, fg_color="#C3CBD6", button_color="#FFFFFF", button_hover_color="#F3F5F8",
                      switch_width=36, switch_height=20).pack(anchor="w", padx=18, pady=(12, 16))

    def _result(self, parent):
        self.res = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER)
        self.res.pack(fill="x", pady=(16, 0))
        self.strip = ctk.CTkFrame(self.res, width=6, height=10, corner_radius=3, fg_color=BORDER)
        self.strip.pack(side="left", fill="y", padx=(10, 0), pady=14)
        inner = ctk.CTkFrame(self.res, fg_color="transparent")
        inner.pack(side="left", fill="both", expand=True, padx=(16, 22), pady=(16, 10))
        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")
        self.circle = ctk.CTkFrame(top, width=48, height=48, corner_radius=24, fg_color=TRACK)
        self.circle.pack(side="left", padx=(0, 14))
        self.circle.pack_propagate(False)
        self.circle_icon = ctk.CTkLabel(self.circle, text="", width=26)
        self.circle_icon.place(relx=0.5, rely=0.5, anchor="center")
        mid = ctk.CTkFrame(top, fg_color="transparent")
        mid.pack(side="left", fill="x", expand=True)
        self.level_lbl = ctk.CTkLabel(mid, text="", font=self.f["level"], height=32, anchor="w")
        self.level_lbl.pack(anchor="w")
        self.threat_chip = self.chip(mid, "", TRACK, MUTED)
        self.threat_chip.pack(anchor="w", pady=(4, 0))
        right = ctk.CTkFrame(top, fg_color="transparent")
        right.pack(side="right", anchor="n")
        self.score_lbl = ctk.CTkLabel(right, text="", font=self.f["score"], height=36, anchor="e")
        self.score_lbl.pack(anchor="e")
        self.score_cap = ctk.CTkLabel(right, text="", font=self.f["small"], text_color=MUTED, height=16, anchor="e")
        self.score_cap.pack(anchor="e")
        self.url_lbl = ctk.CTkLabel(inner, text="", font=self.f["url"], text_color=MUTED, anchor="w", height=18)
        self.url_lbl.pack(fill="x", pady=(10, 2))
        self.gauge = Gauge(inner, self.gauge_font)
        self.gauge.pack(fill="x")
        self.res_inner = [inner, top, mid, right]

    def _layer_card(self, parent, title, icon, weight):
        c = self.card(parent)
        head = ctk.CTkFrame(c, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(16, 8))
        bub = ctk.CTkFrame(head, width=28, height=28, corner_radius=8, fg_color=ACCENT_SOFT)
        bub.pack(side="left")
        bub.pack_propagate(False)
        ctk.CTkLabel(bub, text="", image=self.ic.get(icon, ACCENT, 16)).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(head, text=title, font=self.f["h"], text_color=TEXT, height=20).pack(side="left", padx=8)
        self.chip(head, f"peso {weight:.0%}".replace("%", " %"), ACCENT_SOFT, ACCENT_DARK).pack(side="right")
        val = ctk.CTkLabel(c, text="—", font=self.f["value"], text_color=MUTED, anchor="w", height=20)
        val.pack(fill="x", padx=16)
        bar = ctk.CTkProgressBar(c, height=8, corner_radius=4, fg_color=TRACK, progress_color=TRACK, border_width=0)
        bar.pack(fill="x", padx=16, pady=(8, 8))
        bar.set(0)
        note = ctk.CTkLabel(c, text="", font=self.f["small"], text_color=MUTED, anchor="w", height=16, compound="left")
        note.pack(fill="x", padx=16, pady=(0, 16))
        return c, val, bar, note

    def _layers(self, parent):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=(16, 0))
        row.grid_columnconfigure((0, 1), weight=1, uniform="capas")
        c1, self.l1_val, self.l1_bar, self.l1_note = self._layer_card(row, "Capa 1 · URL", "enlace", config.W_URL)
        c2, self.l2_val, self.l2_bar, self.l2_note = self._layer_card(row, "Capa 2 · Contenido", "documento", config.W_CONTENT)
        c1.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        c2.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

    def _reasons(self, parent):
        card = self.card(parent)
        card.pack(fill="both", expand=True, pady=(16, 0))
        ctk.CTkLabel(card, text="Por qué este resultado", font=self.f["h"], text_color=TEXT, height=18).pack(anchor="w", padx=18, pady=(14, 4))
        self.reasons_box = ctk.CTkScrollableFrame(card, fg_color=CARD, corner_radius=0, height=120,
                                                  scrollbar_button_color=BORDER, scrollbar_button_hover_color=MUTED)
        self.reasons_box.pack(fill="both", expand=True, padx=(10, 6), pady=(0, 10))
        self.reasons_box.bind("<Configure>", self._rewrap)

    def _footer(self, parent):
        bot = ctk.CTkFrame(parent, fg_color="transparent")
        bot.pack(side="bottom", fill="x", pady=(16, 0))
        for text, icon, cmd in (("Agregar a excepciones", "escudo-mas", self.on_whitelist),
                                ("Ver historial", "historial", self.on_history)):
            ctk.CTkButton(bot, text=text, image=self.ic.get(icon, TEXT, 16), compound="left", font=self.f["body"],
                          fg_color=CARD, hover_color="#F3F5F8", text_color=TEXT, border_width=1, border_color=BORDER,
                          corner_radius=8, height=38, width=0, command=cmd).pack(side="left", padx=(0, 8))
        self.status = ctk.CTkLabel(bot, text="", font=self.f["small"], text_color=MUTED)
        self.status.pack(side="right")

    # ================= motivos =================
    def _rewrap(self, _e=None):
        w = max(self.reasons_box.winfo_width() - 70, 200)
        for lbl in self.wrap_labels:
            lbl.configure(wraplength=w)

    def _reason(self, kind, text):
        box = self.reasons_box
        if kind == "aviso":
            row = ctk.CTkFrame(box, fg_color=LEVELS["sospechosa"][1], corner_radius=8, border_width=1,
                               border_color=LEVELS["sospechosa"][2])
            row.pack(fill="x", pady=(2, 6), padx=(0, 6))
            ctk.CTkLabel(row, text="", image=self.ic.get("alerta", AVISO_TEXT, 16), width=16).pack(side="left", padx=(12, 8), pady=8)
            lbl = ctk.CTkLabel(row, text=text, font=self.f["bodyb"], text_color=AVISO_TEXT, anchor="w", justify="left")
            lbl.pack(side="left", fill="x", expand=True, pady=8, padx=(0, 10))
        elif kind == "concl":
            row = ctk.CTkFrame(box, fg_color="transparent")
            row.pack(fill="x", pady=(2, 4))
            ctk.CTkLabel(row, text="", image=self.ic.get("info", ACCENT, 16), width=16).pack(side="left", anchor="n", padx=(0, 8), pady=2)
            lbl = ctk.CTkLabel(row, text=text, font=self.f["bodyb"], text_color=TEXT, anchor="w", justify="left")
            lbl.pack(side="left", fill="x", expand=True)
        elif kind == "capa":
            lbl = ctk.CTkLabel(box, text=text, font=self.f["bodyb"], text_color=ACCENT_DARK, anchor="w", justify="left")
            lbl.pack(fill="x", pady=(8, 2))
        elif kind == "item":
            row = ctk.CTkFrame(box, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkFrame(row, width=6, height=6, corner_radius=3, fg_color=MUTED).pack(side="left", anchor="n", padx=(6, 10), pady=8)
            lbl = ctk.CTkLabel(row, text=text, font=self.f["body"], text_color=TEXT, anchor="w", justify="left")
            lbl.pack(side="left", fill="x", expand=True)
        else:
            lbl = ctk.CTkLabel(box, text=text, font=self.f["body"], text_color=MUTED, anchor="w", justify="left")
            lbl.pack(fill="x", pady=2)
        self.wrap_labels.append(lbl)

    def _set_reasons(self, items):
        for w in self.reasons_box.winfo_children():
            w.destroy()
        self.wrap_labels = []
        for kind, text in items:
            self._reason(kind, text)
        self.after(10, self._rewrap)

    # ================= estados =================
    def _paint(self, strong, soft, border):
        self.res.configure(fg_color=soft, border_color=border)
        for w in self.res_inner:
            w.configure(fg_color="transparent")
        self.strip.configure(fg_color=strong)

    def _layer(self, val, bar, note, text, score, note_text, note_icon="reloj"):
        val.configure(text=text, text_color=TEXT if score is not None else MUTED)
        bar.configure(progress_color=zone_color(score) if score is not None else TRACK)
        bar.set(score if score is not None else 0)
        note.configure(text=f"  {note_text}" if note_text else "", image=self.ic.get(note_icon, MUTED, 14) if note_text else None)

    def show_neutral(self, title, chip_text, icon, url, reasons, status):
        self._paint(BORDER, CARD, BORDER)
        self.circle.configure(fg_color=TRACK)
        self.circle_icon.configure(image=self.ic.get(icon, MUTED, 26))
        self.level_lbl.configure(text=title, text_color=MUTED)
        self.threat_chip.configure(text=f"  {chip_text.upper()}  ", fg_color=TRACK, text_color=MUTED)
        self.score_lbl.configure(text="")
        self.score_cap.configure(text="")
        self.url_lbl.configure(text=url)
        self.gauge.set(None, CARD)
        self._set_reasons(reasons)
        self.status.configure(text=status)

    def show_empty(self):
        self.show_neutral("Sin analizar", "Pega un enlace y pulsa Analizar", "pregunta", "", [("muted",
                          "Aquí aparecerán los motivos del resultado: qué encontró la URL y qué encontró el contenido de la página.")], "Listo")
        self._layer(self.l1_val, self.l1_bar, self.l1_note, "—", None, "Esperando un enlace")
        self._layer(self.l2_val, self.l2_bar, self.l2_note, "—", None, "Esperando un enlace")

    def show_busy(self, url):
        self.show_neutral("Analizando…", "Revisando URL y contenido", "cargando", self._short(url),
                          [("muted", "Revisando la URL y descargando la página…")], "Analizando…")
        self._layer(self.l1_val, self.l1_bar, self.l1_note, "Calculando…", None, "Modelo XGBoost" if self.engine.bundle else "Reglas heurísticas")
        self._layer(self.l2_val, self.l2_bar, self.l2_note, "Descargando la página…", None,
                    f"Máximo {config.FETCH_TIMEOUT} s · solo HTML estático", "info")

    def show_error(self, exc):
        msg = str(exc) or exc.__class__.__name__
        self.show_neutral("No se pudo analizar", "Error", "info", msg[:110],
                          [("muted", msg), ("muted", f"Detalle técnico guardado en {config.DATA_DIR / 'phishsentinel.log'}")], "")

    @staticmethod
    def _short(url, n=100):
        return url if len(url) <= n else url[:n - 1] + "…"

    def show(self, v):
        self.current = v
        strong, soft, bar, icon, title = LEVELS[v.level]
        self._paint(strong, soft, strong)
        self.circle.configure(fg_color=strong)
        self.circle_icon.configure(image=self.ic.get(icon, "#FFFFFF", 26))
        self.level_lbl.configure(text=title, text_color=strong)
        self.threat_chip.configure(text=f"  AMENAZA: {THREATS.get(v.threat, v.threat).upper()}  ", fg_color=strong, text_color="#FFFFFF")
        self.score_lbl.configure(text=fmt(v.score), text_color=strong)
        self.score_cap.configure(text="puntaje final (0 a 1)")
        self.url_lbl.configure(text=self._short(v.url))
        self.gauge.set(v.score, soft)

        if v.ms_url == 0 and v.ms_content == 0:      # dominio en excepciones
            self._layer(self.l1_val, self.l1_bar, self.l1_note, "Dominio en tu lista de excepciones", None, "")
        else:
            self._layer(self.l1_val, self.l1_bar, self.l1_note, f"{v.url_score:.0%} de probabilidad de ser maliciosa".replace("%", " %"),
                        v.url_score, f"{v.ms_url:.0f} ms")
        if v.content_score is None:
            skipped = any("ya es claramente maliciosa" in r for r in v.reasons)
            self._layer(self.l2_val, self.l2_bar, self.l2_note, "Página no revisada", None,
                        "No se descargó: la URL ya es claramente maliciosa" if skipped else "No se pudo descargar: decide solo la capa 1", "info")
        else:
            self._layer(self.l2_val, self.l2_bar, self.l2_note, f"Riesgo del contenido: {fmt(v.content_score)}", v.content_score,
                        f"{v.ms_content:.0f} ms · HTML estático, sin ejecutar JavaScript")

        items = []
        for r in v.reasons or ["Sin señales de riesgo"]:
            if r.startswith("Puntaje cercano"):
                items.append(("aviso", r))
            elif r.startswith("Capa "):
                items.append(("capa", pretty_reason(r)))
            elif r.startswith("    "):
                items.append(("item", r.strip()))
            elif r == "Dominio en tu lista de excepciones":
                items.append(("concl", r))
            else:
                items.append(("concl", r))
        self._set_reasons(items)
        self.status.configure(text=f"Analizado a las {time.strftime('%H:%M:%S')}")

    # ================= análisis (en hilo aparte para no congelar la ventana) =================
    def start(self, url, source):
        if self.busy:
            return
        self.busy = True
        self.started_at = time.monotonic()
        self.btn.configure(text="Analizando…", image=self.ic.get("cargando", "#FFFFFF", 16), state="disabled", fg_color="#8DB0F7")
        self.show_busy(url)
        threading.Thread(target=self._work, args=(url, source), daemon=True).start()

    def _work(self, url, source):
        try:
            self.q.put((self.engine.analyze(url), source))
        except Exception as exc:                      # no tumbar la app por un error de red/parseo
            log.exception("Error analizando %s", url)
            self.q.put((exc, source))

    def report_callback_exception(self, exc, val, tb):
        """Errores dentro de la ventana: se registran en phishsentinel.log en vez de perderse."""
        log.error("Error en la interfaz", exc_info=(exc, val, tb))

    def _ready(self):
        self.busy = False
        self.btn.configure(text="Analizar", image=self.ic.get("buscar", "#FFFFFF", 16), state="normal", fg_color=ACCENT)

    def poll(self):
        try:
            while True:
                res, source = self.q.get_nowait()
                self._ready()
                try:
                    if isinstance(res, Exception):
                        self.show_error(res)
                    else:
                        self.show(res)
                        if source == "clipboard" and res.level != "segura":
                            self.show_alert(res)
                except Exception as exc:              # un fallo al dibujar no puede congelar la app
                    log.exception("Error mostrando el resultado")
                    self.show_error(exc)
        except queue.Empty:
            pass
        except Exception:
            log.exception("Error en poll")
        finally:
            if self.busy and time.monotonic() - self.started_at > ANALYSIS_LIMIT:
                log.warning("El análisis superó %s s", ANALYSIS_LIMIT)
                self._ready()
                self.show_error(TimeoutError("El análisis tardó demasiado. Revisa tu conexión e inténtalo de nuevo."))
            self.after(200, self.poll)

    # ================= alerta del portapapeles =================
    def show_alert(self, v):
        if self.alert is not None and self.alert.winfo_exists():
            self.alert.destroy()
        strong, soft, _bar, _icon, _title = LEVELS[v.level]
        win = self.alert = ctk.CTkToplevel(self, fg_color=CARD)
        win.title("PhishSentinel")
        win.geometry("460x300")
        win.resizable(False, False)
        win.transient(self)
        ctk.CTkFrame(win, height=4, corner_radius=0, fg_color=strong).pack(fill="x")
        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=20)
        top = ctk.CTkFrame(body, fg_color="transparent")
        top.pack(fill="x")
        circ = ctk.CTkFrame(top, width=40, height=40, corner_radius=20, fg_color=soft)
        circ.pack(side="left", padx=(0, 12))
        circ.pack_propagate(False)
        ctk.CTkLabel(circ, text="", image=self.ic.get("alerta", strong, 22)).place(relx=0.5, rely=0.5, anchor="center")
        titles = ctk.CTkFrame(top, fg_color="transparent")
        titles.pack(side="left")
        adj = {"peligrosa": "peligroso", "sospechosa": "sospechoso"}.get(v.level, v.level)
        ctk.CTkLabel(titles, text=f"Copiaste un enlace {adj}", font=self.f["value"], text_color=TEXT, height=20, anchor="w").pack(anchor="w")
        ctk.CTkLabel(titles, text=f"{THREATS.get(v.threat, v.threat).capitalize()} · puntaje {fmt(v.score)}",
                     font=self.f["small"], text_color=strong, height=16, anchor="w").pack(anchor="w")
        ubox = ctk.CTkFrame(body, fg_color=BG, corner_radius=8)
        ubox.pack(fill="x", pady=(14, 10))
        ctk.CTkLabel(ubox, text=self._short(v.url, 58), font=self.f["url"], text_color=TEXT, anchor="w").pack(fill="x", padx=12, pady=6)
        items = [r.strip() for r in v.reasons if r.startswith("    ")]
        # el motivo más informativo primero: marca, IP, formulario o código antes que "No usa HTTPS"
        detail = next((r for r in items if r != "No usa HTTPS"), items[0] if items else "")
        msg = (detail + ". " if detail else "") + "No abras el enlace ni escribas tus datos."
        ctk.CTkLabel(body, text=msg, font=self.f["body"], text_color=TEXT, anchor="w", justify="left", wraplength=400).pack(fill="x")
        act = ctk.CTkFrame(body, fg_color="transparent")
        act.pack(fill="x", side="bottom")
        ctk.CTkButton(act, text="Entendido", image=self.ic.get("check", "#FFFFFF", 16), compound="left", font=self.f["bodyb"],
                      fg_color=ACCENT, hover_color=ACCENT_DARK, corner_radius=8, height=36, width=0,
                      command=win.destroy).pack(side="right")
        ctk.CTkButton(act, text="Ver detalles", image=self.ic.get("info", TEXT, 16), compound="left", font=self.f["body"],
                      fg_color=CARD, hover_color="#F3F5F8", text_color=TEXT, border_width=1, border_color=BORDER,
                      corner_radius=8, height=36, width=0,
                      command=lambda: (win.destroy(), self.deiconify(), self.lift(), self.focus_force())).pack(side="right", padx=8)
        win.after(150, lambda: (win.lift(), win.attributes("-topmost", True), win.focus_force()))

    # ================= acciones =================
    def on_analyze(self):
        url = self.url_var.get().strip()
        if url:
            self.start(url, "manual")

    def on_whitelist(self):
        if self.current and host_of(self.current.url):
            storage.add_whitelist(host_of(self.current.url))
            self.status.configure(text=f"{host_of(self.current.url)} agregado a excepciones")

    def on_history(self):
        win = ctk.CTkToplevel(self, fg_color=BG)
        win.title("Historial de análisis")
        win.geometry("940x560")
        win.transient(self)
        rows = storage.recent()
        head = ctk.CTkFrame(win, fg_color="transparent")
        head.pack(fill="x", padx=24, pady=(20, 12))
        ctk.CTkLabel(head, text="  Últimos análisis", image=self.ic.get("historial", TEXT, 20), compound="left",
                     font=self.f["value"], text_color=TEXT).pack(side="left")
        n = {k: sum(1 for r in rows if r[2] == k) for k in LEVELS}
        cnt = lambda k, one, many: f"{n[k]} {one if n[k] == 1 else many}"
        ctk.CTkLabel(head, text=f"{len(rows)} {'enlace' if len(rows) == 1 else 'enlaces'} · {cnt('peligrosa', 'peligroso', 'peligrosos')} · "
                                f"{cnt('sospechosa', 'sospechoso', 'sospechosos')} · {cnt('segura', 'seguro', 'seguros')}",
                     font=self.f["small"], text_color=MUTED).pack(side="right")
        table = self.card(win)
        table.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        cols = [(110, "Fecha"), (170, "Nivel"), (70, "Puntaje"), (0, "URL")]

        def make_row(parent, bg):
            r = ctk.CTkFrame(parent, fg_color=bg, corner_radius=0)
            r.pack(fill="x")
            for i, (w, _t) in enumerate(cols):
                r.grid_columnconfigure(i, minsize=w, weight=0 if w else 1)
            return r

        hdr = make_row(table, TRACK)
        hdr.pack_configure(padx=1, pady=(1, 0))
        for i, (_w, t) in enumerate(cols):
            ctk.CTkLabel(hdr, text=t.upper(), font=self.f["tag"], text_color=MUTED, anchor="e" if i == 2 else "w"
                         ).grid(row=0, column=i, sticky="ew", padx=(16 if i == 0 else 8, 8), pady=8)
        box = ctk.CTkScrollableFrame(table, fg_color=CARD, corner_radius=0, scrollbar_button_color=BORDER)
        box.pack(fill="both", expand=True, padx=1, pady=(0, 8))
        if not rows:
            ctk.CTkLabel(box, text="Todavía no has analizado enlaces.", font=self.f["body"], text_color=MUTED).pack(pady=24)
        for ts, url, level, threat, score in rows:
            strong = LEVELS.get(level, LEVELS["segura"])[0]
            r = make_row(box, CARD)
            ctk.CTkLabel(r, text=time.strftime("%d/%m %H:%M", time.localtime(ts)), font=self.f["body"], text_color=MUTED,
                         anchor="w").grid(row=0, column=0, sticky="ew", padx=(16, 8), pady=7)
            self.chip(r, level, strong, "#FFFFFF").grid(row=0, column=1, sticky="w", padx=8)
            ctk.CTkLabel(r, text=fmt(score), font=self.f["bodyb"], text_color=strong, anchor="e").grid(row=0, column=2, sticky="ew", padx=8)
            ctk.CTkLabel(r, text=self._short(url, 70), font=self.f["url"], text_color=TEXT, anchor="w").grid(row=0, column=3, sticky="ew", padx=(8, 16))
            ctk.CTkFrame(box, height=1, corner_radius=0, fg_color=TRACK).pack(fill="x")
        win.after(150, lambda: (win.lift(), win.focus_force()))

    def watch_clipboard(self):
        if self.watch_var.get():
            try:
                txt = self.clipboard_get().strip()
            except tk.TclError:
                txt = ""
            if txt and txt != self.last_clip and URL_RE.match(txt):
                self.last_clip = txt
                self.url_var.set(txt)
                self.start(txt, "clipboard")
        self.after(1000, self.watch_clipboard)


if __name__ == "__main__":
    App().mainloop()
