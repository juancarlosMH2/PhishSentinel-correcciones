# Resultados de las correcciones

Correcciones pedidas por el profesor:

1. Aumentar la clasificación o las características.
2. Darle prioridad a la capa 2 (contenido).
3. Bajar la prioridad de la capa 1 (URL).
4. Entrenar con URLs largas legítimas.

Todas las cifras de "Antes" son del código y el modelo de la versión 1.0 del
repositorio (Random Forest); las de "Después", del modelo final (XGBoost
entrenado con las 150.000 URLs de `data/processed/urls.csv`). Los scripts que
las generan están en `training/` (ver la sección "Pruebas" del README).

## Resumen

| Prueba | Antes | Después |
| --- | --- | --- |
| URLs largas legítimas modernas escritas a mano (54) marcadas por error, solo capa 1 | 38,9 % | 24,1 % |
| URLs legítimas de 100+ caracteres no vistas (2.000) marcadas por error | 2,2 % | 3,0 % |
| Phishing de 100+ caracteres no visto (1.579) detectado | — | 97,7 % |
| Legítima reescrita de `https://www.` a `http://` marcada por error | 100 % | 8,6 % (igual que con https) |
| Phishing reescrito de `http://` a `https://` detectado | 70,9 % | 88,2 % (igual que con http) |
| Phishing no visto en el entrenamiento detectado (3.000), solo capa 1 | 98,2 % | 87,9 % |
| Dominios populares de Tranco 20.000–30.000 marcados por error | 5,0 % | 5,3 % |
| Casos de capa 2 con páginas de ejemplo (`layer2_cases_test`) | 5 de 8 | 8 de 8 |
| `tiktok.com/es/` (legítima de ruta corta), puntaje de la capa 1 | 0,84 | 0,34 |
| Phishing con la marca dentro del dominio (`nequi-premios.com`, `soporte-apple-id.com`, punycode) | salían seguras | 10 de 10 peligrosas |
| F1 macro en el conjunto de prueba | 0,985 | 0,935 |

## Por qué bajan el F1 y la detección de phishing

El modelo anterior tenía un **atajo**: en `URL dataset.csv` el 99,8 % de las
URLs legítimas empiezan con `https://www.` y solo el 6 % del phishing usa
https. El modelo aprendió "https = legítima" en lugar de mirar la URL. Por eso
su 0,985 de F1 y su 98 % de detección estaban inflados: si a una URL legítima
solo se le cambiaba `https://www.` por `http://`, la marcaba como maliciosa el
100 % de las veces, y si al phishing se le ponía `https://`, la detección
bajaba al 71 %. Hoy la mayoría del phishing usa https.

Ahora todas las características se calculan sobre la **URL canónica** (sin
`http(s)://`, sin `www.` y sin `/` final), así que el resultado ya no depende
del esquema. Había un segundo atajo del mismo tipo: los dominios legítimos de
Tranco se guardaban como `https://dominio/` y el phishing sin la barra final.

## Qué cambió

### 1. Más características
- **Capa 1:** de 29 a 40 características. Nuevas: largo, dígitos, guiones y
  entropía del dominio registrado; TLD de uso frecuente en phishing; marca
  usada en un dominio que no es el oficial (incluye disfraces como
  `bancol0mbia` y punycode, y *typosquatting* como `instagran`); marca en el
  subdominio o la ruta; dominio incrustado en la ruta; `http` dentro de la URL;
  token más largo (IDs aleatorios); extensión `.php` y extensiones riesgosas.
  Con la misma muestra, solo las nuevas características suben el F1 de 0,898 a
  0,932.
- **Capa 2:** de 5 a 14 reglas. Nuevas: suplantación de marca (título o logo de
  una marca en un dominio ajeno que pide datos), campos sensibles (tarjeta,
  CVV, PIN, cédula), acción de formulario sospechosa, redirección automática a
  otro dominio, favicon externo, enlaces vacíos, enlaces casi todos externos,
  bloqueo del clic derecho y campo de contraseña.
- Se evaluó la otra opción ("aumentar la clasificación" con las clases
  *malware* y *defacement* de `malicious_phish.csv`), pero se eligió ampliar las
  características porque responde directamente a la pregunta de investigación.

### 2 y 3. Prioridad de las capas
- Con la página descargada: `puntaje = 0,3 × capa 1 + 0,7 × capa 2` (antes
  0,6 / 0,4, y el contenido solo podía **subir** el puntaje).
- Una página limpia ahora sí puede bajar el puntaje de una URL que solo "se ve
  rara". Ejemplo: un enlace de Google Docs con ID largo tiene 0,83 en la capa 1
  y queda **segura** al revisar el contenido.
- Si el contenido confirma el ataque (contraseña enviada a otro dominio,
  suplantación de marca o parámetro reflejado) el puntaje sube a 0,85.
- La capa 1 sola solo puede dejar la URL como **sospechosa** cuando el modelo
  está casi seguro (≥ 0,95) y la página no mostró nada; no aplica a dominios
  oficiales de marcas.
- La página se descarga casi siempre (antes se omitía con 0,95 o más; ahora
  solo con 0,99 o más), con un límite total de 10 s.

### 4. URLs largas legítimas
- Unas 11.000 URLs de 100+ caracteres por clase (legítima y phishing), para que
  la longitud deje de ser por sí sola señal de phishing o de legitimidad.
- 8.000 de las legítimas largas se generan sobre dominios de Tranco con la forma
  de las URLs reales: IDs aleatorios largos, parámetros `utm`, `gclid`,
  `fbclid`, OAuth (`client_id`, `redirect_uri`) y subdominios (`mail.`,
  `docs.`, `login.`).
- 1.200 URLs legítimas de ruta corta (`tiktok.com/es/`, `ejemplo.com/help`):
  casi no existían en la clase legítima y el modelo marcaba como phishing
  cualquier ruta corta.

## Comparación de algoritmos (20.000 URLs, igual que la versión 1.0)

El mejor modelo se elige por validación cruzada (`cv_f1`), no por el conjunto de
prueba. SVM y KNN se comparan con 20.000 URLs porque son lentos con más datos.

| Modelo | cv_f1 | Accuracy | Precisión | Recall | F1 | Falsos positivos |
| --- | --- | --- | --- | --- | --- | --- |
| Random Forest | 0,906 | 0,911 | 0,910 | 0,911 | 0,911 | 13,6 % |
| XGBoost | 0,905 | 0,912 | 0,912 | 0,912 | 0,912 | 12,1 % |
| KNN | 0,870 | 0,869 | 0,870 | 0,869 | 0,870 | 17,2 % |
| SVM | 0,855 | 0,867 | 0,870 | 0,867 | 0,867 | 14,8 % |
| Regresión logística | 0,813 | 0,817 | 0,833 | 0,818 | 0,820 | 14,5 % |

**Modelo de la app:** XGBoost con las 150.000 URLs (cv_f1 0,932; F1 0,935).
Con todo el conjunto, Random Forest queda prácticamente igual (cv_f1 0,934 en
una versión anterior de los datos) pero pesa más de 300 MB, lo que no cabe en
GitHub y vuelve enorme el .exe; XGBoost pesa 12 MB y predice más rápido. Sus
hiperparámetros (600 árboles, profundidad 8, tasa 0,1) se eligieron con
validación cruzada de 3 particiones.

## Umbral de "sospechosa"

Capa 1 sola, URLs no vistas en el entrenamiento:

| Corte | Legítimas del dataset marcadas | Tranco marcados | Largas a mano marcadas | Phishing detectado |
| --- | --- | --- | --- | --- |
| 0,40 | 10,9 % | 9,1 % | 27,8 % | 91,2 % |
| 0,45 | 9,6 % | 6,6 % | 24,1 % | 90,2 % |
| **0,50 (actual)** | **8,3 %** | **5,3 %** | **24,1 %** | **88,8 %** |
| 0,55 | 6,9 % | 4,1 % | 20,4 % | 87,6 % |

Entre 0,40 y 0,49 caen cerca del 2,6 % de las legítimas y el 2,4 % del
phishing: en esa franja el modelo casi no distingue. Por eso el corte se deja
en 0,50 y, de 0,40 a 0,49, la URL sale **segura con un aviso** ("puntaje
cercano al límite") en lugar de lanzar una alerta.

## Limitaciones conocidas

- **Capa 2 con sitios reales:** se probó sin internet, con páginas de ejemplo
  (`data/eval/html/`). La cifra con sitios reales se obtiene con
  `python -m training.tranco_layer2_test --n 100`; `falsos_positivos_capa2.csv`
  todavía es de la versión 1.0.
- **Las 54 URLs largas a mano** (`data/eval/urls_largas_legitimas.txt`) siguen
  patrones parecidos a los del generador de URLs largas: esa cifra es
  indicativa. Las independientes son las del dataset no vistas y las de Tranco.
- **Páginas oficiales de marcas** (por ejemplo `paypal.com/signin`): la capa 1
  sola todavía las marca alto, porque palabras como "paypal" cuentan como
  sospechosas aunque el dominio sea el oficial. Al descargar la página, la
  capa 2 baja el puntaje.
- **Si la página no se puede descargar** (los sitios de phishing caen rápido),
  decide solo la capa 1.
- PhishSentinel detecta phishing y XSS, no sitios de piratería con publicidad
  maliciosa (*malvertising*).
