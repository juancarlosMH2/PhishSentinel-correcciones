# Evaluación final — modelo XGBoost (v2)

Umbrales calibrados en validación: **T_LOW=0.0314**, **T_HIGH=0.8799**. Entrenado con 196646 URLs.

## 1. Partición de prueba (dominios que NO se usaron para entrenar)

F1 macro **0.8868** · falsos positivos (argmax) 9.55%

| clase | precisión | recall | F1 | n |
|---|---|---|---|---|
| legitimate | 0.802 | 0.904 | 0.850 | 10146 |
| malware | 0.962 | 0.812 | 0.880 | 3028 |
| phishing | 0.858 | 0.788 | 0.821 | 10001 |
| xss | 0.995 | 0.995 | 0.995 | 3901 |

Matriz de confusión (filas = real, columnas = predicho): ['legitimate', 'malware', 'phishing', 'xss']
```
[[9177   13  945   11]
 [ 213 2458  357    0]
 [2030   85 7878    8]
 [  19    0    1 3881]]
```

## 2. Tranco 20,001–30,000 (fuente distinta; solo dominios raíz)

| conjunto | n | pasa directo | zona de duda | bloqueo directo | marcada con 0.5 |
|---|---|---|---|---|---|
| todos | 10000 | 46.80% | 53.18% | 0.02% | 0.71% |
| no vistos en entrenamiento | 9633 | 46.53% | 53.45% | 0.02% | 0.74% |

Falso positivo **sin capa 2** = 'bloqueo directo'. La zona de duda se resuelve con la capa 2 (descarga del HTML); su efecto real depende del sitio y debe medirse con `python -m training.tranco_layer2_test`.

## 3. URLs largas legítimas

| conjunto | n | pasa directo | zona de duda | bloqueo directo | marcada con 0.5 |
|---|---|---|---|---|---|
| REALES >=100 car. (dominios no vistos) | 3138 | 82.95% | 16.38% | 0.67% | 2.14% |
| sintéticas sobre Tranco de prueba (optimista) | 3000 | 94.80% | 5.17% | 0.03% | 0.40% |
| legítimas reales <100 car. (referencia) | 7008 | 48.92% | 47.96% | 3.12% | 13.13% |

## 4. Recall en amenazas de dominios no vistos

| tipo | n | pasa directo (se escapa sin capa 2) | zona de duda | bloqueo directo |
|---|---|---|---|---|
| phishing con ruta | 9271 | 1.11% | 68.47% | 30.42% |
| phishing solo dominio | 730 | 5.21% | 68.49% | 26.30% |
| phishing fuente phishtank | 5033 | 0.95% | 77.73% | 21.32% |
| phishing fuente mphish | 2456 | 2.20% | 73.29% | 24.51% |
| phishing fuente urlds | 2512 | 1.55% | 45.22% | 53.22% |
| malware | 3028 | 0.99% | 11.72% | 87.29% |
| xss | 3901 | 0.08% | 0.67% | 99.26% |

'Pasa directo' = amenazas que la capa 1 deja pasar **sin** consultar la capa 2 (el hueco real del sistema).
