@echo off
REM Genera dist\PhishSentinel.exe (ejecuta esto en Windows, dentro del entorno virtual del proyecto)
REM --hidden-import phishsentinel.model: el modelo se carga con joblib y PyInstaller no ve ese import.
pyinstaller --noconsole --onefile --name PhishSentinel ^
  --add-data "models\model_url.joblib;models" --add-data "assets;assets" ^
  --hidden-import phishsentinel.model ^
  --collect-data tldextract --collect-submodules sklearn --collect-all xgboost --collect-all customtkinter ^
  main.py
