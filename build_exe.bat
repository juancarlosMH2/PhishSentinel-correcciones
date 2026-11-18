@echo off
REM Genera dist\PhishSentinel.exe (ejecuta esto en Windows, dentro del entorno virtual del proyecto)
pyinstaller --noconsole --onefile --name PhishSentinel ^
  --add-data "models;models" --add-data "assets;assets" ^
  --collect-data tldextract --collect-submodules sklearn --collect-all xgboost --collect-all customtkinter ^
  main.py
