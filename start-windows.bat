@echo off
REM Inicia o QRZ Monitor no Windows

REM Instala dependências
call install-windows.bat

REM Executa o monitor
python qrz-monitor.py
