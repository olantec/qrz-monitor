#!/bin/bash
# Instala dependências do QRZ Monitor para Linux (Debian, Ubuntu, Raspberry Pi)

echo "Atualizando lista de pacotes..."
sudo apt update

echo "Instalando Python3 e pip, se necessário..."
sudo apt install -y python3 python3-pip

echo "Atualizando pip..."
python3 -m pip install --upgrade pip

echo "Instalando dependências do projeto..."
python3 -m pip install requests pystray Pillow

echo "Dependências instaladas com sucesso!"
