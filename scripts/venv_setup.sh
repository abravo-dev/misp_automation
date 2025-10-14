#!/bin/bash
# Crea el entorno virtual de Python e instala las dependencias.
# Debe ejecutarse como el usuario de servicio: sudo -u misp-automation bash scripts/venv_setup.sh
set -e

APP_DIR="/opt/misp-mail-ingestor"
VENV_DIR="${APP_DIR}/venv"
REQUIREMENTS_FILE="${APP_DIR}/requirements.txt"

if [ "$(id -u)" -eq 0 ]; then
  echo "ERROR: Este script debe ejecutarse como el usuario de servicio."
  echo "Ejemplo: sudo -u misp-automation bash $0"
  exit 1
fi

echo ">>> Creando entorno virtual en ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"

echo ">>> Instalando dependencias desde ${REQUIREMENTS_FILE}..."
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip
pip install -r "${REQUIREMENTS_FILE}"
deactivate

echo ">>> Entorno virtual configurado correctamente."