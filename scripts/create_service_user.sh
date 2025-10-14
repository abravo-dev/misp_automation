#!/bin/bash
# Este script crea el usuario de servicio y los directorios necesarios.
set -e

USERNAME="misp-automation"
GROUP="misp-automation"
COMMENT="Service user for MISP automation scripts"
STATE_DIR="/var/lib/${USERNAME}"
LOG_DIR="/var/log/${USERNAME}"

echo ">>> Creando grupo de sistema ${GROUP}..."
groupadd --system ${GROUP} || echo "El grupo ${GROUP} ya existe."

echo ">>> Creando usuario de sistema ${USERNAME}..."
useradd --system --gid ${GROUP} --no-create-home --shell /sbin/nologin -c "${COMMENT}" ${USERNAME} || echo "El usuario ${USERNAME} ya existe."

echo ">>> Creando directorios requeridos..."
mkdir -p ${STATE_DIR}
mkdir -p ${LOG_DIR}

echo ">>> Asignando permisos..."
chown -R ${USERNAME}:${GROUP} ${STATE_DIR}
chown -R ${USERNAME}:${GROUP} ${LOG_DIR}
chmod 750 ${STATE_DIR}
chmod 750 ${LOG_DIR}

echo ">>> Proceso completado."