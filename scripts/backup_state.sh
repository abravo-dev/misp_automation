#!/bin/bash
# Realiza una copia de seguridad de la base de datos de estado.
set -e

STATE_DB="/var/lib/misp-automation/state.db"
BACKUP_DIR="/var/backups/misp-automation"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/state_${TIMESTAMP}.db.gz"

echo ">>> Realizando copia de seguridad de la base de datos de estado..."
mkdir -p ${BACKUP_DIR}
sqlite3 ${STATE_DB} ".backup '${BACKUP_DIR}/temp_backup.db'"
gzip -c "${BACKUP_DIR}/temp_backup.db" > "${BACKUP_FILE}"
rm "${BACKUP_DIR}/temp_backup.db"

# Asigna permisos y limpia copias antiguas (mantiene las últimas 7)
chmod 600 "${BACKUP_FILE}"
find "${BACKUP_DIR}" -name "*.db.gz" -type f -mtime +7 -delete

echo ">>> Copia de seguridad completada: ${BACKUP_FILE}"