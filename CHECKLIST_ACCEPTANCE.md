---

### `CHECKLIST_ACCEPTANCE.md` (Versión Completa)

```markdown
# Checklist de Aceptación del Ingestor IMAP-MISP

Este documento define los criterios para verificar que la instalación y configuración del servicio son correctas.

### ✅ Fase 1: Instalación y Configuración

-   [ ] El usuario `misp-automation` ha sido creado y no tiene shell (`/sbin/nologin`).
-   [ ] El repositorio ha sido clonado en `/opt/misp-mail-ingestor`.
-   [ ] El propietario del directorio `/opt/misp-mail-ingestor` es `misp-automation`.
-   [ ] El script `venv_setup.sh` se ha ejecutado correctamente y existe el directorio `venv`.
-   [ ] El fichero `config.yaml` ha sido creado y configurado con los parámetros correctos.
-   [ ] El fichero de secretos `/etc/default/misp-mail-ingestor` existe, tiene permisos `640` y contiene las credenciales.
-   [ ] Los ficheros `misp-mail2misp.service` y `misp-mail2misp.timer` están en `/etc/systemd/system/`.
-   [ ] El timer `misp-mail2misp.timer` está activo y programado (`systemctl list-timers`).
-   [ ] El fichero de configuración de `logrotate` está en `/etc/logrotate.d/`.

### ✅ Fase 2: Pruebas Funcionales

-   [ ] La ejecución de las pruebas unitarias pasa sin errores: `sudo -u misp-automation pytest`.
-   [ ] Una ejecución manual con `--dry-run --once` finaliza sin errores y muestra en los logs las acciones que realizaría (`Would create event...`).
-   [ ] (Enviar un correo de prueba a la bandeja de entrada) Una ejecución manual sin `--dry-run` procesa el correo correctamente.
-   [ ] Se crea un nuevo evento en MISP con la información del correo de prueba.
-   [ ] Los atributos (IPs, dominios) se añaden al evento en MISP.
-   [ ] El log de aplicación (`ingestor.log`) registra la actividad en formato JSON.
-   [ ] El log de auditoría (`audit.csv`) registra la creación del evento y los atributos.
-   [ ] El script marca el correo como procesado en la base de datos SQLite (`/var/lib/misp-automation/state.db`).
-   [ ] Una segunda ejecución no procesa el mismo correo de nuevo.
-   [ ] Una IP de un país en `EXCLUDE_COUNTRIES` es omitida y logueada como tal.
-   [ ] Una IP privada (ej. `192.168.1.50`) se añade al evento, pero con `to_ids` a `false`.