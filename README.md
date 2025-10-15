# IMAP to MISP Ingestor

Este proyecto implementa un pipeline automático para leer alertas de seguridad desde una cuenta de correo IMAP, extraer Indicadores de Compromiso (IOCs) tanto del cuerpo de los emails como de ficheros CSV adjuntos, y crear eventos en una instancia de MISP.

Está diseñado para correr como un servicio `systemd` bajo un usuario sin privilegios y sigue las mejores prácticas de seguridad y robustez.

## 🚀 Características

-   **Lectura IMAP**: Se conecta de forma segura a un buzón IMAP y procesa los correos no leídos.
-   **Procesamiento Híbrido**: Extrae IOCs del texto del email y de filas de ficheros CSV adjuntos. [cite: 1]
-   **Clasificación Inteligente**: Usa `mappings.json` para clasificar alertas y generar eventos con contexto (tags, MITRE ATT&CK, etc.). [cite: 2]
-   **Enriquecimiento**: Filtra IPs por país (GeoIP) y enriquece con la puntuación de `AbuseIPDB`. [cite: 86]
-   **Persistencia**: Usa una base de datos SQLite para no procesar el mismo email dos veces. [cite: 3]
-   **Seguridad**:
    -   Utiliza variables de entorno para las credenciales.
    -   Se ejecuta como un usuario de sistema sin privilegios (`misp-automation`).
    -   Incluye modo `--dry-run` para simulación. [cite: 3]
    -   Logs en formato JSON y un log de auditoría en CSV. [cite: 3]

## 🔧 Instalación

Sigue estos pasos en la VM de MISP como usuario `root`.

**1. Clonar Repositorio**

```bash
sudo git clone <URL_DEL_REPO> /opt/misp-mail-ingestor
```

**2. Crear Usuario de Servicio y Configurar Entorno**

```bash
sudo bash scripts/create_service_user.sh
cd /opt/misp-mail-ingestor
sudo chown -R misp-automation:misp-automation /opt/misp-mail-ingestor
sudo -u misp-automation bash scripts/venv_setup.sh
```

**3. Configuración**

```bash
# Copia la configuración de ejemplo
sudo cp config.yaml.example config.yaml

# Edita el fichero para ajustarlo a tu entorno
sudo nano config.yaml
```

Asegúrate de configurar correctamente los datos de `IMAP`, `MISP` y las rutas a las bases de datos.

**4. Gestionar Secretos**

Crea un fichero para las variables de entorno y protégelo.

```bash
sudo nano /etc/default/misp-mail-ingestor
```

Añade las siguientes líneas con tus credenciales:

```
IMAP_PASS="tu_contraseña_de_imap"
MISP_API_KEY="tu_api_key_de_misp"
ABUSEIPDB_API_KEY="tu_api_key_de_abuseipdb"
```

Aplica permisos restrictivos:

```bash
sudo chmod 640 /etc/default/misp-mail-ingestor
sudo chown misp-automation:misp-automation /etc/default/misp-mail-ingestor
```

**5. Instalar Servicio y Timer de Systemd**

```bash
sudo cp systemd/misp-mail2misp.service /etc/systemd/system/
sudo cp systemd/misp-mail2misp.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

**6. Activar el Timer**

```bash
sudo systemctl enable --now misp-mail2misp.timer
```

Para verificar que el timer está activo: `systemctl list-timers`

**7. Configurar Rotación de Logs**

```bash
sudo cp logrotate/misp-mail2misp /etc/logrotate.d/
```

## ⚙️ Uso

### Ejecución Manual

Puedes ejecutar el script manualmente para depuración:

```bash
cd /opt/misp-mail-ingestor
sudo -u misp-automation /opt/misp-mail-ingestor/venv/bin/python imap_to_misp.py --config config.yaml --once --verbose
```

Usa `--dry-run` para simular la ejecución sin realizar cambios en MISP.

### Ver Logs

-   **Logs de aplicación (JSON)**: `sudo tail -f /var/log/misp-automation/ingestor.log`
-   **Logs de auditoría (CSV)**: `sudo tail -f /var/log/misp-automation/audit.csv`

## 🛡️ Hardening de Seguridad

-   **Permisos**: Los ficheros de configuración y el directorio de la aplicación pertenecen al usuario `misp-automation` con permisos restrictivos.
-   **Credenciales**: Las claves y contraseñas se gestionan exclusivamente mediante variables de entorno y no están en el código.
-   **Integración con Vault**: Para una gestión de secretos más avanzada, puedes modificar el script para que obtenga las credenciales desde HashiCorp Vault usando la librería `hvac` en lugar de `os.environ.get`.
