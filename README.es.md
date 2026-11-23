# Plugin DMARC para GLPI

[English](README.md)

Recoge de un buzón IMAP los **informes agregados DMARC** (RUA) que envían los receptores de correo
(Google, Microsoft, Yahoo…) sobre sus dominios y los muestra en GLPI, en **Herramientas › DMARC**: quién
envía correo como sus dominios, qué cumple y qué falla en SPF/DKIM/DMARC y por qué, y cuándo se puede
endurecer la política.

* GLPI **11.0** y **12.0** · PHP **8.2+** · Licencia **GPLv2+**
* Idiomas: inglés y español (`locales/`)

## Qué hace

* **Recogida** de una carpeta del buzón (`DMARC` por defecto), en segundo plano, sin bloquear GLPI:

  * **Gmail / Google Workspace con OAuth** (consentimiento del dueño del buzón; sin cuenta de servicio
ni delegación de dominio) o **usuario y contraseña** en cualquier servidor IMAP. Cliente IMAP
propio: no hace falta la extensión `imap` de PHP.
  * **Solo lectura** por defecto (EXAMINE + BODY.PEEK: no cambia nada en el buzón) o **con escritura**:
marca como leído, mueve a otra carpeta o borra lo procesado.
  * Importación manual de ficheros `.eml`, `.zip`, `.gz` y `.xml` (web o consola).
* **Análisis** de informes RFC 7489 y DMARCbis (zip, gzip, XML), con límites de tamaño y sin DTD ni
entidades. Cada informe se guarda una vez; se puede conservar el XML original comprimido.
* **Cuadro de mando** con filtros (periodo, uno o varios dominios, quién informa, agrupación):
Resumen, Evolución, Fuentes de envío (con nombre inverso, proveedor y reputación de **AbuseIPDB**
opcional), Fallos (por causa, con explicación), Recomendaciones, Informes, Avisos y Recogida.
* **Notificaciones de GLPI** (Configuración › Notificaciones, tipo «Aviso DMARC»): fuente no autorizada
o desconocida, fuente autorizada que falla, dominio sin informes, errores de recogida y resumen
semanal. Interruptor general en la configuración del plugin (apagado por defecto).
* **Entidad**: el plugin funciona en una entidad (y opcionalmente sus subentidades).
* **Retención**: hasta 36 meses, con limpieza diaria.
* Derecho propio **DMARC** en Administración › Perfiles: Lectura y Actualización.

## Instalación

### Instalador de una línea

En el servidor de GLPI (como root o con un usuario que pueda escribir en la carpeta de GLPI):

```sh
curl -fsSL https://raw.githubusercontent.com/yacomelian/main/install.sh | bash
```

Pregunta la carpeta de GLPI (y propone las habituales), comprueba que es GLPI 11 o 12 con las
extensiones de PHP necesarias, descarga la última versión publicada, comprueba su SHA-256, guarda una
copia de la versión anterior, la instala con el dueño de los ficheros de GLPI y ejecuta
`glpi:plugin:install` + `activate`.

Opciones: `--path /var/www/glpi`, `--version 1.0.0`, `--container NOMBRE` (GLPI en Docker/Podman),
`--no-activate`, `--yes`. Ver `install.sh --help`.

### Manual

1. Descargue `glpi-dmarc-X.Y.Z.tar.bz2` de las [versiones publicadas](https://github.com/yacomelian/glpi-plugin-dmarc/releases).
2. Descomprímalo en la carpeta `plugins/` (o `marketplace/`) de GLPI: crea `dmarc/`.
3. `php bin/console glpi:plugin:install dmarc -u glpi` y `php bin/console glpi:plugin:activate dmarc`.

### Requisitos

* GLPI 11.0.x o 12.0.x, PHP 8.2 o superior con `openssl`, `zlib`, `zip`, `curl`, `mbstring`, `simplexml`.
* Las acciones automáticas (cron) de GLPI en marcha.
* Salida desde el servidor al IMAP (`imap.gmail.com:993` en Gmail), a `oauth2.googleapis.com:443`
para OAuth y a `api.abuseipdb.com:443` para AbuseIPDB. Se usa el proxy de GLPI.
* Los trabajos en segundo plano usan `exec()` de PHP en Linux; sin él, la recogida se hace dentro de la
acción automática.

## Configuración con Gmail / Google Workspace

1. **Google Cloud** (una vez): Credenciales › Crear credenciales › ID de cliente de OAuth, tipo
«Aplicación web». En «URI de redireccionamiento autorizados», la dirección que muestra la
configuración del plugin (`https://<URL de GLPI>/plugins/dmarc/front/oauth.php`, debe ser https).
Pantalla de consentimiento de tipo **Interno** (con «Externo» en pruebas, Google caduca el permiso
a los 7 días).
2. **GLPI**: servidor `imap.gmail.com`, puerto 993, SSL, usuario (la dirección del buzón), carpeta
`DMARC`, y el ID y el secreto del cliente OAuth.
3. **Guardar y conectar con Google**: entre **con la cuenta del buzón** y autorice. El plugin solo guarda
el permiso si la cuenta autorizada es la del buzón.
4. **Guardar y probar la conexión.**

## Consola

```
php bin/console plugins:dmarc:collect \[--all | --limit=N | --test | --resolve | --check | --summary]
php bin/console plugins:dmarc:import /ruta/a/ficheros-o-carpeta
```

## Seguridad

Secretos cifrados por GLPI, OAuth limitado al buzón que autoriza, informes tratados como datos no
fiables (sin DTD ni entidades, límites de descompresión, todo escapado), buzón en solo lectura por
defecto y acceso a la base de datos solo con el constructor de consultas de GLPI. Para informar de una
vulnerabilidad, vea [SECURITY.md](SECURITY.md).

## Licencia

GPLv2+ — vea [LICENSE](LICENSE). Copyright © 2026 Yaco Melian.

