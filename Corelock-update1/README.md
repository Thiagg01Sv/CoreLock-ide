# CoreLock — Sistema de Seguridad para Windows

## Uso rápido (esto es lo que probablemente querés hacer)

```bash
pip install -r requirements.txt
python corelock_core.py
```

Esto prende **las 6 capas de protección al mismo tiempo**: mineros, red
maliciosa, ransomware, robo de cookies/tokens (Discord, Steam), malware
general, y amenazas en USB. Cada una detecta y, si confirma una amenaza
real, **actúa sola**: mata el proceso y pone el archivo en cuarentena —
sin que tengas que hacer nada. Además, cada alerta importante viene
acompañada de una explicación en lenguaje simple (🗣), no solo el nombre
técnico de la amenaza.

Corré esto como Administrador para que las 5 capas funcionen al 100%.

**Para que arranque solo cada vez que prendés la PC:**

```powershell
# En PowerShell COMO ADMINISTRADOR:
.\install_startup.ps1
```

Esto lo registra como Tarea Programada de Windows, con privilegios de
Administrador, arrancando apenas iniciás sesión. Para desinstalarlo:
`.\install_startup.ps1 -Uninstall`

---

## Contenido del paquete

| Archivo | Qué hace |
|---|---|
| `corelock_core.py` | **EMPEZÁ ACÁ.** Orquestador: corre las 6 capas al mismo tiempo, en paralelo |
| `install_startup.ps1` | Registra CoreLock para que arranque solo con Windows (Tarea Programada) |
| `response_engine.py` | El "sistema inmune": convierte alertas críticas en acción real (mata proceso + cuarentena) |
| `plain_language.py` | **NUEVO.** Traduce cada alerta técnica a lenguaje simple: qué pasó, por qué importa, qué se hizo |
| `usb_guard.py` | **NUEVO.** Escanea unidades USB al conectarse (autorun.inf, ejecutables disfrazados de carpeta, .lnk sospechosos) antes de que las abras |
| `miner_detector.py` | Detecta mineros de criptomonedas ocultos + auto-termina el proceso confirmado |
| `network_guard.py` | Detecta y bloquea actividad de red riesgosa + auto-termina el proceso responsable |
| `ransomware_guard.py` | Detecta ransomware con archivos señuelo + intenta identificar y matar el proceso responsable |
| `cookie_guard.py` | Detecta robo de cookies/credenciales **+ tokens de Discord y sesión de Steam** (infostealers) |
| `malware_scanner.py` | Verifica hashes contra VirusTotal + auto-cuarentena de archivos confirmados como maliciosos |
| `test_*.py` | Tests automáticos de cada módulo (35 tests, corren en <0.2s, no requieren admin) |
| `simulate_test_activity.py` | Generador de actividad de PRUEBA controlada para validar en vivo |
| `requirements.txt` | Dependencias de Python |

---

## ⚠ Incidente conocido y resuelto (28 de agosto de 2026)

Durante testing en producción, `miner_detector.py` marcó falsamente a
`explorer.exe` (el Explorador de Windows, proceso 100% legítimo) como
"disfrazado", porque la lista de rutas legítimas solo contemplaba
`System32`/`SysWOW64` y `explorer.exe` en realidad vive en `C:\Windows\`.
Con `AUTO_RESPOND` activado, esto causó que CoreLock matara el Explorador
repetidamente (Windows lo reiniciaba solo, generando un PID nuevo cada
~5 segundos, y CoreLock lo volvía a matar).

**Ya está arreglado en este paquete**, con dos capas de corrección:

1. **Fix de raíz:** ahora cada proceso de sistema tiene su ruta legítima
   específica verificada (`LEGIT_PATHS_BY_PROCESS`), no una lista genérica.
2. **Red de seguridad central:** `response_engine.py` ahora rechaza matar
   o poner en cuarentena una lista fija de procesos/archivos core de
   Windows (`explorer.exe`, `csrss.exe`, `lsass.exe`, etc.), sin importar
   qué tan convencido esté un detector -- esto es intencional como defensa
   ante bugs de heurística que todavía no conocemos.

6 tests nuevos cubren específicamente este caso para que no pueda
repetirse silenciosamente. Si alguna vez ves un mensaje
`[BLOQUEADO POR RED DE SEGURIDAD]` en la consola, significa que un
detector marcó algo como amenaza pero la red de seguridad lo frenó antes
de actuar -- revisá esa alerta manualmente, es justamente el tipo de caso
límite que preferimos que veas vos antes que el sistema actúe solo.

---

## Sobre response_engine.py — el "anticuerpo" que pediste

**Qué hace exactamente cuando algo se confirma como amenaza:**

1. **Mata el proceso** (`kill_process`) — termina la ejecución inmediatamente
2. **Pone el archivo en cuarentena** (`quarantine_file`) — lo mueve a una carpeta aislada (`~/.corelock_quarantine`), le cambia el nombre para que no se pueda ejecutar por accidente, y le quita permisos de ejecución/lectura general

**Por qué cuarentena y no borrado directo:** ningún sistema de detección es perfecto — ni el nuestro, ni Windows Defender, ni Kaspersky. Un antivirus que borra sin posibilidad de deshacer es un antivirus que en algún momento te va a hacer perder un archivo legítimo por un falso positivo. La cuarentena te da la opción de recuperar algo con `restore_from_quarantine()` si algo se marcó por error.

**Honestidad sobre el límite real de esto:** ningún antivirus del mundo detecta "cualquier tipo" de malware al 100% — existen los llamados *zero-days* (malware nuevo que nadie vio antes). Lo que construimos maximiza la cobertura combinando 5 técnicas de detección distintas (comportamiento de CPU, patrones de red, archivos señuelo, acceso a datos sensibles, y verificación contra 70+ motores antivirus reales), pero ningún sistema — ni el nuestro ni ningún otro — puede prometer detección universal. Es una carrera permanente, no algo que se resuelve una sola vez.

**Cada módulo tiene su propio flag `AUTO_RESPOND = True`** al inicio del archivo — poné `False` si en algún momento preferís que solo alerte y no actúe solo (por ejemplo, mientras estás calibrando sensibilidad y no querés que mate procesos por error).

---

## Sobre ransomware_guard.py y cookie_guard.py — por qué funcionan así

**Ransomware:** en vez de intentar adivinar "qué proceso se ve sospechoso", plantamos archivos señuelo invisibles en Documentos/Escritorio/Imágenes. Ningún programa legítimo tiene ninguna razón para tocarlos jamás. Si algo los modifica, renombra o borra, es una señal casi 100% confiable — es la misma técnica que usan EDR profesionales (CrowdStrike, CoreLockOne) bajo el nombre de "deception technology". Además detecta si de golpe se modifican 20+ archivos reales en 10 segundos, patrón clásico de cifrado masivo.

**Cookies:** Chrome/Edge/Brave **ya cifran** las cookies en disco con DPAPI (atado a tu cuenta de Windows) — no hace falta que nosotros agreguemos otra capa de cifrado, sería redundante y podría romper el navegador. Lo que sí agregamos es detección del robo real: los infostealers no "descifran" nada, copian el archivo de cookies directamente mientras el navegador tiene la sesión abierta. `cookie_guard.py` vigila exactamente eso: cualquier proceso que NO sea un navegador tocando esos archivos.

---


## 1. Instalación

```bash
pip install -r requirements.txt
```

Windows 10/11, Python 3.9+.

---

## 2. Cómo testear que funciona (3 niveles)

### Nivel 1 — Tests automáticos (empezá siempre por acá)

Esto valida la LÓGICA de decisión sin necesitar admin, sin esperar tiempo real,
y sin generar ningún tráfico o carga real en tu PC. Son los tests que ya corrimos
durante el desarrollo — de hecho, encontraron y nos permitieron arreglar un bug real
de manejo de rutas de Windows antes de que llegara a tus manos.

```bash
pip install pytest
python -m pytest test_miner_detector.py test_network_guard.py -v
```

Deberías ver algo como:

```
14 passed in 0.05s
```

Si algún test falla después de que vos modifiques el código (por ejemplo, si cambiás
umbrales o agregás una nueva heurística), es tu señal de que rompiste algo antes de
que llegue a producción. **Corré esto cada vez que toques el código.**

---

### Nivel 2 — Prueba en vivo controlada (con actividad simulada, no real)

Acá confirmás que el programa realmente reacciona en tu PC de verdad, generando
actividad benigna que IMITA los patrones sospechosos (nada de esto es malware real).

**Abrí 2-3 terminales (PowerShell como Administrador para las que corren el guardián).**

#### Probar detección de CPU sostenida (minero simulado)

Terminal 1:
```bash
python miner_detector.py
```

Terminal 2:
```bash
python simulate_test_activity.py cpu
```

Por defecto el umbral real es 90 segundos — para no esperar tanto en la primera
prueba, editá `SUSTAINED_SECONDS = 15` arriba de `miner_detector.py`, guardá, y
volvé a correr ambos. Deberías ver una alerta `SOSPECHOSO` con el detalle de CPU
sostenida.

#### Probar bloqueo de puerto riesgoso

Terminal 1 (como Administrador):
```bash
python network_guard.py
```

Terminal 2:
```bash
python simulate_test_activity.py port
```

Terminal 3:
```bash
python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', 4444))"
```

Deberías ver en Terminal 1 una alerta `CRITICO` y, si corriste como Administrador,
un mensaje `ACCION` confirmando que se creó la regla de firewall.

**Verificar que el bloqueo realmente se aplicó:**
```bash
netsh advfirewall firewall show rule name=all | findstr CoreLock
```

Esto te lista todas las reglas que CoreLock creó — si aparecen, el bloqueo es real,
no solo un mensaje en consola.

#### Probar detección de patrón de escaneo/exfiltración

Terminal 1:
```bash
network_guard.py
```

Terminal 2:
```bash
python simulate_test_activity.py scan
```

Esto se conecta a 16 servidores DNS públicos reales (Google, Cloudflare, Quad9, etc.)
rápidamente — tráfico real e inofensivo, pero con el PATRÓN que dispara la alerta
de "demasiadas IPs distintas en poco tiempo".

---

### Nivel 3 — Prueba con software real (opcional, para verificación final)

Si querés el nivel más alto de confianza antes de confiar en esto día a día:

- **Para el detector de mineros:** descargá XMRig (es software legítimo de minería
  de código abierto, no es malware en sí — lo usan tanto mineros legítimos como
  atacantes) desde su repo oficial de GitHub, corré/o solo dejalo en el disco sin
  ejecutar, y confirmá que `check_known_miner_name` lo detecta apenas arranca el proceso.
  **No hace falta minar de verdad, con que el proceso exista alcanza para probar la detección.**

- **Para el guardián de red:** instalá `nmap` y corré un escaneo de puertos contra
  tu propia PC desde otra máquina en tu red local — vas a ver cómo `network_guard.py`
  lo detecta como patrón de escaneo.

---

## 5. Testear los módulos nuevos (ransomware, cookies, malware)

### Ransomware — probalo sin miedo, es completamente seguro

```bash
python ransomware_guard.py
```

Esto crea archivos señuelo reales en tus carpetas de Documentos/Escritorio/Imágenes
(en una subcarpeta oculta `.corelock_canary`). Para probar que la detección
funciona, simplemente **abrí uno de esos archivos y guardalo con un cambio**, o
renombralo agregándole `.locked` al final. Deberías ver la alerta `CRITICO`
aparecer al instante.

### Cookies — requiere tener un navegador instalado y correr como Admin

```bash
python cookie_guard.py
```

Para testear que detecta accesos indebidos, corré esto en otra terminal
mientras tenés Chrome/Edge abierto con sesión iniciada en algún sitio:

```bash
python -c "
import time
path = r'C:\Users\TU_USUARIO\AppData\Local\Google\Chrome\User Data\Default\Cookies'
with open(path, 'rb') as f:
    f.read()
    time.sleep(6)
"
```

(Reemplazá `TU_USUARIO` por tu usuario real de Windows). Esto simula exactamente
lo que hace un infostealer: un proceso Python (que no es el navegador) leyendo
el archivo de cookies. Deberías ver la alerta `CRITICO` en la otra terminal.

### Malware general — necesita una API key gratuita de VirusTotal

1. Registrate gratis en https://www.virustotal.com/gui/join-us
2. Copiá tu API key desde tu perfil
3. Configurala: `setx VT_API_KEY "tu_key_aqui"` (cerrá y reabrí la terminal)
4. Corré: `python malware_scanner.py`
5. Descargá cualquier archivo `.exe` a tu carpeta de Descargas — el script lo va
   a hashear automáticamente y consultar contra 70+ motores antivirus reales.

**Para probar el caso positivo de verdad** (sin descargar malware real, por
supuesto): el sitio oficial de EICAR (https://www.eicar.org/download-anti-malware-testfile/)
provee un archivo de prueba estándar de la industria, reconocido por TODOS los
antivirus como "malware de prueba" pero que no contiene código dañino real —
es el estándar universal para testear que un antivirus reacciona.

---

## 6. Ajustar sensibilidad (evitar falsos positivos en tu caso particular)

Si usás programas que legítimamente consumen mucha CPU seguido (renderizado, compilación,
juegos), y te generan alertas molestas:

En `miner_detector.py`:
```python
CPU_THRESHOLD = 70.0        # subilo a 85-90 si tenés falsos positivos
SUSTAINED_SECONDS = 90       # subilo si tus tareas legítimas duran más
```

En `network_guard.py`:
```python
TRUSTED_PROCESSES = {...}    # agregá ahí cualquier app tuya que dispare alertas por error
```

---

## 4. Próximos pasos sugeridos

1. Unificar ambos scripts en un solo servicio de Windows (arranca solo al prender la PC)
2. Conectar con VirusTotal API para verificar hashes de archivos desconocidos
3. Integrar el hook de VPN/WireGuard para apps marcadas como sensibles
