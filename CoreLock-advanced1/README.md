# Sentinel — Sistema de Seguridad para Windows

## Contenido del paquete

| Archivo | Qué hace |
|---|---|
| `miner_detector.py` | Detecta mineros de criptomonedas ocultos (CPU sostenida, nombres conocidos, procesos disfrazados, conexiones a pools) |
| `network_guard.py` | Detecta y bloquea actividad de red riesgosa (puertos peligrosos, patrones de escaneo/exfiltración) |
| `test_miner_detector.py` | Tests automáticos del detector de mineros (no requieren admin ni esperar tiempo real) |
| `test_network_guard.py` | Tests automáticos del guardián de red |
| `simulate_test_activity.py` | Generador de actividad de PRUEBA controlada para validar en vivo |
| `requirements.txt` | Dependencias de Python |

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
netsh advfirewall firewall show rule name=all | findstr Sentinel
```

Esto te lista todas las reglas que Sentinel creó — si aparecen, el bloqueo es real,
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

## 3. Ajustar sensibilidad (evitar falsos positivos en tu caso particular)

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
