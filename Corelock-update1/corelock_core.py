"""
CoreLock Core - El sistema completo, unificado
==================================================
Corre los 5 módulos de detección al mismo tiempo, en paralelo, como
un solo sistema inmune:

  1. miner_detector.py    -> mineros de criptomonedas ocultos
  2. network_guard.py     -> tráfico de red malicioso / exfiltración
  3. ransomware_guard.py  -> cifrado masivo de archivos (canary files)
  4. cookie_guard.py      -> robo de cookies/credenciales (infostealers)
  5. malware_scanner.py   -> verificación de ejecutables contra VirusTotal

Cada uno detecta y, si AUTO_RESPOND está activo en ese módulo, actúa
automáticamente vía response_engine.py (mata el proceso + cuarentena
del archivo), con la red de seguridad central que nunca toca procesos
core de Windows.

Uso:
    python corelock_core.py

Recomendado correr como Administrador para que TODAS las capas
(bloqueo de firewall, lectura de archivos de otros procesos, etc.)
funcionen al 100%. Sin admin, sigue detectando pero con capacidades
reducidas en network_guard y cookie_guard.
"""

import sys
import time
import threading
import platform

import miner_detector
import network_guard
import ransomware_guard
import cookie_guard
import malware_scanner
import usb_guard

IS_WINDOWS = platform.system() == "Windows"

MODULES = [
    (miner_detector, "MinerDetector"),
    (network_guard, "NetworkGuard"),
    (ransomware_guard, "RansomwareGuard"),
    (cookie_guard, "CookieGuard"),
    (malware_scanner, "MalwareScanner"),
    (usb_guard, "UsbGuard"),
]


def _run_module(module, name):
    """Corre el main() de un módulo dentro de su propio thread.
    Si un módulo crashea, no se lleva a los demás con él."""
    try:
        module.main()
    except Exception as e:
        print(f"\033[91m[CORELOCK CORE] '{name}' se detuvo por un error: {e}\033[0m")


def check_admin() -> bool:
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def print_banner():
    print("=" * 66)
    print("   CORELOCK - Sistema de Seguridad Unificado")
    print("   Detección + Respuesta Automática en 6 capas")
    print("=" * 66)
    print()
    print("Capas activas:")
    print("  [1] Mineros de criptomonedas ocultos")
    print("  [2] Tráfico de red malicioso / exfiltración de datos")
    print("  [3] Ransomware (archivos señuelo + cifrado masivo)")
    print("  [4] Robo de cookies/credenciales/tokens (infostealers)")
    print("  [5] Malware general (verificación contra VirusTotal)")
    print("  [6] Amenazas en unidades USB al conectarse")
    print()

    if IS_WINDOWS and not check_admin():
        print("\033[93m⚠  NO estás corriendo como Administrador.\033[0m")
        print("   La detección funciona igual, pero el bloqueo de firewall y la")
        print("   lectura de archivos de otros procesos van a estar limitados.")
        print("   Para protección completa: cerrá esto y corré como Administrador.\n")
    else:
        print("\033[92m✓ Corriendo con privilegios completos.\033[0m\n")

    print("Todos los logs quedan en archivos separados por módulo:")
    print("  corelock_alerts.log, corelock_network_alerts.log,")
    print("  corelock_ransomware_alerts.log, corelock_cookie_alerts.log,")
    print("  corelock_malware_alerts.log, corelock_quarantine.log")
    print()
    print("Presioná Ctrl+C para detener TODO el sistema.")
    print("-" * 66)
    print()


def main():
    print_banner()

    threads = []
    for module, name in MODULES:
        t = threading.Thread(target=_run_module, args=(module, name), name=name, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)  # escalonar el arranque para que los banners no se pisen

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nDeteniendo CoreLock Core (todas las capas)...")
        sys.exit(0)


if __name__ == "__main__":
    main()
