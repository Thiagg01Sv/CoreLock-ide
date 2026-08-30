"""
CoreLock - Cookie Guard (Detección de robo de cookies / infostealers)
=========================================================================
IMPORTANTE: Chrome, Edge y Brave YA cifran las cookies en disco usando
DPAPI de Windows, atado a tu cuenta de usuario -- nadie puede copiar
ese archivo a otra PC y leerlo. Este módulo no reemplaza eso, lo
complementa detectando el patrón real que usan los infostealers
(RedLine, Vidar, LummaC2, etc.): un proceso que NO es el navegador
abriendo directamente los archivos de cookies/credenciales para
copiarlos y exfiltrarlos mientras la sesión sigue activa.

Requiere: pip install psutil
Debe correr como Administrador para ver archivos abiertos por otros procesos.
"""

import os
import time
import json
import platform
from datetime import datetime

import psutil

import response_engine
import plain_language

# Si está en True, cualquier proceso NO-navegador que toque archivos de
# cookies/credenciales se termina automáticamente. Es agresivo a propósito:
# no hay ninguna razón legítima para que esto pase.
AUTO_RESPOND = True

IS_WINDOWS = platform.system() == "Windows"
LOG_FILE = "corelock_cookie_alerts.log"
POLL_INTERVAL = 5

LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
APPDATA = os.environ.get("APPDATA", "")

BROWSER_SENSITIVE_FILES = {
    "Chrome": [
        rf"{LOCALAPPDATA}\Google\Chrome\User Data\Default\Cookies",
        rf"{LOCALAPPDATA}\Google\Chrome\User Data\Default\Login Data",
        rf"{LOCALAPPDATA}\Google\Chrome\User Data\Local State",
    ],
    "Edge": [
        rf"{LOCALAPPDATA}\Microsoft\Edge\User Data\Default\Cookies",
        rf"{LOCALAPPDATA}\Microsoft\Edge\User Data\Default\Login Data",
    ],
    "Brave": [
        rf"{LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
    ],
}

# Steam guarda datos de sesión en archivos con nombre fijo dentro de config/
STEAM_SENSITIVE_FILES = [
    r"C:\Program Files (x86)\Steam\config\loginusers.vdf",
    r"C:\Program Files (x86)\Steam\config\config.vdf",
]

# Discord guarda el token de sesión dentro de LevelDB en "Local Storage".
# No es un archivo único con nombre fijo (son .ldb/.log rotados por Chromium,
# que es la base de Discord), así que acá se protege el DIRECTORIO completo,
# no un archivo puntual -- cualquier proceso ajeno a Discord tocando algo
# ahí adentro es la señal que buscamos.
DISCORD_TOKEN_DIR_CANDIDATES = [
    rf"{APPDATA}\discord\Local Storage\leveldb",
    rf"{APPDATA}\discordptb\Local Storage\leveldb",
    rf"{APPDATA}\discordcanary\Local Storage\leveldb",
]

# Procesos que SÍ tienen permitido tocar estos archivos
LEGIT_BROWSER_PROCESSES = {
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe",
    "chrome_proxy.exe", "googlecrashhandler.exe", "googlecrashhandler64.exe",
    "discord.exe", "discordptb.exe", "discordcanary.exe",
    "steam.exe", "steamwebhelper.exe", "steamservice.exe",
}

already_alerted = set()


def log_alert(severity: str, message: str, details: dict):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {"timestamp": ts, "severity": severity, "message": message, "details": details}
    color = {"INFO": "\033[94m", "SOSPECHOSO": "\033[93m", "CRITICO": "\033[91m"}.get(severity, "")
    reset = "\033[0m"
    print(f"{color}[{ts}] [{severity}] {message}{reset}")
    for k, v in details.items():
        print(f"    {k}: {v}")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    if severity in ("CRITICO", "SOSPECHOSO") and "Razones" in details:
        plain_language.print_explanation(details.get("Razones", ""), message)


def find_firefox_cookie_paths() -> list:
    """Firefox usa un perfil con nombre aleatorio, hay que buscarlo."""
    paths = []
    profiles_dir = os.path.join(APPDATA, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(profiles_dir):
        for profile in os.listdir(profiles_dir):
            cookie_path = os.path.join(profiles_dir, profile, "cookies.sqlite")
            if os.path.exists(cookie_path):
                paths.append(cookie_path.lower())
    return paths


def get_all_sensitive_paths() -> set:
    """Archivos puntuales (ruta exacta) a proteger: cookies de navegadores
    y los archivos de sesión de Steam."""
    paths = set()
    for files in BROWSER_SENSITIVE_FILES.values():
        for p in files:
            if p:
                paths.add(p.lower())
    for p in STEAM_SENSITIVE_FILES:
        paths.add(p.lower())
    paths.update(find_firefox_cookie_paths())
    return paths


def get_all_sensitive_prefixes() -> set:
    """Directorios completos a proteger (no un archivo puntual): el
    almacén de tokens de Discord, que rota de nombre de archivo."""
    return {p.lower() for p in DISCORD_TOKEN_DIR_CANDIDATES if p}


def is_legit_process(name: str) -> bool:
    return name.lower() in LEGIT_BROWSER_PROCESSES


def find_suspicious_file_access(proc, sensitive_paths: set, sensitive_prefixes: set = None) -> list:
    """Dado un proceso ya obtenido, devuelve la lista de archivos sensibles
    que tiene abiertos -- ya sea un archivo puntual (cookies, Steam) o
    cualquier archivo dentro de un directorio protegido (tokens de Discord)."""
    sensitive_prefixes = sensitive_prefixes or set()
    matches = []
    try:
        for f in proc.open_files():
            path_lower = f.path.lower()
            if path_lower in sensitive_paths:
                matches.append(f.path)
            elif any(path_lower.startswith(prefix) for prefix in sensitive_prefixes):
                matches.append(f.path)
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        pass
    return matches


def check_all_processes(sensitive_paths: set, sensitive_prefixes: set = None):
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"] or ""
            if is_legit_process(name):
                continue

            matches = find_suspicious_file_access(proc, sensitive_paths, sensitive_prefixes)
            for path in matches:
                alert_key = f"{proc.pid}:{path}"
                if alert_key in already_alerted:
                    continue
                try:
                    exe_path = proc.exe()
                except Exception:
                    exe_path = "N/A"
                log_alert(
                    "CRITICO",
                    "¡Posible robo de cookies! Proceso NO-navegador accediendo a datos sensibles",
                    {
                        "Proceso": name,
                        "PID": proc.pid,
                        "Ruta del proceso": exe_path,
                        "Archivo accedido": path,
                        "Recomendación": "Verificar este proceso YA. Si es malware, cambiar contraseñas.",
                    },
                )
                already_alerted.add(alert_key)

                if AUTO_RESPOND:
                    response_engine.neutralize(
                        pid=proc.pid,
                        file_path=exe_path if exe_path != "N/A" else None,
                        reason=f"Acceso indebido a {path}",
                    )
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue


def main():
    print("=" * 60)
    print("  CORELOCK - Cookie Guard (Anti Robo de Cookies/Tokens)")
    print("=" * 60)
    print("Nota: Chrome/Edge ya cifran cookies con DPAPI atado a tu cuenta.")
    print("Este módulo detecta procesos NO-autorizados intentando leer sesiones")
    print("guardadas de navegadores, Discord y Steam.\n")

    if IS_WINDOWS:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠  Corré como Administrador para detectar accesos de otros procesos correctamente.\n")

    sensitive_paths = get_all_sensitive_paths()
    sensitive_prefixes = get_all_sensitive_prefixes()
    print(f"Monitoreando {len(sensitive_paths)} archivos y {len(sensitive_prefixes)} carpetas sensibles "
          f"(navegadores, Discord, Steam).")
    print(f"Log de alertas: {os.path.abspath(LOG_FILE)}")
    print("Presiona Ctrl+C para detener.\n")

    try:
        while True:
            check_all_processes(sensitive_paths, sensitive_prefixes)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")


if __name__ == "__main__":
    main()
