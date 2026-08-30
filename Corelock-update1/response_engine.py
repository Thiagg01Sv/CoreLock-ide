"""
CoreLock - Motor de Respuesta Automática (el "sistema inmune")
=====================================================================
Hasta ahora, los demás módulos de CoreLock DETECTAN y ALERTAN. Este
módulo es el que ACTÚA: convierte una alerta crítica en una acción
real, automática, sin esperar a que el usuario haga nada.

Dos acciones:
  1. kill_process(pid)      -> termina el proceso malicioso
  2. quarantine_file(path)  -> aísla el archivo (lo mueve, renombra,
                                y le quita permisos de ejecución)

"Cuarentena" y no "borrado directo" a propósito: si algo resulta ser
un falso positivo, se puede recuperar con restore_from_quarantine().
Un antivirus que borra sin posibilidad de deshacer es un antivirus
que en algún momento te va a hacer perder algo que no era malware.

Requiere: pip install psutil
Debe correr como Administrador para matar procesos de otros usuarios
y modificar permisos de archivos protegidos.
"""

import os
import shutil
import subprocess
import json
import platform
import hashlib
from datetime import datetime

import psutil
import plain_language

IS_WINDOWS = platform.system() == "Windows"
QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), ".corelock_quarantine")
QUARANTINE_LOG = "corelock_quarantine.log"

# Red de seguridad CENTRAL, aplicada sin importar qué módulo llame a
# kill_process(). Estos procesos son core del sistema operativo Windows:
# matarlos puede colgar la sesión completa, tumbar el escritorio, o dejar
# el sistema inestable. Ningún módulo de detección debería poder saltarse
# esto, ni siquiera por un bug de heurística que todavía no conocemos.
NEVER_AUTO_KILL = {
    "explorer.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "lsass.exe", "services.exe", "smss.exe", "system", "registry",
    "system idle process", "dwm.exe", "sihost.exe",
}


def _log(action: str, details: dict):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {"timestamp": ts, "action": action, "details": details}
    print(f"\033[92m[{ts}] [RESPUESTA AUTOMÁTICA] {action}\033[0m")
    for k, v in details.items():
        print(f"    {k}: {v}")
    with open(QUARANTINE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    razon = details.get("Razón", "") or details.get("Razón solicitada", "")
    if razon:
        plain_language.print_explanation(razon, action)


def ensure_quarantine_dir():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)


def hash_prefix(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()[:16]
    except Exception:
        return "unknown"


def quarantine_file(path: str, reason: str = "") -> bool:
    """Mueve un archivo a cuarentena, renombrado y sin permisos de ejecución.
    Devuelve True si se pudo aislar correctamente.

    Igual que kill_process, rechaza tocar archivos cuyo nombre coincide
    con un proceso core protegido -- no importa desde qué módulo se llame."""
    if not path or not os.path.exists(path):
        return False

    basename_lower = os.path.basename(path).lower()
    if basename_lower in NEVER_AUTO_KILL:
        _log(
            "BLOQUEADO POR RED DE SEGURIDAD",
            {
                "Archivo": path,
                "Razón solicitada": reason,
                "Motivo del bloqueo": f"'{basename_lower}' es un archivo core de Windows protegido",
            },
        )
        return False

    ensure_quarantine_dir()
    file_hash = hash_prefix(path)
    basename = os.path.basename(path)
    dest = os.path.join(QUARANTINE_DIR, f"{file_hash}_{basename}.quarantined")

    try:
        shutil.move(path, dest)
        if IS_WINDOWS:
            username = os.environ.get("USERNAME", "")
            subprocess.run(
                ["icacls", dest, "/inheritance:r", "/grant:r", f"{username}:R"],
                capture_output=True, timeout=10,
            )
        else:
            os.chmod(dest, 0o400)
        _log("ARCHIVO EN CUARENTENA", {"Original": path, "Cuarentena": dest, "Razón": reason})
        return True
    except Exception as e:
        _log("ERROR AL PONER EN CUARENTENA", {"Archivo": path, "Error": str(e)})
        return False


def kill_process(pid: int, reason: str = "") -> bool:
    """Termina un proceso por PID. Best-effort: procesos con protección
    elevada (algunos rootkits) pueden resistir esto -- por eso las demás
    capas (firewall, cuarentena de archivo) importan igual.

    SIEMPRE rechaza matar procesos en NEVER_AUTO_KILL, sin importar quién
    llame a esta función ni qué tan convencido esté el detector de que
    es una amenaza. Es la última línea de defensa contra falsos positivos
    catastróficos (ej: matar explorer.exe en loop infinito)."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        return True  # ya no existía, el objetivo ya está cumplido
    except Exception as e:
        _log("ERROR AL TERMINAR PROCESO", {"PID": pid, "Error": str(e)})
        return False

    if name.lower() in NEVER_AUTO_KILL:
        _log(
            "BLOQUEADO POR RED DE SEGURIDAD",
            {
                "PID": pid,
                "Nombre": name,
                "Razón solicitada": reason,
                "Motivo del bloqueo": f"'{name}' es un proceso core de Windows protegido contra auto-terminación",
            },
        )
        return False

    try:
        proc.kill()
        proc.wait(timeout=5)
        _log("PROCESO TERMINADO", {"PID": pid, "Nombre": name, "Razón": reason})
        return True
    except psutil.NoSuchProcess:
        return True
    except Exception as e:
        _log("ERROR AL TERMINAR PROCESO", {"PID": pid, "Error": str(e)})
        return False


def neutralize(pid: int = None, file_path: str = None, reason: str = ""):
    """Punto de entrada único usado por todos los detectores: 'cómete la amenaza'.
    Mata el proceso (si se conoce el PID) y pone en cuarentena el archivo
    (si se conoce la ruta). Cualquiera de los dos parámetros es opcional."""
    if pid:
        kill_process(pid, reason)
    if file_path:
        quarantine_file(file_path, reason)


def restore_from_quarantine(quarantined_filename: str, restore_to: str) -> bool:
    """Por si algo se marcó como falso positivo y hay que recuperarlo."""
    src = os.path.join(QUARANTINE_DIR, quarantined_filename)
    if not os.path.exists(src):
        return False
    try:
        shutil.move(src, restore_to)
        _log("ARCHIVO RESTAURADO", {"Desde": src, "Hacia": restore_to})
        return True
    except Exception as e:
        _log("ERROR AL RESTAURAR", {"Archivo": quarantined_filename, "Error": str(e)})
        return False


def list_quarantine() -> list:
    ensure_quarantine_dir()
    return os.listdir(QUARANTINE_DIR)
