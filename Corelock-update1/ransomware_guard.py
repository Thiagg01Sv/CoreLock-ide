"""
CoreLock - Detector de Ransomware (Canary Files)
====================================================
Técnica real usada por EDR profesionales: coloca archivos "señuelo"
(canary files) en carpetas típicas del usuario. NINGÚN proceso legítimo
debería tocar jamás estos archivos -- si algo los modifica, renombra o
borra, es una señal casi inequívoca de ransomware cifrando el disco
en tiempo real.

También detecta el patrón clásico de ransomware: muchísimos archivos
modificados en muy poco tiempo, y extensiones nuevas típicas de cifrado
(.locked, .encrypted, .crypt, etc.)

Requiere: pip install watchdog psutil
"""

import os
import time
import json
import hashlib
import platform
from datetime import datetime
from collections import deque
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import psutil
import response_engine
import plain_language

IS_WINDOWS = platform.system() == "Windows"
LOG_FILE = "corelock_ransomware_alerts.log"

# Si está en True, al detectar ransomware se intenta identificar y matar
# el proceso responsable (best-effort: se identifica por mayor actividad
# de escritura a disco en el momento de la alerta). No es 100% preciso
# sin un driver de kernel -- pero en la gran mayoría de los casos reales
# el proceso cifrador es fácilmente el que más está escribiendo.
AUTO_RESPOND = True

if IS_WINDOWS:
    WATCH_FOLDERS = [
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Pictures"),
    ]
else:
    WATCH_FOLDERS = [os.path.expanduser("~/Documents"), os.path.expanduser("~/Desktop")]

CANARY_DIRNAME = ".corelock_canary"
CANARY_COUNT_PER_FOLDER = 5

# Extensiones que casi siempre delatan ransomware conocido
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypto", ".locky", ".cerber",
    ".zepto", ".odin", ".thor", ".aesir", ".zzzzz", ".micro", ".ttt",
    ".xxx", ".vault", ".wallet", ".r5a", ".enc", ".ransom",
}

# Si se modifican más de N archivos "reales" en menos de M segundos,
# es un patrón fuerte de cifrado masivo en curso
MASS_MODIFY_THRESHOLD = 20
MASS_MODIFY_WINDOW = 10  # segundos


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


def create_canary_files() -> list:
    """Crea archivos señuelo con contenido real (no vacío) en carpetas clave."""
    canary_paths = []
    for folder in WATCH_FOLDERS:
        if not os.path.isdir(folder):
            continue
        canary_dir = os.path.join(folder, CANARY_DIRNAME)
        os.makedirs(canary_dir, exist_ok=True)
        for i in range(CANARY_COUNT_PER_FOLDER):
            for ext in (".docx", ".xlsx", ".jpg", ".pdf", ".txt"):
                path = os.path.join(canary_dir, f"canary_{i}{ext}")
                if not os.path.exists(path):
                    with open(path, "wb") as f:
                        f.write(os.urandom(1024))
                canary_paths.append(path)
    return canary_paths


def is_canary_extension(path: str) -> bool:
    return CANARY_DIRNAME in path


# Procesos del sistema que nunca deberían matarse aunque tengan I/O alto
PROTECTED_PROCESSES = {
    "system", "system idle process", "svchost.exe", "explorer.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "python.exe", "python3.exe",
}


def find_likely_culprit_process():
    """Best-effort: identifica el proceso con más bytes escritos a disco
    en una ventana corta. No es perfecto (requeriría un driver de kernel
    para atribución exacta), pero en la práctica el proceso que está
    cifrando archivos masivamente se destaca claramente en I/O de escritura."""
    snapshot_before = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            io = proc.io_counters()
            snapshot_before[proc.pid] = (proc.info["name"], io.write_bytes)
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            continue

    time.sleep(1.5)  # ventana corta para medir la tasa de escritura

    best_pid, best_name, best_delta = None, None, 0
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            io = proc.io_counters()
            name = proc.info["name"] or ""
            if name.lower() in PROTECTED_PROCESSES:
                continue
            prev = snapshot_before.get(proc.pid)
            if prev:
                delta = io.write_bytes - prev[1]
                if delta > best_delta:
                    best_pid, best_name, best_delta = proc.pid, name, delta
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            continue

    return best_pid, best_name, best_delta


def _respond_to_ransomware(trigger_path: str):
    """Se llama apenas se confirma actividad de ransomware. Busca el
    proceso más probable e intenta neutralizarlo de inmediato."""
    log_alert("INFO", "Buscando proceso responsable (ventana de ~1.5s)...", {})
    pid, name, delta = find_likely_culprit_process()
    if pid and delta > 0:
        log_alert(
            "ACCION",
            f"Candidato identificado: '{name}' (PID {pid}) con mayor actividad de escritura",
            {"Bytes escritos en ventana": delta},
        )
        response_engine.kill_process(pid, reason=f"Sospecha de ransomware, disparado por {trigger_path}")
    else:
        log_alert(
            "INFO",
            "No se pudo identificar un proceso responsable claro. "
            "Revisá el Administrador de Tareas manualmente.",
            {},
        )


class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, canary_paths):
        self.canary_paths = set(canary_paths)
        self.recent_modifications = deque()

    def _register_modification(self, path: str):
        now = time.time()
        self.recent_modifications.append((path, now))
        while self.recent_modifications and now - self.recent_modifications[0][1] > MASS_MODIFY_WINDOW:
            self.recent_modifications.popleft()

        if len(self.recent_modifications) >= MASS_MODIFY_THRESHOLD:
            log_alert(
                "CRITICO",
                "Posible cifrado masivo de archivos en curso (patrón ransomware)",
                {
                    "Archivos modificados": len(self.recent_modifications),
                    "Ventana": f"{MASS_MODIFY_WINDOW}s",
                    "Último archivo": path,
                    "Recomendación": "Desconectar de internet/red YA y revisar Administrador de Tareas",
                },
            )
            self.recent_modifications.clear()

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path

        if path in self.canary_paths or is_canary_extension(path):
            log_alert(
                "CRITICO",
                "¡ARCHIVO SEÑUELO MODIFICADO! Fuerte indicio de ransomware activo",
                {"Archivo": path, "Acción": "MODIFICACIÓN"},
            )
            if AUTO_RESPOND:
                _respond_to_ransomware(path)
            return

        ext = Path(path).suffix.lower()
        if ext in RANSOMWARE_EXTENSIONS:
            log_alert("CRITICO", f"Archivo con extensión típica de ransomware: {ext}", {"Archivo": path})

        self._register_modification(path)

    def on_moved(self, event):
        # Ransomware suele renombrar: documento.docx -> documento.docx.locked
        if event.is_directory:
            return
        if event.src_path in self.canary_paths or is_canary_extension(event.src_path):
            log_alert(
                "CRITICO",
                "¡ARCHIVO SEÑUELO RENOMBRADO! Fuerte indicio de ransomware activo",
                {"Original": event.src_path, "Nuevo nombre": event.dest_path},
            )
            return
        ext = Path(event.dest_path).suffix.lower()
        if ext in RANSOMWARE_EXTENSIONS:
            log_alert(
                "CRITICO",
                f"Archivo renombrado con extensión de ransomware: {ext}",
                {"Original": event.src_path, "Nuevo nombre": event.dest_path},
            )

    def on_deleted(self, event):
        if event.is_directory:
            return
        if event.src_path in self.canary_paths or is_canary_extension(event.src_path):
            log_alert(
                "CRITICO",
                "¡ARCHIVO SEÑUELO BORRADO! Fuerte indicio de ransomware activo",
                {"Archivo": event.src_path},
            )


def main():
    print("=" * 60)
    print("  CORELOCK - Detector de Ransomware (Canary Files)")
    print("=" * 60)
    canary_paths = create_canary_files()
    if not canary_paths:
        print("No se pudieron crear archivos señuelo. Revisá que las carpetas existan.")
        return
    print(f"{len(canary_paths)} archivos señuelo creados en: {', '.join(WATCH_FOLDERS)}")
    print(f"Log de alertas: {os.path.abspath(LOG_FILE)}")
    print("Presiona Ctrl+C para detener.\n")

    handler = RansomwareHandler(canary_paths)
    observer = Observer()
    for folder in WATCH_FOLDERS:
        if os.path.isdir(folder):
            observer.schedule(handler, folder, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
