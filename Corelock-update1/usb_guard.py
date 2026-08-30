"""
CoreLock - USB Guard
========================
Detecta cuando se conecta una unidad extraíble (USB) y la escanea por
las técnicas más comunes de propagación de malware por USB, ANTES de
que abras la unidad desde el Explorador de Windows:

  - autorun.inf en la raíz (ejecución automática -- Windows ya la
    ignora en unidades USB desde hace años, pero muchísimo malware
    lo sigue incluyendo porque a veces funciona en configuraciones
    viejas o mal parcheadas)
  - Ejecutables disfrazados de carpeta (nombre "Fotos.exe" con ícono
    de carpeta, para que hagas doble clic sin darte cuenta)
  - Accesos directos (.lnk) sospechosos en la raíz
  - Ejecutables marcados como ocultos + de sistema (técnica clásica
    para esconder el malware real mientras se ve una carpeta normal)

Requiere: pip install psutil
"""

import os
import time
import json
import platform
from datetime import datetime
from pathlib import Path

import psutil
import response_engine
import plain_language

IS_WINDOWS = platform.system() == "Windows"
LOG_FILE = "corelock_usb_alerts.log"
POLL_INTERVAL = 3

# Si está en True, un archivo confirmado como amenaza en el USB se pone
# en cuarentena automáticamente (se copia a cuarentena local; el USB
# tal cual no se modifica más allá de eso).
AUTO_RESPOND = True

# Nombres típicos de carpetas que el malware imita para engañar al ojo
COMMON_FOLDER_NAMES = {
    "fotos", "photos", "documentos", "documents", "videos", "musica",
    "music", "nueva carpeta", "new folder", "imagenes", "images",
}

SUSPICIOUS_EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".pif"}

known_drives = set()


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


def get_removable_drives() -> set:
    """Devuelve las letras de unidad actualmente conectadas que Windows
    identifica como removibles (USB), usando la API nativa de Windows
    para evitar falsos positivos con discos internos."""
    drives = set()
    if not IS_WINDOWS:
        return drives
    try:
        import ctypes
        DRIVE_REMOVABLE = 2
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter_index in range(26):
            if bitmask & (1 << letter_index):
                drive = f"{chr(65 + letter_index)}:\\"
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                if drive_type == DRIVE_REMOVABLE:
                    drives.add(drive)
    except Exception:
        pass
    return drives


def is_hidden_system_file(path: str) -> bool:
    """Detecta el combo oculto+sistema, típico de malware que se
    esconde del Explorador de Windows en su configuración por defecto."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
        if attrs == -1:
            return False
        return bool(attrs & FILE_ATTRIBUTE_HIDDEN) and bool(attrs & FILE_ATTRIBUTE_SYSTEM)
    except Exception:
        return False


def scan_drive(drive_path: str) -> list:
    """Escanea la raíz de una unidad y devuelve una lista de
    (severidad, mensaje, ruta_completa) por cada hallazgo."""
    findings = []
    try:
        entries = os.listdir(drive_path)
    except Exception:
        return findings

    for entry in entries:
        full_path = os.path.join(drive_path, entry)
        lower_name = entry.lower()
        ext = Path(entry).suffix.lower()
        base_no_ext = Path(entry).stem.lower()

        if lower_name == "autorun.inf":
            findings.append(("CRITICO", "autorun.inf encontrado en la raíz del USB", full_path))
            continue

        if ext in SUSPICIOUS_EXECUTABLE_EXTENSIONS and base_no_ext in COMMON_FOLDER_NAMES:
            findings.append(
                ("CRITICO", f"Ejecutable disfrazado de carpeta: '{entry}'", full_path)
            )
            continue

        if ext == ".lnk":
            findings.append(
                ("SOSPECHOSO", f"Acceso directo (.lnk) sospechoso en la raíz del USB: '{entry}'", full_path)
            )
            continue

        if ext in SUSPICIOUS_EXECUTABLE_EXTENSIONS and is_hidden_system_file(full_path):
            findings.append(
                ("CRITICO", f"Ejecutable oculto+sistema (técnica de camuflaje): '{entry}'", full_path)
            )

    return findings


def handle_new_drive(drive_path: str):
    log_alert(
        "INFO",
        f"Nueva unidad extraíble detectada: {drive_path}. Escaneando antes de permitir acceso normal...",
        {},
    )
    findings = scan_drive(drive_path)

    if not findings:
        log_alert("INFO", f"USB {drive_path} escaneado: no se encontraron amenazas conocidas.", {})
        return

    for severity, msg, path in findings:
        details = {"Unidad": drive_path, "Archivo": path, "Razones": msg}
        log_alert(severity, msg, details)
        if AUTO_RESPOND and severity == "CRITICO":
            response_engine.quarantine_file(path, reason=msg)


def main():
    print("=" * 60)
    print("  CORELOCK - USB Guard")
    print("=" * 60)

    if not IS_WINDOWS:
        print("Este módulo depende de APIs específicas de Windows para detectar")
        print("unidades removibles. En este sistema no hay nada para monitorear.")
        return

    global known_drives
    known_drives = get_removable_drives()
    print(f"Unidades USB detectadas al iniciar: {', '.join(known_drives) or 'ninguna'}")
    print(f"Log de alertas: {os.path.abspath(LOG_FILE)}")
    print("Presiona Ctrl+C para detener.\n")

    try:
        while True:
            current = get_removable_drives()
            new_drives = current - known_drives
            for drive in new_drives:
                handle_new_drive(drive)
            known_drives = current
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")


if __name__ == "__main__":
    main()
