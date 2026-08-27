import psutil
import time
import hashlib
import json
import os
import ntpath
import sys
from datetime import datetime
from collections import defaultdict, deque

# ─────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────

# Umbral de CPU sostenido (%) que dispara sospecha
CPU_THRESHOLD = 70.0

# Cuántos segundos de CPU alta sostenida antes de alertar
SUSTAINED_SECONDS = 90

# Intervalo de muestreo (segundos)
POLL_INTERVAL = 5

# Puertos típicos del protocolo Stratum (usado por pools de minería)
SUSPICIOUS_PORTS = {3333, 3334, 4444, 5555, 7777, 8080, 9999, 14444, 45700}

# Nombres de procesos de mineros conocidos (case-insensitive)
KNOWN_MINER_NAMES = {
    "xmrig", "xmr-stak", "cpuminer", "t-rex", "nbminer", "phoenixminer",
    "ethminer", "claymore", "cgminer", "bfgminer", "ccminer", "lolminer",
    "gminer", "teamredminer", "srbminer", "wildrig",
}

# Dominios de pools de minería conocidos (fragmento de dominio, no exacto)
KNOWN_POOL_DOMAINS = {
    "nanopool.org", "ethermine.org", "f2pool.com", "poolin.com",
    "minexmr.com", "supportxmr.com", "moneroocean.stream", "2miners.com",
    "hashvault.pro", "viabtc.com", "antpool.com",
}

# Rutas legítimas donde procesos del sistema deberían vivir
LEGIT_SYSTEM_PATHS = {
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
}

# Nombres de procesos de sistema que a veces se falsifican
COMMONLY_SPOOFED = {"svchost.exe", "csrss.exe", "lsass.exe", "explorer.exe", "conhost.exe"}

LOG_FILE = "sentinel_alerts.log"

# ─────────────────────────────────────────────────────────────
# ESTADO INTERNO
# ─────────────────────────────────────────────────────────────

# Historial de CPU por proceso: {pid: deque([cpu_pct, ...])}
cpu_history = defaultdict(lambda: deque(maxlen=SUSTAINED_SECONDS // POLL_INTERVAL))

# PIDs ya alertados (para no repetir spam de alertas)
already_alerted = set()


def log_alert(severity: str, message: str, details: dict):
    """Registra una alerta en consola y en archivo de log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "severity": severity,
        "message": message,
        "details": details,
    }

    color_map = {"INFO": "\033[94m", "SOSPECHOSO": "\033[93m", "CRITICO": "\033[91m"}
    reset = "\033[0m"
    color = color_map.get(severity, "")

    print(f"{color}[{timestamp}] [{severity}] {message}{reset}")
    if details:
        for k, v in details.items():
            print(f"    {k}: {v}")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def get_file_hash(path: str) -> str:
    """Calcula SHA256 de un ejecutable (para comparar contra listas negras)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return ""


def is_spoofed_system_process(proc: psutil.Process) -> bool:
    """Detecta si un proceso finge ser un proceso legítimo de Windows
    pero corre desde una ruta que no es la del sistema."""
    try:
        name = proc.name().lower()
        if name not in COMMONLY_SPOOFED:
            return False
        exe_path = proc.exe().lower()
        exe_dir = ntpath.dirname(exe_path)
        return not any(exe_dir.startswith(legit) for legit in LEGIT_SYSTEM_PATHS)
    except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
        return False


def has_suspicious_network_activity(proc: psutil.Process) -> list:
    """Revisa si el proceso tiene conexiones hacia puertos o dominios
    típicos de pools de minería."""
    findings = []
    try:
        for conn in proc.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
                findings.append(f"Conexión a puerto sospechoso {conn.raddr.port} ({conn.raddr.ip})")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return findings


def check_known_miner_name(proc: psutil.Process) -> bool:
    try:
        name = proc.name().lower().replace(".exe", "")
        return any(miner in name for miner in KNOWN_MINER_NAMES)
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False


def evaluate_process(proc: psutil.Process):
    """Evalúa un único proceso contra todas las heurísticas."""
    pid = proc.pid

    try:
        cpu = proc.cpu_percent(interval=None)
        name = proc.name()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return

    cpu_history[pid].append(cpu)

    reasons = []
    severity = "INFO"

    # 1. Nombre de minero conocido -> crítico inmediato
    if check_known_miner_name(proc):
        reasons.append(f"Nombre de proceso coincide con minero conocido: {name}")
        severity = "CRITICO"

    # 2. Proceso de sistema falsificado (corriendo desde ruta rara)
    if is_spoofed_system_process(proc):
        try:
            exe_path = proc.exe()
        except Exception:
            exe_path = "desconocida"
        reasons.append(f"Proceso '{name}' se hace pasar por proceso de sistema pero corre desde: {exe_path}")
        severity = "CRITICO"

    # 3. CPU sostenida alta
    history = cpu_history[pid]
    if len(history) == history.maxlen and all(c >= CPU_THRESHOLD for c in history):
        reasons.append(
            f"CPU sostenida al {sum(history)/len(history):.1f}% durante {SUSTAINED_SECONDS}s sin interrupción"
        )
        if severity == "INFO":
            severity = "SOSPECHOSO"

    # 4. Conexiones de red sospechosas
    net_findings = has_suspicious_network_activity(proc)
    if net_findings:
        reasons.extend(net_findings)
        severity = "CRITICO"

    if reasons and pid not in already_alerted:
        try:
            exe_path = proc.exe()
        except Exception:
            exe_path = "N/A"

        details = {
            "PID": pid,
            "Nombre": name,
            "Ruta": exe_path,
            "CPU actual": f"{cpu:.1f}%",
            "Razones": " | ".join(reasons),
        }
        log_alert(severity, f"Actividad sospechosa detectada en proceso '{name}' (PID {pid})", details)
        already_alerted.add(pid)


def cleanup_dead_pids(current_pids: set):
    """Limpia el historial de procesos que ya no existen."""
    dead = [pid for pid in cpu_history if pid not in current_pids]
    for pid in dead:
        del cpu_history[pid]
    already_alerted.intersection_update(current_pids)


def main():
    print("=" * 60)
    print("  SENTINEL - Detector de Cryptominers en Background")
    print("=" * 60)
    print(f"Umbral CPU: {CPU_THRESHOLD}% sostenido por {SUSTAINED_SECONDS}s")
    print(f"Intervalo de muestreo: {POLL_INTERVAL}s")
    print(f"Log de alertas: {os.path.abspath(LOG_FILE)}")
    print("Presiona Ctrl+C para detener.\n")

    try:
        while True:
            current_pids = set()
            for proc in psutil.process_iter(["pid", "name"]):
                current_pids.add(proc.pid)
                evaluate_process(proc)

            cleanup_dead_pids(current_pids)
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")
        sys.exit(0)


if __name__ == "__main__":
    main()
