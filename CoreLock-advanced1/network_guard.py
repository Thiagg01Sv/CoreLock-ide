import psutil
import subprocess
import time
import json
import os
import sys
import platform
from datetime import datetime
from collections import defaultdict




POLL_INTERVAL = 5

RISKY_PORTS = {
    3389,   # RDP
    23,     # Telnet (sin cifrar)
    21,     # FTP (sin cifrar)
    3333, 4444, 5555, 7777,  # Stratum / mineros / backdoors comunes
    6667,   # IRC (usado por botnets)
    1080,   # SOCKS proxy (a veces abusado)
}

# Cuántas IPs distintas puede contactar un mismo proceso en la ventana
# de tiempo antes de considerarse "escaneo" o comportamiento anómalo
MAX_UNIQUE_IPS_PER_WINDOW = 15
WINDOW_SECONDS = 60

# Procesos que confiamos por defecto (no se evalúan)
TRUSTED_PROCESSES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "explorer.exe",
    "svchost.exe", "system", "steam.exe", "discord.exe",
    "outlook.exe", "teams.exe", "zoom.exe",
}

# Apps que el usuario marca como "sensibles": si tienen actividad de red
# riesgosa, en vez de solo bloquear, se sugiere forzarlas por VPN
SENSITIVE_APPS = set()  # ej: {"billetera_cripto.exe", "banco.exe"}

LOG_FILE = "sentinel_network_alerts.log"
IS_WINDOWS = platform.system() == "Windows"

# ─────────────────────────────────────────────────────────────
# ESTADO INTERNO
# ─────────────────────────────────────────────────────────────

# {pid: {(ip, timestamp), ...}} — para detectar escaneo/comportamiento anómalo
connection_windows = defaultdict(list)
blocked_rules = set()  # evita duplicar reglas de firewall
already_alerted = set()


def log_alert(severity: str, message: str, details: dict):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {"timestamp": timestamp, "severity": severity, "message": message, "details": details}

    color_map = {"INFO": "\033[94m", "SOSPECHOSO": "\033[93m", "CRITICO": "\033[91m", "ACCION": "\033[92m"}
    reset = "\033[0m"
    color = color_map.get(severity, "")

    print(f"{color}[{timestamp}] [{severity}] {message}{reset}")
    for k, v in details.items():
        print(f"    {k}: {v}")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")




def block_ip_windows(ip: str, rule_name: str) -> bool:
    """Crea una regla de bloqueo saliente en Windows Firewall para una IP.
    Requiere permisos de Administrador."""
    if not IS_WINDOWS:
        log_alert("ACCION", f"[SIMULADO - no es Windows] Se bloquearía la IP {ip}", {})
        return True

    if rule_name in blocked_rules:
        return True

    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            blocked_rules.add(rule_name)
            return True
        else:
            log_alert("INFO", f"No se pudo crear regla de firewall (¿corriendo como Admin?)",
                       {"stderr": result.stderr.strip()})
            return False
    except Exception as e:
        log_alert("INFO", f"Error al intentar bloquear IP {ip}: {e}", {})
        return False


def block_process_by_path_windows(exe_path: str, rule_name: str) -> bool:
    """Bloquea TODA la salida a internet de un ejecutable específico,
    sin importar a qué IP se conecte."""
    if not IS_WINDOWS:
        log_alert("ACCION", f"[SIMULADO - no es Windows] Se bloquearía el programa {exe_path}", {})
        return True

    if rule_name in blocked_rules:
        return True

    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"program={exe_path}",
            "enable=yes",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            blocked_rules.add(rule_name)
            return True
        return False
    except Exception as e:
        log_alert("INFO", f"Error al bloquear programa {exe_path}: {e}", {})
        return False


def route_through_vpn_hook(proc_name: str, exe_path: str):

    log_alert(
        "ACCION",
        f"App sensible '{proc_name}' con actividad de red riesgosa detectada",
        {
            "Recomendación": "Activar túnel VPN antes de permitir esta conexión",
            "Ruta": exe_path,
            "Nota": "Configurá WireGuard con un túnel 'sentinel-tunnel' para automatizar esto",
        },
    )
    # Ejemplo de cómo se activaría un túnel WireGuard ya configurado:
    # subprocess.run(["wireguard", "/installtunnelservice", "sentinel-tunnel.conf"])


def evaluate_connections():
    now = time.time()

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        log_alert("INFO", "Sin permisos para leer conexiones de red. Correr como Administrador.", {})
        return

    by_pid = defaultdict(list)
    for conn in connections:
        if conn.pid and conn.raddr:
            by_pid[conn.pid].append(conn)

    for pid, conns in by_pid.items():
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe_path = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if name.lower() in TRUSTED_PROCESSES:
            continue

        reasons = []
        severity = "INFO"
        risky_ips = []

        for conn in conns:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            # Registrar en ventana temporal para detectar escaneo
            connection_windows[pid].append((remote_ip, now))

            if remote_port in RISKY_PORTS:
                reasons.append(f"Conexión a puerto riesgoso {remote_port} en {remote_ip}")
                severity = "CRITICO"
                risky_ips.append(remote_ip)

        # Limpiar ventana y contar IPs únicas recientes
        connection_windows[pid] = [
            (ip, t) for (ip, t) in connection_windows[pid] if now - t <= WINDOW_SECONDS
        ]
        unique_ips = {ip for ip, _ in connection_windows[pid]}

        if len(unique_ips) > MAX_UNIQUE_IPS_PER_WINDOW:
            reasons.append(
                f"Proceso contactó {len(unique_ips)} IPs distintas en {WINDOW_SECONDS}s "
                f"(patrón de escaneo o exfiltración)"
            )
            severity = "CRITICO"

        alert_key = f"{pid}:{name}"
        if reasons and alert_key not in already_alerted:
            details = {
                "PID": pid,
                "Proceso": name,
                "Ruta": exe_path,
                "Razones": " | ".join(reasons),
            }
            log_alert(severity, f"Actividad de red riesgosa: '{name}' (PID {pid})", details)
            already_alerted.add(alert_key)

            if severity == "CRITICO":
                if name.lower() in SENSITIVE_APPS:
                    route_through_vpn_hook(name, exe_path)
                else:
                    # Bloqueo automático de las IPs riesgosas detectadas
                    for ip in risky_ips:
                        rule_name = f"Sentinel_Block_{name}_{ip}".replace(" ", "_")
                        if block_ip_windows(ip, rule_name):
                            log_alert("ACCION", f"IP {ip} bloqueada para proceso '{name}'", {})


def cleanup(current_pids: set):
    for pid in list(connection_windows.keys()):
        if pid not in current_pids:
            del connection_windows[pid]
    stale = {k for k in already_alerted if int(k.split(":")[0]) not in current_pids}
    already_alerted.difference_update(stale)


def main():
    if IS_WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            print("⚠  ADVERTENCIA: no estás corriendo como Administrador.")
            print("   La detección funcionará, pero el bloqueo automático de IPs no.")
            print("   Cerrá esto y volvé a correr con 'Ejecutar como administrador'.\n")

    print("=" * 60)
    print("  SENTINEL - Network Guard (Protección de IP/Red)")
    print("=" * 60)
    print(f"Ventana de análisis: {WINDOW_SECONDS}s | Máx IPs únicas permitidas: {MAX_UNIQUE_IPS_PER_WINDOW}")
    print(f"Log de alertas: {os.path.abspath(LOG_FILE)}")
    if SENSITIVE_APPS:
        print(f"Apps sensibles (se protegen con VPN en vez de bloqueo directo): {SENSITIVE_APPS}")
    print("Presiona Ctrl+C para detener.\n")

    try:
        while True:
            evaluate_connections()
            current_pids = {p.pid for p in psutil.process_iter()}
            cleanup(current_pids)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")
        sys.exit(0)


if __name__ == "__main__":
    main()
