import sys
import time
import socket
import threading


def simulate_cpu_load(duration=100):
    print(f"Generando carga de CPU real durante {duration} segundos...")
    print("Mientras corre esto, en OTRA terminal corré miner_detector.py")
    print("Deberías ver una alerta 'SOSPECHOSO' o 'CRITICO' después del umbral configurado.\n")
    print("TIP: para no esperar 90s reales, editá SUSTAINED_SECONDS=15 en miner_detector.py")
    print("     antes de correr este test, así ves el resultado más rápido.\n")

    end_time = time.time() + duration

    def burn():
        while time.time() < end_time:
            _ = sum(i * i for i in range(10000))

    threads = [threading.Thread(target=burn) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("Carga de CPU finalizada.")


def simulate_risky_port_listener(port=4444, duration=60):
    print(f"Abriendo listener de prueba en el puerto {port} (uno de los puertos riesgosos)...")
    print("En OTRA terminal corré network_guard.py como Administrador.")
    print("Luego, en una TERCERA terminal, conectate con:")
    print(f"    python -c \"import socket; s=socket.socket(); s.connect(('127.0.0.1', {port}))\"")
    print("Deberías ver una alerta CRITICO en network_guard.py.\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(5)
    s.settimeout(duration)

    try:
        conn, addr = s.accept()
        print(f"Conexión de prueba recibida desde {addr}. ¡Revisá network_guard.py ahora!")
        conn.close()
    except socket.timeout:
        print("Nadie se conectó dentro del tiempo de espera. Probá de nuevo.")
    finally:
        s.close()


def simulate_ip_scan_pattern():
    test_ips = [
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.8.4.4",
        "1.0.0.1", "76.76.19.19", "94.140.14.14", "185.228.168.9", "64.6.64.6",
        "77.88.8.8", "156.154.70.1", "199.85.126.10", "84.200.69.80", "198.101.242.72",
        "8.26.56.26",
    ]
    print(f"Conectando a {len(test_ips)} IPs distintas (servidores DNS públicos reales)...")
    print("En OTRA terminal corré network_guard.py.")
    print("Deberías ver una alerta CRITICO por 'patrón de escaneo o exfiltración'.\n")

    for ip in test_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, 53))  # puerto DNS, conexión real breve
            s.close()
            print(f"  Conectado a {ip}")
        except Exception as e:
            print(f"  {ip} -> no se pudo conectar ({e})")
        time.sleep(0.5)

    print("\nListo. Revisá la ventana de network_guard.py.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "cpu":
        simulate_cpu_load()
    elif mode == "port":
        simulate_risky_port_listener()
    elif mode == "scan":
        simulate_ip_scan_pattern()
    else:
        print(f"Modo desconocido: {mode}")
        print(__doc__)
