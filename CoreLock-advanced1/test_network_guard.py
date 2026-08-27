import unittest
import time
from unittest.mock import MagicMock, patch

import network_guard as ng


def make_conn(pid, remote_ip, remote_port):
    conn = MagicMock()
    conn.pid = pid
    conn.raddr = MagicMock(ip=remote_ip, port=remote_port)
    return conn


class TestRiskyPortDetection(unittest.TestCase):

    def setUp(self):
        ng.connection_windows.clear()
        ng.already_alerted.clear()
        ng.blocked_rules.clear()

    @patch("network_guard.psutil.Process")
    @patch("network_guard.psutil.net_connections")
    def test_detects_risky_port_and_blocks(self, mock_net_conns, mock_process_cls):
        pid = 5001
        mock_net_conns.return_value = [make_conn(pid, "198.51.100.10", 4444)]  # puerto riesgoso

        fake_proc = MagicMock()
        fake_proc.name.return_value = "desconocido.exe"
        fake_proc.exe.return_value = "C:\\temp\\desconocido.exe"
        mock_process_cls.return_value = fake_proc

        with patch("network_guard.log_alert") as mock_log, \
             patch("network_guard.block_ip_windows", return_value=True) as mock_block:
            ng.evaluate_connections()
            self.assertTrue(mock_log.called, "Debería haber alertado por puerto riesgoso")
            self.assertTrue(mock_block.called, "Debería haber intentado bloquear la IP")

    @patch("network_guard.psutil.Process")
    @patch("network_guard.psutil.net_connections")
    def test_trusted_process_not_evaluated(self, mock_net_conns, mock_process_cls):
        pid = 5002
        mock_net_conns.return_value = [make_conn(pid, "198.51.100.10", 4444)]

        fake_proc = MagicMock()
        fake_proc.name.return_value = "chrome.exe"  # está en TRUSTED_PROCESSES
        fake_proc.exe.return_value = "C:\\Program Files\\Chrome\\chrome.exe"
        mock_process_cls.return_value = fake_proc

        with patch("network_guard.log_alert") as mock_log:
            ng.evaluate_connections()
            self.assertFalse(mock_log.called, "Un proceso confiable no debería generar alerta")

    @patch("network_guard.psutil.Process")
    @patch("network_guard.psutil.net_connections")
    def test_normal_https_connection_not_flagged(self, mock_net_conns, mock_process_cls):
        pid = 5003
        mock_net_conns.return_value = [make_conn(pid, "142.250.0.1", 443)]

        fake_proc = MagicMock()
        fake_proc.name.return_value = "miapp.exe"
        fake_proc.exe.return_value = "C:\\Program Files\\MiApp\\miapp.exe"
        mock_process_cls.return_value = fake_proc

        with patch("network_guard.log_alert") as mock_log:
            ng.evaluate_connections()
            self.assertFalse(mock_log.called, "Una conexión HTTPS normal no debería alertar")


class TestScanPatternDetection(unittest.TestCase):
    """Verifica que contactar muchas IPs distintas rápido dispare alerta de escaneo."""

    def setUp(self):
        ng.connection_windows.clear()
        ng.already_alerted.clear()

    @patch("network_guard.psutil.Process")
    @patch("network_guard.psutil.net_connections")
    def test_many_unique_ips_triggers_scan_alert(self, mock_net_conns, mock_process_cls):
        pid = 6001
        # Simulamos MAX_UNIQUE_IPS_PER_WINDOW + 1 conexiones a IPs distintas
        num_ips = ng.MAX_UNIQUE_IPS_PER_WINDOW + 5
        conns = [make_conn(pid, f"203.0.113.{i}", 443) for i in range(num_ips)]
        mock_net_conns.return_value = conns

        fake_proc = MagicMock()
        fake_proc.name.return_value = "escaneador.exe"
        fake_proc.exe.return_value = "C:\\temp\\escaneador.exe"
        mock_process_cls.return_value = fake_proc

        with patch("network_guard.log_alert") as mock_log:
            ng.evaluate_connections()
            self.assertTrue(mock_log.called, "Debería detectar patrón de escaneo/exfiltración")


if __name__ == "__main__":
    unittest.main(verbosity=2)
