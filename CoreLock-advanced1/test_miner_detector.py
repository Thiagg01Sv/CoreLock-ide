import unittest
from unittest.mock import MagicMock, patch
from collections import deque

import miner_detector as md


class FakeProcess:
    """Simula un psutil.Process sin necesitar un proceso real del sistema."""

    def __init__(self, pid, name, exe_path, cpu=0.0, connections=None):
        self.pid = pid
        self._name = name
        self._exe = exe_path
        self._cpu = cpu
        self._connections = connections or []

    def name(self):
        return self._name

    def exe(self):
        return self._exe

    def cpu_percent(self, interval=None):
        return self._cpu

    def net_connections(self, kind="inet"):
        return self._connections


class TestMinerNameDetection(unittest.TestCase):
    """Verifica que se detecten nombres de mineros conocidos."""

    def test_detects_known_miner_xmrig(self):
        proc = FakeProcess(pid=1001, name="xmrig.exe", exe_path="C:\\Users\\test\\xmrig.exe")
        self.assertTrue(md.check_known_miner_name(proc))

    def test_detects_known_miner_case_insensitive(self):
        proc = FakeProcess(pid=1002, name="XMRig.exe", exe_path="C:\\temp\\XMRig.exe")
        self.assertTrue(md.check_known_miner_name(proc))

    def test_legit_process_not_flagged(self):
        proc = FakeProcess(pid=1003, name="chrome.exe", exe_path="C:\\Program Files\\Chrome\\chrome.exe")
        self.assertFalse(md.check_known_miner_name(proc))


class TestSpoofedSystemProcess(unittest.TestCase):
    """Verifica que se detecten procesos que fingen ser de Windows."""

    def test_detects_fake_svchost_outside_system32(self):
        proc = FakeProcess(
            pid=2001, name="svchost.exe",
            exe_path="C:\\Users\\test\\Downloads\\svchost.exe"
        )
        self.assertTrue(md.is_spoofed_system_process(proc))

    def test_legit_svchost_in_system32_not_flagged(self):
        proc = FakeProcess(
            pid=2002, name="svchost.exe",
            exe_path="C:\\Windows\\System32\\svchost.exe"
        )
        self.assertFalse(md.is_spoofed_system_process(proc))

    def test_unrelated_process_not_flagged(self):
        proc = FakeProcess(pid=2003, name="notepad.exe", exe_path="C:\\Windows\\System32\\notepad.exe")
        self.assertFalse(md.is_spoofed_system_process(proc))


class TestSustainedCPUDetection(unittest.TestCase):
    """Verifica que la CPU sostenida alta dispare alerta, y que picos cortos NO."""

    def setUp(self):
        md.cpu_history.clear()
        md.already_alerted.clear()

    def test_sustained_high_cpu_triggers_alert(self):
        pid = 3001
        proc = FakeProcess(pid=pid, name="misterioso.exe", exe_path="C:\\temp\\misterioso.exe", cpu=95.0)

        # Simulamos que ya pasó suficiente tiempo con CPU alta (llenamos el historial)
        window_size = md.SUSTAINED_SECONDS // md.POLL_INTERVAL
        md.cpu_history[pid] = deque([95.0] * window_size, maxlen=window_size)

        with patch("miner_detector.log_alert") as mock_log:
            md.evaluate_process(proc)
            self.assertTrue(mock_log.called, "Debería haber generado una alerta por CPU sostenida")

    def test_short_cpu_spike_does_not_trigger(self):
        pid = 3002
        proc = FakeProcess(pid=pid, name="juego.exe", exe_path="C:\\Games\\juego.exe", cpu=95.0)

        # Solo una muestra de CPU alta, no la ventana completa -> no debería alertar
        md.cpu_history[pid] = deque([95.0], maxlen=md.SUSTAINED_SECONDS // md.POLL_INTERVAL)

        with patch("miner_detector.log_alert") as mock_log:
            md.evaluate_process(proc)
            self.assertFalse(mock_log.called, "Un pico corto de CPU no debería generar alerta")


class TestNetworkActivityDetection(unittest.TestCase):
    """Verifica detección de conexiones a puertos típicos de pools de minería."""

    def test_detects_stratum_port_connection(self):
        fake_conn = MagicMock()
        fake_conn.raddr = MagicMock(ip="203.0.113.5", port=3333)  # puerto Stratum típico
        proc = FakeProcess(
            pid=4001, name="oculto.exe", exe_path="C:\\temp\\oculto.exe",
            connections=[fake_conn]
        )
        findings = md.has_suspicious_network_activity(proc)
        self.assertTrue(len(findings) > 0)
        self.assertIn("3333", findings[0])

    def test_normal_https_connection_not_flagged(self):
        fake_conn = MagicMock()
        fake_conn.raddr = MagicMock(ip="142.250.0.1", port=443)  # HTTPS normal
        proc = FakeProcess(
            pid=4002, name="chrome.exe", exe_path="C:\\Program Files\\Chrome\\chrome.exe",
            connections=[fake_conn]
        )
        findings = md.has_suspicious_network_activity(proc)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
