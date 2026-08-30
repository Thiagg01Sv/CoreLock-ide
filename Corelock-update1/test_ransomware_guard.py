import unittest
from unittest.mock import MagicMock, patch

import ransomware_guard as rg


def make_event(src_path, is_directory=False, dest_path=None):
    ev = MagicMock()
    ev.src_path = src_path
    ev.is_directory = is_directory
    if dest_path:
        ev.dest_path = dest_path
    return ev


class TestCanaryDetection(unittest.TestCase):

    def test_canary_modification_triggers_critical_alert(self):
        canary_path = "C:\\Users\\test\\Documents\\.corelock_canary\\canary_0.docx"
        handler = rg.RansomwareHandler([canary_path])
        event = make_event(canary_path)

        # AUTO_RESPOND dispara una búsqueda de proceso culpable con 1.5s de
        # espera real; la deshabilitamos para que el test siga siendo rápido
        # y determinístico, y solo validamos que se generó la alerta CRITICO.
        with patch("ransomware_guard.log_alert") as mock_log, \
             patch("ransomware_guard.AUTO_RESPOND", False):
            handler.on_modified(event)
            mock_log.assert_called_once()
            severity = mock_log.call_args[0][0]
            self.assertEqual(severity, "CRITICO")

    def test_canary_deletion_triggers_critical_alert(self):
        canary_path = "C:\\Users\\test\\Desktop\\.corelock_canary\\canary_1.jpg"
        handler = rg.RansomwareHandler([canary_path])
        event = make_event(canary_path)

        with patch("ransomware_guard.log_alert") as mock_log:
            handler.on_deleted(event)
            mock_log.assert_called_once()

    def test_normal_file_modification_does_not_trigger_canary_alert(self):
        handler = rg.RansomwareHandler(["C:\\Users\\test\\Documents\\.corelock_canary\\canary_0.docx"])
        event = make_event("C:\\Users\\test\\Documents\\reporte_real.docx")

        with patch("ransomware_guard.log_alert") as mock_log:
            handler.on_modified(event)
            # No debería marcarlo como canary (aunque sí cuenta para el rate-limit)
            calls = [c for c in mock_log.call_args_list if "SEÑUELO" in c[0][1]]
            self.assertEqual(len(calls), 0)


    def test_canary_modification_triggers_auto_response_when_enabled(self):
        canary_path = "C:\\Users\\test\\Documents\\.corelock_canary\\canary_0.docx"
        handler = rg.RansomwareHandler([canary_path])
        event = make_event(canary_path)

        with patch("ransomware_guard._respond_to_ransomware") as mock_respond, \
             patch("ransomware_guard.log_alert"), \
             patch("ransomware_guard.AUTO_RESPOND", True):
            handler.on_modified(event)
            mock_respond.assert_called_once_with(canary_path)


class TestRansomwareExtensionDetection(unittest.TestCase):

    def test_known_ransomware_extension_flagged(self):
        handler = rg.RansomwareHandler([])
        event = make_event("C:\\Users\\test\\Documents\\foto.jpg.locked")

        with patch("ransomware_guard.log_alert") as mock_log:
            handler.on_modified(event)
            self.assertTrue(mock_log.called)
            severity = mock_log.call_args_list[0][0][0]
            self.assertEqual(severity, "CRITICO")

    def test_normal_extension_not_flagged_as_ransomware_ext(self):
        handler = rg.RansomwareHandler([])
        event = make_event("C:\\Users\\test\\Documents\\notas.txt")

        with patch("ransomware_guard.log_alert") as mock_log:
            handler.on_modified(event)
            self.assertFalse(mock_log.called)


class TestMassModificationDetection(unittest.TestCase):

    def test_mass_modification_triggers_alert(self):
        handler = rg.RansomwareHandler([])
        with patch("ransomware_guard.log_alert") as mock_log:
            for i in range(rg.MASS_MODIFY_THRESHOLD):
                event = make_event(f"C:\\Users\\test\\Documents\\archivo_{i}.txt")
                handler.on_modified(event)
            self.assertTrue(mock_log.called)
            severities = [c[0][0] for c in mock_log.call_args_list]
            self.assertIn("CRITICO", severities)

    def test_few_modifications_do_not_trigger_mass_alert(self):
        handler = rg.RansomwareHandler([])
        with patch("ransomware_guard.log_alert") as mock_log:
            for i in range(3):
                event = make_event(f"C:\\Users\\test\\Documents\\archivo_{i}.txt")
                handler.on_modified(event)
            self.assertFalse(mock_log.called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
