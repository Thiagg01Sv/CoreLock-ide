import unittest
import os
import tempfile
import shutil
from unittest.mock import patch

import usb_guard as ug


class TestScanDrive(unittest.TestCase):
    """Usa una carpeta temporal como si fuera la raíz de un USB conectado --
    no necesita un USB real ni Windows para validar la lógica de detección."""

    def setUp(self):
        self.fake_usb = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.fake_usb, ignore_errors=True)

    def _touch(self, name: str, content: bytes = b"contenido de prueba"):
        path = os.path.join(self.fake_usb, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_detects_autorun_inf(self):
        self._touch("autorun.inf", b"[autorun]\nopen=virus.exe")
        findings = ug.scan_drive(self.fake_usb)
        severities = [f[0] for f in findings]
        self.assertIn("CRITICO", severities)
        self.assertTrue(any("autorun" in f[1].lower() for f in findings))

    def test_detects_executable_disguised_as_folder(self):
        self._touch("Fotos.exe")
        findings = ug.scan_drive(self.fake_usb)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "CRITICO")
        self.assertIn("disfrazado", findings[0][1].lower())

    def test_detects_suspicious_lnk_file(self):
        self._touch("Fotos de vacaciones.lnk")
        findings = ug.scan_drive(self.fake_usb)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "SOSPECHOSO")

    def test_normal_document_not_flagged(self):
        self._touch("informe.docx")
        self._touch("presentacion.pdf")
        findings = ug.scan_drive(self.fake_usb)
        self.assertEqual(len(findings), 0)

    def test_normal_named_executable_not_flagged_as_disguised(self):
        # Un .exe con nombre propio (no imita una carpeta común) no debería
        # dispararse por esta regla puntual -- evita falsos positivos con
        # instaladores legítimos que el usuario trae a propósito en el USB
        self._touch("instalador_setup_v2.exe")
        findings = ug.scan_drive(self.fake_usb)
        self.assertEqual(len(findings), 0)

    def test_empty_drive_no_findings(self):
        findings = ug.scan_drive(self.fake_usb)
        self.assertEqual(findings, [])

    def test_nonexistent_drive_returns_empty_list_gracefully(self):
        findings = ug.scan_drive("/ruta/que/no/existe/jamas")
        self.assertEqual(findings, [])


class TestHandleNewDrive(unittest.TestCase):

    @patch("usb_guard.response_engine.quarantine_file")
    @patch("usb_guard.log_alert")
    @patch("usb_guard.scan_drive")
    def test_critical_finding_triggers_auto_quarantine(self, mock_scan, mock_log, mock_quarantine):
        mock_scan.return_value = [("CRITICO", "autorun.inf encontrado", "D:\\autorun.inf")]

        with patch("usb_guard.AUTO_RESPOND", True):
            ug.handle_new_drive("D:\\")

        mock_quarantine.assert_called_once()

    @patch("usb_guard.response_engine.quarantine_file")
    @patch("usb_guard.log_alert")
    @patch("usb_guard.scan_drive")
    def test_no_findings_does_not_quarantine_anything(self, mock_scan, mock_log, mock_quarantine):
        mock_scan.return_value = []
        ug.handle_new_drive("D:\\")
        mock_quarantine.assert_not_called()

    @patch("usb_guard.response_engine.quarantine_file")
    @patch("usb_guard.log_alert")
    @patch("usb_guard.scan_drive")
    def test_sospechoso_severity_does_not_auto_quarantine(self, mock_scan, mock_log, mock_quarantine):
        # SOSPECHOSO (ej: un .lnk) alerta pero no actúa solo -- solo CRITICO
        # dispara cuarentena automática
        mock_scan.return_value = [("SOSPECHOSO", "acceso directo raro", "D:\\cosa.lnk")]

        with patch("usb_guard.AUTO_RESPOND", True):
            ug.handle_new_drive("D:\\")

        mock_quarantine.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
