import unittest
import os
import tempfile
import shutil
from unittest.mock import MagicMock, patch

import response_engine as re_


class TestQuarantine(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.original_quarantine_dir = re_.QUARANTINE_DIR
        re_.QUARANTINE_DIR = os.path.join(self.tmpdir, ".corelock_quarantine")

    def tearDown(self):
        re_.QUARANTINE_DIR = self.original_quarantine_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_quarantine_moves_file_out_of_original_location(self):
        test_file = os.path.join(self.tmpdir, "sospechoso.exe")
        with open(test_file, "wb") as f:
            f.write(b"contenido de prueba, no es malware real")

        with patch("response_engine.IS_WINDOWS", False):  # evitar llamar a icacls en este entorno
            result = re_.quarantine_file(test_file, reason="test")

        self.assertTrue(result)
        self.assertFalse(os.path.exists(test_file))
        quarantined_files = os.listdir(re_.QUARANTINE_DIR)
        self.assertEqual(len(quarantined_files), 1)
        self.assertTrue(quarantined_files[0].endswith(".quarantined"))

    def test_quarantine_nonexistent_file_returns_false(self):
        result = re_.quarantine_file("/ruta/que/no/existe.exe")
        self.assertFalse(result)

    def test_quarantine_none_path_returns_false(self):
        result = re_.quarantine_file(None)
        self.assertFalse(result)


class TestKillProcess(unittest.TestCase):

    @patch("response_engine.psutil.Process")
    def test_kill_process_success(self, mock_process_cls):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "malware.exe"
        mock_process_cls.return_value = fake_proc

        result = re_.kill_process(1234, reason="test")
        self.assertTrue(result)
        fake_proc.kill.assert_called_once()

    @patch("response_engine.psutil.Process")
    def test_kill_process_already_gone_counts_as_success(self, mock_process_cls):
        import psutil
        mock_process_cls.side_effect = psutil.NoSuchProcess(1234)

        result = re_.kill_process(1234, reason="test")
        self.assertTrue(result)


class TestNeverAutoKillSafetyNet(unittest.TestCase):
    """Regresión del bug real: explorer.exe se mataba en loop infinito.
    Estos tests garantizan que la red de seguridad central bloquea esto
    sin importar qué tan convencido esté un detector."""

    @patch("response_engine.psutil.Process")
    def test_protected_process_is_never_killed(self, mock_process_cls):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "explorer.exe"
        mock_process_cls.return_value = fake_proc

        result = re_.kill_process(1234, reason="falso positivo de prueba")

        self.assertFalse(result)
        fake_proc.kill.assert_not_called()

    @patch("response_engine.psutil.Process")
    def test_protected_process_case_insensitive(self, mock_process_cls):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "Explorer.EXE"
        mock_process_cls.return_value = fake_proc

        result = re_.kill_process(1234, reason="test")
        self.assertFalse(result)
        fake_proc.kill.assert_not_called()

    @patch("response_engine.psutil.Process")
    def test_non_protected_process_can_still_be_killed(self, mock_process_cls):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "malware_real.exe"
        mock_process_cls.return_value = fake_proc

        result = re_.kill_process(1234, reason="test")
        self.assertTrue(result)
        fake_proc.kill.assert_called_once()

    def test_quarantine_refuses_protected_filename(self):
        self.tmpdir = tempfile.mkdtemp()
        original_dir = re_.QUARANTINE_DIR
        re_.QUARANTINE_DIR = os.path.join(self.tmpdir, ".corelock_quarantine")

        protected_file = os.path.join(self.tmpdir, "explorer.exe")
        with open(protected_file, "wb") as f:
            f.write(b"contenido de prueba")

        try:
            result = re_.quarantine_file(protected_file, reason="test")
            self.assertFalse(result)
            self.assertTrue(os.path.exists(protected_file))  # no se movió
        finally:
            re_.QUARANTINE_DIR = original_dir
            shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestNeutralize(unittest.TestCase):

    @patch("response_engine.quarantine_file")
    @patch("response_engine.kill_process")
    def test_neutralize_calls_both_when_both_provided(self, mock_kill, mock_quarantine):
        re_.neutralize(pid=999, file_path="C:\\temp\\malo.exe", reason="test")
        mock_kill.assert_called_once()
        mock_quarantine.assert_called_once()

    @patch("response_engine.quarantine_file")
    @patch("response_engine.kill_process")
    def test_neutralize_skips_quarantine_when_no_path(self, mock_kill, mock_quarantine):
        re_.neutralize(pid=999, file_path=None, reason="test")
        mock_kill.assert_called_once()
        mock_quarantine.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
