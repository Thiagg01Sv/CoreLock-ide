import unittest
from unittest.mock import MagicMock, patch

import cookie_guard as cg


class TestLegitProcessFiltering(unittest.TestCase):

    def test_chrome_is_legit(self):
        self.assertTrue(cg.is_legit_process("chrome.exe"))

    def test_chrome_case_insensitive(self):
        self.assertTrue(cg.is_legit_process("Chrome.EXE"))

    def test_unknown_process_not_legit(self):
        self.assertFalse(cg.is_legit_process("stealer_totally_legit.exe"))


class TestSuspiciousFileAccessDetection(unittest.TestCase):

    def test_detects_non_browser_reading_cookie_file(self):
        sensitive_paths = {r"c:\users\test\appdata\local\google\chrome\user data\default\cookies"}

        fake_open_file = MagicMock()
        fake_open_file.path = r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Cookies"

        fake_proc = MagicMock()
        fake_proc.open_files.return_value = [fake_open_file]

        matches = cg.find_suspicious_file_access(fake_proc, sensitive_paths)
        self.assertEqual(len(matches), 1)

    def test_no_match_when_process_touches_unrelated_file(self):
        sensitive_paths = {r"c:\users\test\appdata\local\google\chrome\user data\default\cookies"}

        fake_open_file = MagicMock()
        fake_open_file.path = r"C:\Users\test\Documents\notas.txt"

        fake_proc = MagicMock()
        fake_proc.open_files.return_value = [fake_open_file]

        matches = cg.find_suspicious_file_access(fake_proc, sensitive_paths)
        self.assertEqual(len(matches), 0)

    def test_access_denied_handled_gracefully(self):
        import psutil
        sensitive_paths = {r"c:\path\cookies"}
        fake_proc = MagicMock()
        fake_proc.open_files.side_effect = psutil.AccessDenied()

        matches = cg.find_suspicious_file_access(fake_proc, sensitive_paths)
        self.assertEqual(matches, [])


class TestDiscordSteamTokenProtection(unittest.TestCase):
    """#11 -- anti-robo de tokens de Discord/Steam."""

    def test_discord_is_now_legit(self):
        self.assertTrue(cg.is_legit_process("Discord.exe"))

    def test_steam_is_now_legit(self):
        self.assertTrue(cg.is_legit_process("steam.exe"))
        self.assertTrue(cg.is_legit_process("steamwebhelper.exe"))

    def test_detects_process_reading_inside_discord_token_directory(self):
        sensitive_prefixes = {r"c:\users\test\appdata\roaming\discord\local storage\leveldb"}

        fake_open_file = MagicMock()
        # Discord rota los nombres de archivo (000003.ldb, etc.) -- por
        # eso se protege el directorio completo, no un archivo puntual
        fake_open_file.path = r"C:\Users\test\AppData\Roaming\discord\Local Storage\leveldb\000003.ldb"

        fake_proc = MagicMock()
        fake_proc.open_files.return_value = [fake_open_file]

        matches = cg.find_suspicious_file_access(fake_proc, set(), sensitive_prefixes)
        self.assertEqual(len(matches), 1)

    def test_steam_loginusers_detected_as_exact_path(self):
        sensitive_paths = {r"c:\program files (x86)\steam\config\loginusers.vdf"}

        fake_open_file = MagicMock()
        fake_open_file.path = r"C:\Program Files (x86)\Steam\config\loginusers.vdf"

        fake_proc = MagicMock()
        fake_proc.open_files.return_value = [fake_open_file]

        matches = cg.find_suspicious_file_access(fake_proc, sensitive_paths)
        self.assertEqual(len(matches), 1)

    def test_unrelated_file_outside_discord_dir_not_flagged(self):
        sensitive_prefixes = {r"c:\users\test\appdata\roaming\discord\local storage\leveldb"}

        fake_open_file = MagicMock()
        fake_open_file.path = r"C:\Users\test\Documents\notas.txt"

        fake_proc = MagicMock()
        fake_proc.open_files.return_value = [fake_open_file]

        matches = cg.find_suspicious_file_access(fake_proc, set(), sensitive_prefixes)
        self.assertEqual(len(matches), 0)

    def test_get_all_sensitive_prefixes_includes_discord_variants(self):
        prefixes = cg.get_all_sensitive_prefixes()
        self.assertTrue(any("discord" in p for p in prefixes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
