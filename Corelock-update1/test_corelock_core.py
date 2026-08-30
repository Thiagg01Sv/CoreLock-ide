import unittest
from unittest.mock import patch

import corelock_core as sc


class TestCoreLockCoreOrchestration(unittest.TestCase):

    def test_all_five_modules_registered(self):
        names = [name for _, name in sc.MODULES]
        expected = {"MinerDetector", "NetworkGuard", "RansomwareGuard", "CookieGuard",
                    "MalwareScanner", "UsbGuard"}
        self.assertEqual(set(names), expected)

    def test_run_module_catches_exceptions_without_crashing_others(self):
        class FakeModule:
            @staticmethod
            def main():
                raise RuntimeError("simulando un crash en un módulo")

        # No debe lanzar excepción hacia afuera -- un módulo roto no
        # puede tirar abajo a los otros 4
        try:
            sc._run_module(FakeModule, "FakeModule")
        except Exception:
            self.fail("_run_module no debería propagar excepciones de un módulo individual")


if __name__ == "__main__":
    unittest.main(verbosity=2)
