import tempfile
import unittest
from pathlib import Path

from aliyun_ip_gate.web_config import load_web_config


class WebConfigTests(unittest.TestCase):
    def test_loads_port_and_access_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, ".env")
            path.write_text(
                "WEB_PORT=17321\nWEB_ACCESS_TOKEN=test-token\n", encoding="utf-8"
            )

            config = load_web_config(path)

            self.assertEqual(config.port, 17321)
            self.assertEqual(config.access_token, "test-token")

    def test_rejects_invalid_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, ".env")
            path.write_text("WEB_PORT=70000\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "1 到 65535"):
                load_web_config(path)


if __name__ == "__main__":
    unittest.main()
