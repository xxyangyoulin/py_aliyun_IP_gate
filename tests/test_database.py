import os
import tempfile
import unittest

from aliyun_ip_gate.config import Settings
from aliyun_ip_gate.database import Database


class DatabaseTests(unittest.TestCase):
    def test_saves_and_loads_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(os.path.join(directory, "data", "app.db"))
            database.initialize()
            database.save_settings(
                Settings(300, "CN", "Guizhou", "token", "sync", "whitelist", "", True)
            )
            database.save_account(
                None,
                "PRIMARY",
                "access-key",
                "secret",
                [("cn-test", "sg-test")],
                ["rm-test"],
            )
            database.set_additional_ips(["203.0.113.10"])

            config = database.load_config()

            self.assertEqual(config.settings.check_interval_seconds, 300)
            self.assertTrue(config.settings.keep_history)
            self.assertEqual(config.accounts[0].security_groups, (("cn-test", "sg-test"),))
            self.assertEqual(config.accounts[0].rds_instances, ("rm-test",))
            self.assertEqual(config.additional_ips, ("203.0.113.10",))
            self.assertEqual(os.stat(database.path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
