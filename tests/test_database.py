import os
import sqlite3
import tempfile
import unittest

from aliyun_ip_gate.config import Settings
from aliyun_ip_gate.database import Database


class DatabaseTests(unittest.TestCase):
    def test_upgrades_existing_runtime_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "data", "app.db")
            os.makedirs(os.path.dirname(path))
            with sqlite3.connect(path) as connection:
                connection.execute(
                    """
                    CREATE TABLE runtime_state (
                        id INTEGER PRIMARY KEY,
                        last_ips TEXT NOT NULL,
                        last_success_at TEXT,
                        last_error TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO runtime_state VALUES (1, '', NULL, '')"
                )

            database = Database(path)
            database.initialize()

            state = database.get_runtime_state()
            self.assertFalse(state["worker_active"])
            self.assertIsNone(state["worker_heartbeat_at"])

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

    def test_worker_state_and_sync_run_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(os.path.join(directory, "data", "app.db"))
            database.initialize()
            database.record_worker_started("2026-09-07T10:00:00+08:00")
            database.record_worker_schedule(
                "2026-09-07T10:01:00+08:00",
                "2026-09-07T10:11:00+08:00",
            )
            database.add_sync_run(
                "2026-09-07T10:01:00+08:00",
                "2026-09-07T10:01:01+08:00",
                "203.0.113.10",
                "203.0.113.10",
                True,
                "同步成功",
                ({
                    "account_name": "PRIMARY",
                    "resource_type": "ECS",
                    "resource_id": "cn-test:sg-test",
                    "success": True,
                    "action": "changed",
                    "message": "新增 203.0.113.10",
                },),
            )

            state = database.get_runtime_state()
            runs = database.list_sync_runs()

            self.assertTrue(state["worker_active"])
            self.assertEqual(state["worker_next_run_at"], "2026-09-07T10:11:00+08:00")
            self.assertEqual(runs[0]["resources"][0]["resource_type"], "ECS")
            self.assertEqual(database.count_sync_runs(), 1)

            database.clear_sync_runs()

            self.assertEqual(database.count_sync_runs(), 0)
            with database.connect() as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM sync_run_resources"
                ).fetchone()[0]
            self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
