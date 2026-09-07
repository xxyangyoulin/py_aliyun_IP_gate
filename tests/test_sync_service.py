import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from aliyun_ip_gate.config import Settings
from aliyun_ip_gate.database import Database
from aliyun_ip_gate import sync_service


class SyncServiceTests(unittest.TestCase):
    def create_database(self, directory, webhook=""):
        database = Database(os.path.join(directory, "data", "app.db"))
        database.initialize()
        database.save_settings(
            Settings(600, "", "", "", "sync", "sync", webhook, False)
        )
        database.save_account(
            None,
            "PRIMARY",
            "access-key",
            "secret",
            [("cn-test", "sg-test")],
            [],
        )
        return database

    def test_unchanged_ip_still_checks_cloud(self):
        with tempfile.TemporaryDirectory() as directory:
            database = self.create_database(directory)
            database.record_success("198.51.100.1", "2026-01-01T00:00:00+08:00")
            synced = []
            with (
                patch.object(
                    sync_service,
                    "get_public_ips",
                    return_value=[("198.51.100.1", None, None)],
                ),
                patch.object(sync_service, "EcsClient", return_value=object()),
                patch.object(
                    sync_service,
                    "sync_ecs_group",
                    side_effect=lambda *args: synced.append(args[3]),
                ),
                redirect_stdout(StringIO()),
            ):
                sync_service.sync_once(database)

            self.assertEqual(synced, [["198.51.100.1"]])
            runs = database.list_sync_runs()
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["resources"][0]["action"], "unchanged")

    def test_preview_only_reads_cloud_state(self):
        with tempfile.TemporaryDirectory() as directory:
            database = self.create_database(directory)
            with (
                patch.object(
                    sync_service,
                    "get_public_ips",
                    return_value=[("198.51.100.1", None, None)],
                ),
                patch.object(sync_service, "EcsClient", return_value=object()),
                patch.object(
                    sync_service,
                    "sync_ecs_group",
                    return_value={
                        "added_ips": ["198.51.100.1"],
                        "removed_ips": [],
                    },
                ) as sync_ecs_group,
                redirect_stdout(StringIO()),
            ):
                result = sync_service.preview_sync(database)

            self.assertTrue(result["success"])
            self.assertEqual(result["resources"][0]["action"], "changed")
            self.assertTrue(sync_ecs_group.call_args.args[-1])
            self.assertEqual(database.count_sync_runs(), 0)

    def test_account_connection_only_reads_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            database = self.create_database(directory)
            account_id = database.list_accounts()[0].id
            with (
                patch.object(sync_service, "EcsClient", return_value=object()),
                patch.object(
                    sync_service,
                    "sync_ecs_group",
                    return_value={"added_ips": [], "removed_ips": []},
                ) as sync_ecs_group,
                redirect_stdout(StringIO()),
            ):
                result = sync_service.check_account_connection(
                    database, account_id
                )

            self.assertTrue(result["success"])
            self.assertEqual(result["resources"][0]["action"], "checked")
            self.assertTrue(sync_ecs_group.call_args.args[-1])

    def test_missing_targets_does_not_query_public_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(os.path.join(directory, "data", "app.db"))
            database.initialize()
            with patch.object(sync_service, "get_public_ips") as get_public_ips:
                with self.assertRaisesRegex(RuntimeError, "没有配置任何"):
                    sync_service.sync_once(database)

            get_public_ips.assert_not_called()

    def test_disabled_account_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            database = self.create_database(directory)
            account_id = database.list_accounts()[0].id
            database.set_account_enabled(account_id, False)

            with patch.object(sync_service, "get_public_ips") as get_public_ips:
                with self.assertRaisesRegex(RuntimeError, "没有配置任何"):
                    sync_service.sync_once(database)

            get_public_ips.assert_not_called()

    def test_notification_failure_does_not_change_sync_result(self):
        with tempfile.TemporaryDirectory() as directory:
            database = self.create_database(
                directory, "https://example.test/webhook"
            )
            with (
                patch.object(
                    sync_service,
                    "get_public_ips",
                    return_value=[("198.51.100.1", None, None)],
                ),
                patch.object(sync_service, "EcsClient", return_value=object()),
                patch.object(sync_service, "sync_ecs_group"),
                patch.object(
                    sync_service,
                    "notify_ip_change",
                    side_effect=RuntimeError("failed"),
                ),
                redirect_stdout(StringIO()),
            ):
                result = sync_service.sync_once(database)

            state = database.get_runtime_state()
            self.assertEqual(state["last_ips"], "198.51.100.1")
            self.assertEqual(state["last_error"], "")
            self.assertIn("飞书通知失败", result["message"])

    def test_lock_prevents_concurrent_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            database = self.create_database(directory)

            with sync_service.sync_lock(database.path):
                with self.assertRaises(sync_service.SyncAlreadyRunning):
                    with sync_service.sync_lock(database.path):
                        pass


if __name__ == "__main__":
    unittest.main()
