import os
import re
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from aliyun_ip_gate.database import Database
from aliyun_ip_gate import web
from aliyun_ip_gate.web_config import WebConfig


class WebTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Database(os.path.join(self.directory.name, "data", "app.db"))
        self.database.initialize()
        self.original_database = web.database
        self.original_web_config = web.app.state.web_config
        web.database = self.database
        web.app.state.web_config = WebConfig(8000, "test-access-token")
        self.client = TestClient(web.app)

    def tearDown(self):
        self.client.close()
        web.database = self.original_database
        web.app.state.web_config = self.original_web_config
        self.directory.cleanup()

    def authenticate(self):
        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={"csrf_token": token, "access_token": "test-access-token"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return re.search(
            r'name="csrf_token" value="([^"]+)"', response.text
        ).group(1)

    def test_dashboard_renders(self):
        self.authenticate()
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("运行状态", response.text)

    def test_ip_lists_render_as_tags(self):
        self.authenticate()
        self.database.set_additional_ips(("1.1.1.1", "8.8.8.8"))

        response = self.client.get("/additional-ips")

        self.assertEqual(response.status_code, 200)
        self.assertIn('class="ip-tag editable" data-ip="1.1.1.1"', response.text)
        self.assertIn('name="additional_ips" value="1.1.1.1,8.8.8.8"', response.text)

    def test_post_requires_csrf_token(self):
        self.authenticate()
        response = self.client.post("/additional-ips", data={})

        self.assertEqual(response.status_code, 403)

    def test_sync_preview_uses_preview_service(self):
        self.authenticate()
        token = self.csrf_token("/")
        result = {
            "success": True,
            "detected_ips": ["203.0.113.10"],
            "target_ips": ["203.0.113.10"],
            "resources": [],
        }
        with patch.object(web, "preview_sync", return_value=result) as preview:
            response = self.client.post(
                "/sync/preview", data={"csrf_token": token}
            )

        self.assertEqual(response.json(), result)
        preview.assert_called_once_with(self.database)

    def test_clears_sync_runs(self):
        self.authenticate()
        self.database.add_sync_run("start", "finish", "", "", True, "ok")
        token = self.csrf_token("/runs")

        response = self.client.post(
            "/runs/clear",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.database.count_sync_runs(), 0)

    def test_saves_settings(self):
        self.authenticate()
        token = self.csrf_token("/settings")

        response = self.client.post(
            "/settings",
            data={
                "csrf_token": token,
                "check_interval_seconds": "300",
                "allowed_country": "CN",
                "allowed_region": "Guizhou",
                "ecs_rule_description": "sync",
                "rds_whitelist_name": "whitelist",
                "keep_history": "on",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        settings = self.database.get_settings()
        self.assertEqual(settings.check_interval_seconds, 300)
        self.assertTrue(settings.keep_history)

    def test_saves_account_without_rendering_secret(self):
        self.authenticate()
        token = self.csrf_token("/accounts/new")

        response = self.client.post(
            "/accounts/save",
            data={
                "csrf_token": token,
                "account_id": "",
                "name": "PRIMARY",
                "access_key_id": "access-key-id",
                "access_key_secret": "private-secret",
                "security_groups": "cn-test:sg-test",
                "rds_instances": "rm-test",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        account = self.database.list_accounts()[0]
        edit_page = self.client.get(f"/accounts/{account.id}/edit")
        self.assertNotIn("private-secret", edit_page.text)
        self.assertIn('data-target-editor="ecs"', edit_page.text)
        self.assertIn(
            'name="security_groups" data-target-list value="cn-test:sg-test"',
            edit_page.text,
        )
        self.assertEqual(account.security_groups, (("cn-test", "sg-test"),))

        reveal_response = self.client.post(
            "/secrets/reveal",
            data={
                "csrf_token": self.csrf_token(f"/accounts/{account.id}/edit"),
                "secret_name": "access_key_secret",
                "account_id": str(account.id),
            },
        )
        self.assertEqual(reveal_response.json(), {"value": "private-secret"})
        self.assertEqual(reveal_response.headers["cache-control"], "no-store")

        connection_result = {
            "success": True,
            "message": "连接及资源读取正常",
            "resources": [],
        }
        with patch.object(
            web, "check_account_connection", return_value=connection_result
        ) as check_connection:
            test_response = self.client.post(
                f"/accounts/{account.id}/test",
                data={
                    "csrf_token": self.csrf_token(
                        f"/accounts/{account.id}/edit"
                    )
                },
            )

        self.assertEqual(test_response.json(), connection_result)
        check_connection.assert_called_once_with(self.database, account.id)

        toggle_response = self.client.post(
            f"/accounts/{account.id}/enabled",
            data={
                "csrf_token": self.csrf_token("/accounts"),
                "enabled": "0",
            },
            follow_redirects=False,
        )
        self.assertEqual(toggle_response.status_code, 303)
        self.assertFalse(self.database.get_account(account.id).enabled)

    def test_requires_login(self):
        response = self.client.get("/", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")


if __name__ == "__main__":
    unittest.main()
