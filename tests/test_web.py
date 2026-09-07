import os
import re
import tempfile
import unittest

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

    def test_post_requires_csrf_token(self):
        self.authenticate()
        response = self.client.post("/additional-ips", data={})

        self.assertEqual(response.status_code, 403)

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
        self.assertEqual(account.security_groups, (("cn-test", "sg-test"),))

    def test_requires_login(self):
        response = self.client.get("/", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")


if __name__ == "__main__":
    unittest.main()
