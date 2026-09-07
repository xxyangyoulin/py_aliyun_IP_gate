import unittest
from types import SimpleNamespace

from aliyun_ip_gate.aliyun import sync_ecs_group, sync_rds_instance


class EcsClient:
    def __init__(self):
        self.authorized = []

    def describe_security_group_attribute(self, request):
        body = SimpleNamespace(permissions=None, next_token=None)
        return SimpleNamespace(body=body)

    def authorize_security_group(self, request):
        self.authorized.append(request)

    def revoke_security_group(self, request):
        raise AssertionError("不应删除规则")


class RdsClient:
    def __init__(self, current_ips):
        group = SimpleNamespace(
            dbinstance_iparray_name="sync", security_iplist=",".join(current_ips)
        )
        items = SimpleNamespace(dbinstance_iparray=[group])
        self.body = SimpleNamespace(items=items)
        self.modified = []

    def describe_dbinstance_iparray_list(self, request):
        return SimpleNamespace(body=self.body)

    def modify_security_ips(self, request):
        self.modified.append(request)


class AliyunSyncTests(unittest.TestCase):
    def test_ecs_creates_default_rule(self):
        client = EcsClient()

        sync_ecs_group(client, "cn-test", "sg-test", ["203.0.113.10"], "sync")

        self.assertEqual(len(client.authorized), 1)
        self.assertEqual(client.authorized[0].source_cidr_ip, "203.0.113.10")
        self.assertEqual(client.authorized[0].description, "sync:1")

    def test_rds_skips_unchanged_whitelist(self):
        client = RdsClient(["203.0.113.10"])

        sync_rds_instance(client, "rm-test", ["203.0.113.10"], "sync")

        self.assertEqual(client.modified, [])

    def test_rds_replaces_whitelist(self):
        client = RdsClient(["203.0.113.10"])

        sync_rds_instance(client, "rm-test", ["203.0.113.11"], "sync")

        self.assertEqual(client.modified[0].security_ips, "203.0.113.11")


if __name__ == "__main__":
    unittest.main()
