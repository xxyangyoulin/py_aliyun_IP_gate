import unittest
from unittest.mock import Mock, patch

from aliyun_ip_gate.feishu import notify_ip_change


class NotifyIpChangeTests(unittest.TestCase):
    @patch("aliyun_ip_gate.feishu.requests.post")
    def test_sends_card(self, post):
        response = post.return_value
        response.json.return_value = {"code": 0, "msg": "success"}

        notify_ip_change("https://example.test/webhook", "1.1.1.1", "2.2.2.2")

        response.raise_for_status.assert_called_once_with()
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["msg_type"], "interactive")
        self.assertEqual(
            payload["card"]["header"]["title"]["content"], "同步 IP 列表已变更"
        )

    @patch("aliyun_ip_gate.feishu.requests.post")
    def test_rejects_business_error(self, post):
        response = Mock()
        response.json.return_value = {"code": 19024, "msg": "Key Words Not Found"}
        post.return_value = response

        with self.assertRaisesRegex(RuntimeError, "code=19024"):
            notify_ip_change("https://example.test/webhook", "old", "new")


if __name__ == "__main__":
    unittest.main()
