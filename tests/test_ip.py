import unittest

from aliyun_ip_gate.ip import parse_additional_ips


class ParseAdditionalIpsTests(unittest.TestCase):
    def test_normalizes_sorts_and_deduplicates(self):
        self.assertEqual(
            parse_additional_ips("203.0.113.11, 203.0.113.10,203.0.113.11"),
            ["203.0.113.10", "203.0.113.11"],
        )

    def test_rejects_invalid_address(self):
        with self.assertRaisesRegex(ValueError, "不是有效 IPv4"):
            parse_additional_ips("invalid")

    def test_rejects_ipv6(self):
        with self.assertRaisesRegex(ValueError, "不是 IPv4"):
            parse_additional_ips("2001:db8::1")


if __name__ == "__main__":
    unittest.main()
