import requests


def notify_ip_change(webhook_url, old_ips, new_ips):
    response = requests.post(
        webhook_url,
        json={
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": "同步 IP 列表已变更"},
                    "template": "orange",
                },
                "elements": [
                    {
                        "tag": "div",
                        "fields": [
                            {
                                "is_short": False,
                                "text": {
                                    "tag": "lark_md",
                                    "content": f"**原地址：**{old_ips or '无缓存'}",
                                },
                            },
                            {
                                "is_short": False,
                                "text": {
                                    "tag": "lark_md",
                                    "content": f"**新地址：**{new_ips}",
                                },
                            },
                        ],
                    }
                ],
            },
        },
        timeout=10,
    )
    response.raise_for_status()
    result = response.json()
    if result.get("code") != 0:
        raise RuntimeError(
            f"{result.get('msg', '未知错误')} (code={result.get('code')})"
        )
