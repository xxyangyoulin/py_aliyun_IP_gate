import argparse
import ipaddress
import os
import re
import time

import requests
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_rds20140815.client import Client as RdsClient
from alibabacloud_rds20140815 import models as rds_models
from alibabacloud_tea_openapi import models as open_api_models
from dotenv import load_dotenv


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_public_ips(check_location=True):
    ips = set()
    ip_providers = (
        "https://v4.ident.me",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
        "https://ipv4.icanhazip.com",
        "https://api-ipv4.ip.sb/ip",
    )
    for url in ip_providers:
        try:
            headers = {}
            if url.startswith("https://ipinfo.io/") and os.getenv("IPINFO_TOKEN"):
                headers["Authorization"] = f"Bearer {os.environ['IPINFO_TOKEN']}"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            candidate = ipaddress.ip_address(response.text.strip())
            if candidate.version != 4:
                raise ValueError("当前仅支持 IPv4")
            ips.add(str(candidate))
            print(f"IPv4 查询接口: {url} -> {candidate}")
        except (requests.RequestException, ValueError) as error:
            print(f"IPv4 查询接口失败，尝试下一个: {url} ({error})")

    if not ips:
        raise RuntimeError("所有公网 IPv4 查询接口均不可用")

    if not check_location:
        return [(ip, None, None) for ip in sorted(ips)]

    locations = []
    for ip in sorted(ips):
        geo_providers = (
            f"https://ipinfo.io/{ip}/json",
            f"https://api.ip.sb/geoip/{ip}",
            f"https://ipwho.is/{ip}",
        )
        for url in geo_providers:
            try:
                headers = {}
                if url.startswith("https://ipinfo.io/") and os.getenv("IPINFO_TOKEN"):
                    headers["Authorization"] = f"Bearer {os.environ['IPINFO_TOKEN']}"
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                data = response.json()
                if data.get("ip") != ip:
                    raise ValueError("接口返回的 IP 不匹配")

                if url.startswith("https://api.ip.sb/"):
                    country, region = data["country_code"], data["region"]
                elif url.startswith("https://ipinfo.io/"):
                    country, region = data["country"], data["region"]
                else:
                    if not data["success"]:
                        raise ValueError("接口返回失败")
                    country, region = data["country_code"], data["region"]

                print(f"IP 归属地接口: {url.rsplit('/', 1)[0]}")
                locations.append((ip, country, region))
                break
            except (requests.RequestException, KeyError, TypeError, ValueError) as error:
                print(f"IP 归属地接口失败，尝试下一个: {url.rsplit('/', 1)[0]} ({error})")
        else:
            raise RuntimeError(f"无法确认公网 IP {ip} 的归属地")

    return locations


def sync_ecs_group(
    client, region_id, security_group_id, ips, description_prefix, keep_history=False
):
    rules = []
    next_token = None
    while True:
        request = ecs_models.DescribeSecurityGroupAttributeRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            direction="ingress",
            max_results=100,
            next_token=next_token,
        )
        body = client.describe_security_group_attribute(request).body
        if body.permissions and body.permissions.permission:
            rules.extend(body.permissions.permission)
        next_token = body.next_token
        if not next_token:
            break

    numbered_description = re.compile(
        rf"{re.escape(description_prefix)}:([1-9][0-9]*)"
    )
    managed_rules = [
        rule
        for rule in rules
        if rule.description == description_prefix
        or numbered_description.fullmatch(rule.description or "")
    ]

    groups = {}
    for rule in managed_rules:
        if not rule.source_cidr_ip:
            raise RuntimeError(f"安全组规则 {rule.security_group_rule_id} 不是 IPv4 CIDR 规则")
        try:
            source = ipaddress.ip_network(rule.source_cidr_ip, strict=False)
        except ValueError as error:
            raise RuntimeError(
                f"安全组规则 {rule.security_group_rule_id} 的来源不是有效 IPv4"
            ) from error
        if source.version != 4 or source.prefixlen != 32:
            raise RuntimeError(
                f"安全组规则 {rule.security_group_rule_id} 的来源不是单个 IPv4"
            )

        shape = (
            rule.ip_protocol,
            rule.port_range,
            rule.source_port_range,
            rule.dest_cidr_ip,
            rule.policy,
            rule.priority,
            rule.nic_type,
        )
        group = groups.setdefault(shape, {"templates": [], "numbered": {}})
        if rule.description == description_prefix:
            group["templates"].append(rule)
        else:
            number = int(numbered_description.fullmatch(rule.description).group(1))
            group["numbered"].setdefault(number, []).append(rule)

    if not groups:
        groups[("TCP", "1/65535", None, None, "Accept", "1", "internet")] = {
            "templates": [],
            "numbered": {},
        }

    unmanaged_rules = [rule for rule in rules if rule not in managed_rules]

    def rule_ip(rule):
        if not rule.source_cidr_ip:
            return None
        try:
            source = ipaddress.ip_network(rule.source_cidr_ip, strict=False)
        except ValueError:
            return None
        if source.version != 4 or source.prefixlen != 32:
            return None
        return str(source.network_address)

    def revoke(rule_ids):
        if not rule_ids:
            return
        request = ecs_models.RevokeSecurityGroupRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            security_group_rule_id=rule_ids,
        )
        client.revoke_security_group(request)

    for shape, group in groups.items():
        templates = group["templates"]
        numbered = group["numbered"]
        all_group_rules = templates + [
            rule for current_rules in numbered.values() for rule in current_rules
        ]
        kept_rules = {}
        used_ips = set()
        for number in range(1, len(ips) + 1):
            for rule in numbered.get(number, []):
                current_ip = rule_ip(rule)
                if current_ip in ips and current_ip not in used_ips:
                    kept_rules[number] = rule
                    used_ips.add(current_ip)
                    break

        missing_numbers = [
            number for number in range(1, len(ips) + 1) if number not in kept_rules
        ]
        missing_ips = [ip for ip in ips if ip not in used_ips]
        obsolete_rules = [rule for rule in all_group_rules if rule not in kept_rules.values()]
        pending = list(zip(missing_numbers, missing_ips))

        def authorize(number, ip):
            for rule in unmanaged_rules:
                unmanaged_shape = (
                    rule.ip_protocol,
                    rule.port_range,
                    rule.source_port_range,
                    rule.dest_cidr_ip,
                    rule.policy,
                    rule.priority,
                    rule.nic_type,
                )
                if unmanaged_shape == shape and rule_ip(rule) == ip:
                    raise RuntimeError(
                        f"安全组已有相同协议、端口和来源 {ip} 的非同步规则，拒绝覆盖"
                    )

            ip_protocol, port_range, source_port_range, dest_cidr_ip, policy, priority, nic_type = shape
            request = ecs_models.AuthorizeSecurityGroupRequest(
                region_id=region_id,
                security_group_id=security_group_id,
                ip_protocol=ip_protocol,
                port_range=port_range,
                source_port_range=source_port_range,
                dest_cidr_ip=dest_cidr_ip,
                source_cidr_ip=ip,
                policy=policy,
                priority=priority,
                nic_type=nic_type,
                description=f"{description_prefix}:{number}",
            )
            client.authorize_security_group(request)

        if keep_history:
            existing_ips = {rule_ip(rule) for rule in all_group_rules}
            used_numbers = set(numbered)
            if templates:
                used_numbers.add(1)
            next_number = 1
            for ip in ips:
                if ip in existing_ips:
                    continue
                while next_number in used_numbers:
                    next_number += 1
                authorize(next_number, ip)
                used_numbers.add(next_number)
                existing_ips.add(ip)
            continue

        for number, ip in pending:
            if not any(rule_ip(rule) == ip for rule in obsolete_rules):
                authorize(number, ip)

        for number, ip in pending:
            conflicting_rules = [
                rule for rule in obsolete_rules if rule_ip(rule) == ip
            ]
            if not conflicting_rules:
                continue
            revoke([rule.security_group_rule_id for rule in conflicting_rules])
            obsolete_rules = [
                rule for rule in obsolete_rules if rule not in conflicting_rules
            ]
            authorize(number, ip)

        revoke([rule.security_group_rule_id for rule in obsolete_rules])


def sync_rds_instance(client, instance_id, ips, whitelist_name, keep_history=False):
    request = rds_models.DescribeDBInstanceIPArrayListRequest(dbinstance_id=instance_id)
    body = client.describe_dbinstance_iparray_list(request).body
    groups = body.items.dbinstance_iparray if body.items else []
    group = next(
        (item for item in groups if item.dbinstance_iparray_name == whitelist_name),
        None,
    )
    current_ips = {
        ip.strip()
        for ip in (group.security_iplist.split(",") if group else [])
        if ip.strip()
    }
    target_ips = set(ips)
    if keep_history:
        target_ips.update(current_ips)
    if current_ips == target_ips:
        return
    security_ips = ",".join(sorted(target_ips))

    request = rds_models.ModifySecurityIpsRequest(
        dbinstance_id=instance_id,
        dbinstance_iparray_name=whitelist_name,
        security_ips=security_ips,
        security_iptype="IPv4",
        modify_mode="Cover",
    )
    client.modify_security_ips(request)


def notify_feishu_ip_change(webhook_url, old_ips, new_ips):
    response = requests.post(
        webhook_url,
        json={
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": "本地公网 IP 已变更"},
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


def sync_once(keep_history=False):
    allowed_country = os.getenv("IP_ALLOWED_COUNTRY", "").strip()
    allowed_region = os.getenv("IP_ALLOWED_REGION", "").strip()
    check_location = bool(allowed_country or allowed_region)
    locations = get_public_ips(check_location)
    for ip, country, region in locations:
        if not check_location:
            print(f"当前公网 IP: {ip}，未配置地域限制")
            continue
        print(f"当前公网 IP: {ip}，位置: {country}/{region}")
        if (
            allowed_country
            and country.strip().casefold() != allowed_country.casefold()
        ) or (
            allowed_region
            and region.strip().casefold() != allowed_region.casefold()
        ):
            print(
                f"当前 IP 不符合地域限制: "
                f"{allowed_country or '*'}/{allowed_region or '*'}，跳过同步"
            )
            return
    ips = [ip for ip, _, _ in locations]
    cached_ips = ",".join(ips)

    cache_file = os.getenv("IP_CACHE_FILE", ".last_ip")
    if not os.path.isabs(cache_file):
        cache_file = os.path.join(PROJECT_DIR, cache_file)
    old_ips = ""
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as file:
            old_ips = file.read().strip()
            if old_ips == cached_ips:
                print("IP 未变化，跳过同步")
                return

    description = os.environ["ALIYUN_ECS_RULE_DESCRIPTION"].strip()
    if not description:
        raise ValueError("ALIYUN_ECS_RULE_DESCRIPTION 禁止为空")
    whitelist_name = os.getenv("ALIYUN_RDS_WHITELIST_NAME", "aliyun_sync_local_ip")
    if not whitelist_name.strip() or whitelist_name.strip().lower() == "default":
        raise ValueError("ALIYUN_RDS_WHITELIST_NAME 禁止为空或使用 default")
    target_count = 0
    failures = []

    for account_name in os.environ["ALIYUN_ACCOUNTS"].split(","):
        account_name = account_name.strip().upper()
        if not account_name:
            continue
        prefix = f"ALIYUN_{account_name}"
        try:
            access_key_id = os.environ[f"{prefix}_ACCESS_KEY_ID"]
            access_key_secret = os.environ[f"{prefix}_ACCESS_KEY_SECRET"]
        except KeyError as error:
            failures.append(f"账号 {account_name} 缺少配置 {error.args[0]}")
            print(f"账号配置失败，继续处理下一个账号: {account_name} ({error.args[0]})")
            continue

        for group in os.getenv(f"{prefix}_SECURITY_GROUPS", "").split(","):
            if not group.strip():
                continue
            target_count += 1
            try:
                region_id, security_group_id = group.strip().split(":", 1)
                config = open_api_models.Config(
                    access_key_id=access_key_id,
                    access_key_secret=access_key_secret,
                )
                config.endpoint = f"ecs.{region_id}.aliyuncs.com"
                sync_ecs_group(
                    EcsClient(config),
                    region_id,
                    security_group_id,
                    ips,
                    description,
                    keep_history,
                )
                print(f"已同步安全组: {account_name}/{region_id}/{security_group_id}")
            except Exception as error:
                failures.append(f"安全组 {account_name}/{group.strip()}: {error}")
                print(f"安全组同步失败，继续处理下一个目标: {account_name}/{group.strip()} ({error})")

        rds_config = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
        )
        rds_config.endpoint = "rds.aliyuncs.com"
        rds_client = RdsClient(rds_config)
        for instance_id in os.getenv(f"{prefix}_RDS_INSTANCES", "").split(","):
            instance_id = instance_id.strip()
            if not instance_id:
                continue
            target_count += 1
            try:
                sync_rds_instance(
                    rds_client, instance_id, ips, whitelist_name, keep_history
                )
                print(f"已同步 RDS 白名单: {account_name}/{instance_id}/{whitelist_name}")
            except Exception as error:
                failures.append(f"RDS {account_name}/{instance_id}: {error}")
                print(f"RDS 同步失败，继续处理下一个目标: {account_name}/{instance_id} ({error})")

    if failures:
        raise RuntimeError(f"本轮有 {len(failures)} 个目标同步失败，未更新 IP 缓存")
    if not target_count:
        raise RuntimeError("没有配置任何安全组或 RDS 实例")
    webhook_url = os.getenv("FEISHU_WEBHOOK_URL", "").strip()
    if webhook_url:
        notify_feishu_ip_change(webhook_url, old_ips, cached_ips)
        print("已发送飞书 IP 变更通知")
    with open(cache_file, "w", encoding="utf-8") as file:
        file.write(cached_ips)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="执行一次后退出")
    parser.add_argument(
        "--keep-history",
        action="store_true",
        help="保留 ECS 和 RDS 中的历史 IP，只新增不删除",
    )
    args = parser.parse_args()
    load_dotenv(os.path.join(PROJECT_DIR, ".env"))
    interval = int(os.getenv("CHECK_INTERVAL_SECONDS", "600"))

    while True:
        try:
            sync_once(args.keep_history)
        except Exception as error:
            print(f"同步失败: {error}")
        if args.once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
