import ipaddress
import re

from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_rds20140815 import models as rds_models


def sync_ecs_group(
    client,
    region_id,
    security_group_id,
    ips,
    description_prefix,
    keep_history=False,
    dry_run=False,
):
    changes = {"added_ips": [], "removed_ips": []}
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
            changes["added_ips"].append(ip)
            if not dry_run:
                client.authorize_security_group(request)

        def revoke(rules_to_revoke):
            if not rules_to_revoke:
                return
            changes["removed_ips"].extend(
                ip for ip in (rule_ip(rule) for rule in rules_to_revoke) if ip
            )
            if dry_run:
                return
            request = ecs_models.RevokeSecurityGroupRequest(
                region_id=region_id,
                security_group_id=security_group_id,
                security_group_rule_id=[
                    rule.security_group_rule_id for rule in rules_to_revoke
                ],
            )
            client.revoke_security_group(request)

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
            revoke(conflicting_rules)
            obsolete_rules = [
                rule for rule in obsolete_rules if rule not in conflicting_rules
            ]
            authorize(number, ip)

        revoke(obsolete_rules)

    return changes


def sync_rds_instance(
    client, instance_id, ips, whitelist_name, keep_history=False, dry_run=False
):
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
    changes = {
        "added_ips": sorted(target_ips - current_ips),
        "removed_ips": sorted(current_ips - target_ips),
    }
    if current_ips == target_ips:
        return changes
    security_ips = ",".join(sorted(target_ips))

    request = rds_models.ModifySecurityIpsRequest(
        dbinstance_id=instance_id,
        dbinstance_iparray_name=whitelist_name,
        security_ips=security_ips,
        security_iptype="IPv4",
        modify_mode="Cover",
    )
    if not dry_run:
        client.modify_security_ips(request)
    return changes
