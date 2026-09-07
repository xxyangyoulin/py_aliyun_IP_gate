import fcntl
import os
from contextlib import contextmanager
from datetime import datetime

from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_rds20140815.client import Client as RdsClient
from alibabacloud_tea_openapi import models as open_api_models

from .aliyun import sync_ecs_group, sync_rds_instance
from .feishu import notify_ip_change
from .ip import get_public_ips


class SyncAlreadyRunning(RuntimeError):
    pass


def current_time():
    return datetime.now().astimezone().isoformat(timespec="seconds")


@contextmanager
def sync_lock(database_path):
    lock_path = os.path.join(os.path.dirname(database_path), "sync.lock")
    with open(lock_path, "a", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SyncAlreadyRunning("已有同步任务正在执行") from error
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def create_ecs_client(account, region_id):
    client_config = open_api_models.Config(
        access_key_id=account.access_key_id,
        access_key_secret=account.access_key_secret,
    )
    client_config.endpoint = f"ecs.{region_id}.aliyuncs.com"
    return EcsClient(client_config)


def create_rds_client(account):
    client_config = open_api_models.Config(
        access_key_id=account.access_key_id,
        access_key_secret=account.access_key_secret,
    )
    client_config.endpoint = "rds.aliyuncs.com"
    return RdsClient(client_config)


def resolve_target_ips(config):
    target_count = sum(
        len(account.security_groups) + len(account.rds_instances)
        for account in config.accounts
    )
    if not target_count:
        raise RuntimeError("没有配置任何安全组或 RDS 实例")

    settings = config.settings
    check_location = bool(settings.allowed_country or settings.allowed_region)
    locations = get_public_ips(check_location, settings.ipinfo_token)
    for ip, country, region in locations:
        if not check_location:
            print(f"当前公网 IP: {ip}，未配置地域限制")
            continue
        print(f"当前公网 IP: {ip}，位置: {country}/{region}")
        if (
            settings.allowed_country
            and country.strip().casefold() != settings.allowed_country.casefold()
        ) or (
            settings.allowed_region
            and region.strip().casefold() != settings.allowed_region.casefold()
        ):
            raise RuntimeError(
                "当前 IP 不符合地域限制: "
                f"{settings.allowed_country or '*'}/"
                f"{settings.allowed_region or '*'}"
            )

    detected_ips = sorted(ip for ip, _, _ in locations)
    target_ips = sorted(set(detected_ips).union(config.additional_ips))
    return detected_ips, target_ips


def format_resource_result(account, resource_type, resource_id, changes=None, error=None):
    if error is not None:
        return {
            "account_name": account.name,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "success": False,
            "action": "failed",
            "message": str(error),
            "added_ips": [],
            "removed_ips": [],
        }

    added_ips = sorted(set(changes["added_ips"]))
    removed_ips = sorted(set(changes["removed_ips"]))
    parts = []
    if added_ips:
        parts.append("新增 " + ", ".join(added_ips))
    if removed_ips:
        parts.append("删除 " + ", ".join(removed_ips))
    return {
        "account_name": account.name,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "success": True,
        "action": "changed" if parts else "unchanged",
        "message": "；".join(parts) if parts else "无需变更",
        "added_ips": added_ips,
        "removed_ips": removed_ips,
    }


def process_resources(config, target_ips, dry_run=False, accounts=None):
    settings = config.settings
    resources = []
    selected_accounts = accounts if accounts is not None else config.accounts
    for account in selected_accounts:
        for region_id, security_group_id in account.security_groups:
            resource_id = f"{region_id}:{security_group_id}"
            try:
                changes = sync_ecs_group(
                    create_ecs_client(account, region_id),
                    region_id,
                    security_group_id,
                    target_ips,
                    settings.ecs_rule_description,
                    settings.keep_history,
                    dry_run,
                )
                if changes is None:
                    changes = {"added_ips": [], "removed_ips": []}
                resources.append(
                    format_resource_result(account, "ECS", resource_id, changes)
                )
                print(f"已处理安全组: {account.name}/{resource_id}")
            except Exception as error:
                resources.append(
                    format_resource_result(account, "ECS", resource_id, error=error)
                )
                print(
                    f"安全组处理失败，继续下一个目标: "
                    f"{account.name}/{resource_id}: {error}"
                )

        if account.rds_instances:
            try:
                rds_client = create_rds_client(account)
            except Exception as error:
                for instance_id in account.rds_instances:
                    resources.append(
                        format_resource_result(
                            account, "RDS", instance_id, error=error
                        )
                    )
                continue
            for instance_id in account.rds_instances:
                try:
                    changes = sync_rds_instance(
                        rds_client,
                        instance_id,
                        target_ips,
                        settings.rds_whitelist_name,
                        settings.keep_history,
                        dry_run,
                    )
                    if changes is None:
                        changes = {"added_ips": [], "removed_ips": []}
                    resources.append(
                        format_resource_result(account, "RDS", instance_id, changes)
                    )
                    print(f"已处理 RDS 白名单: {account.name}/{instance_id}")
                except Exception as error:
                    resources.append(
                        format_resource_result(
                            account, "RDS", instance_id, error=error
                        )
                    )
                    print(
                        f"RDS 处理失败，继续下一个目标: "
                        f"{account.name}/{instance_id}: {error}"
                    )
    return resources


def preview_sync(database):
    with sync_lock(database.path):
        config = database.load_config()
        detected_ips, target_ips = resolve_target_ips(config)
        resources = process_resources(config, target_ips, dry_run=True)
        return {
            "detected_ips": detected_ips,
            "target_ips": target_ips,
            "success": all(resource["success"] for resource in resources),
            "resources": resources,
        }


def check_account_connection(database, account_id):
    config = database.load_config()
    account = next((item for item in config.accounts if item.id == account_id), None)
    if account is None:
        raise RuntimeError("账号不存在")
    if not account.security_groups and not account.rds_instances:
        return {
            "success": False,
            "message": "请先为账号配置至少一个 ECS 安全组或 RDS 实例",
            "resources": [],
        }
    state = database.get_runtime_state()
    target_ips = [
        item.strip() for item in state["last_ips"].split(",") if item.strip()
    ]
    resources = process_resources(
        config, target_ips, dry_run=True, accounts=(account,)
    )
    for resource in resources:
        if resource["success"]:
            resource["action"] = "checked"
            resource["message"] = "凭证有效，资源读取正常"
    success = all(resource["success"] for resource in resources)
    return {
        "success": success,
        "message": "连接及资源读取正常" if success else "部分资源检查失败",
        "resources": resources,
    }


def sync_once(database):
    started_at = current_time()
    detected_ips = []
    target_ips = []
    resources = []
    with sync_lock(database.path):
        try:
            config = database.load_config()
            settings = config.settings
            detected_ips, target_ips = resolve_target_ips(config)
            cached_ips = ",".join(target_ips)
            state = database.get_runtime_state()
            old_ips = state["last_ips"]
            ips_changed = old_ips != cached_ips
            if not ips_changed:
                print("IP 未变化，继续校验云端配置")

            resources = process_resources(config, target_ips)
            failures = [resource for resource in resources if not resource["success"]]
            if failures:
                raise RuntimeError(
                    f"本轮有 {len(failures)} 个目标同步失败: "
                    + "；".join(
                        f"{item['resource_type']} {item['account_name']}/"
                        f"{item['resource_id']}: {item['message']}"
                        for item in failures
                    )
                )

            finished_at = current_time()
            database.record_success(cached_ips, finished_at)
            message = "同步成功"
            if ips_changed and settings.feishu_webhook_url:
                try:
                    notify_ip_change(settings.feishu_webhook_url, old_ips, cached_ips)
                    print("已发送飞书 IP 变更通知")
                except Exception as error:
                    message = f"同步成功；飞书通知失败: {error}"
                    print(f"飞书通知失败: {error}")
            database.add_sync_run(
                started_at,
                finished_at,
                ",".join(detected_ips),
                cached_ips,
                True,
                message,
                resources,
            )
            return {
                "detected_ips": detected_ips,
                "target_ips": target_ips,
                "message": message,
                "resources": resources,
            }
        except Exception as error:
            finished_at = current_time()
            database.record_error(str(error))
            database.add_sync_run(
                started_at,
                finished_at,
                ",".join(detected_ips),
                ",".join(target_ips),
                False,
                str(error),
                resources,
            )
            raise
