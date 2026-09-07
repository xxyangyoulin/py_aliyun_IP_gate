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


def sync_once(database):
    started_at = current_time()
    detected_ips = []
    target_ips = []
    with sync_lock(database.path):
        try:
            config = database.load_config()
            settings = config.settings
            target_count = sum(
                len(account.security_groups) + len(account.rds_instances)
                for account in config.accounts
            )
            if not target_count:
                raise RuntimeError("没有配置任何安全组或 RDS 实例")
            check_location = bool(settings.allowed_country or settings.allowed_region)
            locations = get_public_ips(check_location, settings.ipinfo_token)
            for ip, country, region in locations:
                if not check_location:
                    print(f"当前公网 IP: {ip}，未配置地域限制")
                    continue
                print(f"当前公网 IP: {ip}，位置: {country}/{region}")
                if (
                    settings.allowed_country
                    and country.strip().casefold()
                    != settings.allowed_country.casefold()
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
            cached_ips = ",".join(target_ips)
            state = database.get_runtime_state()
            old_ips = state["last_ips"]
            ips_changed = old_ips != cached_ips
            if not ips_changed:
                print("IP 未变化，继续校验云端配置")

            failures = []
            for account in config.accounts:
                for region_id, security_group_id in account.security_groups:
                    try:
                        client_config = open_api_models.Config(
                            access_key_id=account.access_key_id,
                            access_key_secret=account.access_key_secret,
                        )
                        client_config.endpoint = f"ecs.{region_id}.aliyuncs.com"
                        sync_ecs_group(
                            EcsClient(client_config),
                            region_id,
                            security_group_id,
                            target_ips,
                            settings.ecs_rule_description,
                            settings.keep_history,
                        )
                        print(
                            f"已同步安全组: {account.name}/{region_id}/"
                            f"{security_group_id}"
                        )
                    except Exception as error:
                        failures.append(
                            f"安全组 {account.name}/{region_id}:{security_group_id}: {error}"
                        )
                        print(f"安全组同步失败，继续处理下一个目标: {failures[-1]}")

                if account.rds_instances:
                    client_config = open_api_models.Config(
                        access_key_id=account.access_key_id,
                        access_key_secret=account.access_key_secret,
                    )
                    client_config.endpoint = "rds.aliyuncs.com"
                    rds_client = RdsClient(client_config)
                    for instance_id in account.rds_instances:
                        try:
                            sync_rds_instance(
                                rds_client,
                                instance_id,
                                target_ips,
                                settings.rds_whitelist_name,
                                settings.keep_history,
                            )
                            print(
                                f"已同步 RDS 白名单: {account.name}/{instance_id}/"
                                f"{settings.rds_whitelist_name}"
                            )
                        except Exception as error:
                            failures.append(
                                f"RDS {account.name}/{instance_id}: {error}"
                            )
                            print(f"RDS 同步失败，继续处理下一个目标: {failures[-1]}")

            if failures:
                raise RuntimeError(
                    f"本轮有 {len(failures)} 个目标同步失败: "
                    + "；".join(failures)
                )

            finished_at = current_time()
            database.record_success(cached_ips, finished_at)
            message = "同步成功"
            if ips_changed and settings.feishu_webhook_url:
                try:
                    notify_ip_change(
                        settings.feishu_webhook_url, old_ips, cached_ips
                    )
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
            )
            return {
                "detected_ips": detected_ips,
                "target_ips": target_ips,
                "message": message,
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
            )
            raise
