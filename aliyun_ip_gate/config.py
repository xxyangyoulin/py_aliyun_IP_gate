from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    check_interval_seconds: int
    allowed_country: str
    allowed_region: str
    ipinfo_token: str
    ecs_rule_description: str
    rds_whitelist_name: str
    feishu_webhook_url: str
    keep_history: bool


@dataclass(frozen=True)
class Account:
    id: int
    name: str
    access_key_id: str
    access_key_secret: str
    security_groups: tuple
    rds_instances: tuple


@dataclass(frozen=True)
class Config:
    settings: Settings
    accounts: tuple
    additional_ips: tuple
