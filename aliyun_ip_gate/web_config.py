from dataclasses import dataclass

from dotenv import dotenv_values


@dataclass(frozen=True)
class WebConfig:
    port: int
    access_token: str


def load_web_config(path):
    values = dotenv_values(path)
    try:
        port = int(values.get("WEB_PORT") or "17321")
    except ValueError as error:
        raise ValueError("WEB_PORT 必须是整数") from error
    if not 1 <= port <= 65535:
        raise ValueError("WEB_PORT 必须在 1 到 65535 之间")
    return WebConfig(
        port=port,
        access_token=(values.get("WEB_ACCESS_TOKEN") or "").strip(),
    )
