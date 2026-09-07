import ipaddress

import requests


def get_public_ips(check_location=True, ipinfo_token=""):
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
            if url.startswith("https://ipinfo.io/") and ipinfo_token:
                headers["Authorization"] = f"Bearer {ipinfo_token}"
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
                if url.startswith("https://ipinfo.io/") and ipinfo_token:
                    headers["Authorization"] = f"Bearer {ipinfo_token}"
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


def parse_additional_ips(value):
    additional_ips = []
    for item in value.split(","):
        if not item.strip():
            continue
        try:
            ip = ipaddress.ip_address(item.strip())
        except ValueError as error:
            raise ValueError(f"额外 IP 不是有效 IPv4 地址: {item.strip()}") from error
        if ip.version != 4:
            raise ValueError(f"额外 IP 不是 IPv4 地址: {item.strip()}")
        additional_ips.append(str(ip))
    return sorted(set(additional_ips))
