# Aliyun IP Gate

定时获取本机公网 IPv4，并同步到多个阿里云账号下的 ECS 安全组和 RDS IP 白名单。支持可选的国家、省份限制；未配置时不限制地域。

## 安装

需要 Python 3.9 或更高版本。

```bash
python -m pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

## RAM 权限

创建自定义策略并授权给 AccessKey 所属的 RAM 用户，授权范围选择“整个云账号”：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeSecurityGroupAttribute",
        "ecs:AuthorizeSecurityGroup",
        "ecs:RevokeSecurityGroup",
        "rds:DescribeDBInstanceIPArrayList",
        "rds:ModifySecurityIps"
      ],
      "Resource": "*"
    }
  ]
}
```

只使用 ECS 或 RDS 时，可以删除另一类权限。

## 配置

所有配置位于 `.env`，完整示例和注释见 `.env.example`。

```dotenv
ALIYUN_ACCOUNTS=PRIMARY,SECONDARY

ALIYUN_PRIMARY_ACCESS_KEY_ID=your_access_key_id
ALIYUN_PRIMARY_ACCESS_KEY_SECRET=your_access_key_secret
ALIYUN_PRIMARY_SECURITY_GROUPS=cn-chengdu:sg-example1,cn-hangzhou:sg-example2
ALIYUN_PRIMARY_RDS_INSTANCES=rm-example1

ALIYUN_SECONDARY_ACCESS_KEY_ID=your_access_key_id
ALIYUN_SECONDARY_ACCESS_KEY_SECRET=your_access_key_secret
ALIYUN_SECONDARY_SECURITY_GROUPS=
ALIYUN_SECONDARY_RDS_INSTANCES=

ALIYUN_ECS_RULE_DESCRIPTION=自动同步
ALIYUN_RDS_WHITELIST_NAME=aliyun_sync_local_ip

IP_ALLOWED_COUNTRY=CN
IP_ALLOWED_REGION=Guizhou
CHECK_INTERVAL_SECONDS=600
IPINFO_TOKEN=
IP_CACHE_FILE=.last_ip
FEISHU_WEBHOOK_URL=
```

- `SECURITY_GROUPS` 格式为 `地域ID:安全组ID`，多个目标用英文逗号分隔。
- `RDS_INSTANCES` 填写实例 ID，多个目标用英文逗号分隔。
- 两项地域配置可分别留空；都为空或不存在时不限制地域。
- 不使用某类目标时，将对应配置留空。
- 配置 `FEISHU_WEBHOOK_URL` 后，本地公网 IP 变更并成功同步时会发送飞书群机器人通知。

## 同步规则

- ECS 规则描述使用 `自动同步:1`、`自动同步:2` 格式，只管理配置前缀及其严格编号规则。
- 安全组没有同步规则时，自动创建 `TCP`、`1/65535`，即 TCP 全端口规则。
- 如需其他协议或端口，先手工创建描述为 `自动同步` 的单 IPv4 模板规则，程序会沿用其规格。
- ECS 通常先创建新规则再删除旧规则；不会删除其他描述的规则。
- RDS 使用独占白名单分组并以覆盖模式同步，禁止使用 `default`。
- IP 不符合地域限制时直接返回，不删除此前同步的 IP。

## 运行

执行一次：

```bash
python main.py --once
```

持续运行：

```bash
python main.py
```

保留 ECS 和 RDS 中的历史 IP，只新增不删除：

```bash
python main.py --once --keep-history
python main.py --keep-history
```

程序按 `CHECK_INTERVAL_SECONDS` 定时检查。只有全部目标同步成功后才更新 `.last_ip`；新增目标或修改配置后，可删除 `.last_ip` 再执行一次。

不要提交 `.env` 或泄露 AccessKey。建议使用专用 RAM 用户。
