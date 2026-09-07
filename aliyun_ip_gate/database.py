import os
import secrets
import sqlite3

from .config import Account, Config, Settings


class Database:
    def __init__(self, path):
        self.path = path

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    check_interval_seconds INTEGER NOT NULL,
                    allowed_country TEXT NOT NULL,
                    allowed_region TEXT NOT NULL,
                    ipinfo_token TEXT NOT NULL,
                    ecs_rule_description TEXT NOT NULL,
                    rds_whitelist_name TEXT NOT NULL,
                    feishu_webhook_url TEXT NOT NULL,
                    keep_history INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    access_key_id TEXT NOT NULL,
                    access_key_secret TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS ecs_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    region_id TEXT NOT NULL,
                    security_group_id TEXT NOT NULL,
                    UNIQUE(account_id, region_id, security_group_id)
                );

                CREATE TABLE IF NOT EXISTS rds_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    instance_id TEXT NOT NULL,
                    UNIQUE(account_id, instance_id)
                );

                CREATE TABLE IF NOT EXISTS additional_ips (
                    ip TEXT PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS runtime_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_ips TEXT NOT NULL,
                    last_success_at TEXT,
                    last_error TEXT NOT NULL,
                    worker_started_at TEXT,
                    worker_heartbeat_at TEXT,
                    worker_next_run_at TEXT,
                    worker_active INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS sync_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    detected_ips TEXT NOT NULL,
                    target_ips TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    message TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sync_run_resources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL REFERENCES sync_runs(id) ON DELETE CASCADE,
                    account_name TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    message TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sync_run_resources_run_id
                ON sync_run_resources(run_id);

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            runtime_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(runtime_state)")
            }
            for name, definition in (
                ("worker_started_at", "TEXT"),
                ("worker_heartbeat_at", "TEXT"),
                ("worker_next_run_at", "TEXT"),
                ("worker_active", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in runtime_columns:
                    connection.execute(
                        f"ALTER TABLE runtime_state ADD COLUMN {name} {definition}"
                    )
            connection.execute("PRAGMA user_version = 2")
            connection.execute(
                """
                INSERT OR IGNORE INTO settings VALUES
                (1, 600, '', '', '', '自动同步', 'aliyun_sync_local_ip', '', 0)
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO runtime_state
                    (id, last_ips, last_success_at, last_error)
                VALUES (1, '', NULL, '')
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('web_secret', ?)",
                (secrets.token_urlsafe(32),),
            )
        os.chmod(self.path, 0o600)

    def get_settings(self):
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        return Settings(
            check_interval_seconds=row["check_interval_seconds"],
            allowed_country=row["allowed_country"],
            allowed_region=row["allowed_region"],
            ipinfo_token=row["ipinfo_token"],
            ecs_rule_description=row["ecs_rule_description"],
            rds_whitelist_name=row["rds_whitelist_name"],
            feishu_webhook_url=row["feishu_webhook_url"],
            keep_history=bool(row["keep_history"]),
        )

    def save_settings(self, settings):
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE settings SET
                    check_interval_seconds = ?, allowed_country = ?, allowed_region = ?,
                    ipinfo_token = ?, ecs_rule_description = ?, rds_whitelist_name = ?,
                    feishu_webhook_url = ?, keep_history = ?
                WHERE id = 1
                """,
                (
                    settings.check_interval_seconds,
                    settings.allowed_country,
                    settings.allowed_region,
                    settings.ipinfo_token,
                    settings.ecs_rule_description,
                    settings.rds_whitelist_name,
                    settings.feishu_webhook_url,
                    int(settings.keep_history),
                ),
            )

    def list_accounts(self, include_disabled=True):
        query = "SELECT * FROM accounts"
        if not include_disabled:
            query += " WHERE enabled = 1"
        query += " ORDER BY name COLLATE NOCASE"
        with self.connect() as connection:
            rows = connection.execute(query).fetchall()
            accounts = []
            for row in rows:
                security_groups = connection.execute(
                    """
                    SELECT region_id, security_group_id FROM ecs_targets
                    WHERE account_id = ? ORDER BY region_id, security_group_id
                    """,
                    (row["id"],),
                ).fetchall()
                rds_instances = connection.execute(
                    """
                    SELECT instance_id FROM rds_targets
                    WHERE account_id = ? ORDER BY instance_id
                    """,
                    (row["id"],),
                ).fetchall()
                accounts.append(
                    Account(
                        id=row["id"],
                        name=row["name"],
                        access_key_id=row["access_key_id"],
                        access_key_secret=row["access_key_secret"],
                        security_groups=tuple(
                            (target["region_id"], target["security_group_id"])
                            for target in security_groups
                        ),
                        rds_instances=tuple(
                            target["instance_id"] for target in rds_instances
                        ),
                    )
                )
        return accounts

    def get_account(self, account_id):
        return next(
            (account for account in self.list_accounts() if account.id == account_id),
            None,
        )

    def save_account(
        self,
        account_id,
        name,
        access_key_id,
        access_key_secret,
        security_groups,
        rds_instances,
    ):
        with self.connect() as connection:
            if account_id is None:
                cursor = connection.execute(
                    """
                    INSERT INTO accounts (name, access_key_id, access_key_secret)
                    VALUES (?, ?, ?)
                    """,
                    (name, access_key_id, access_key_secret),
                )
                account_id = cursor.lastrowid
            else:
                connection.execute(
                    """
                    UPDATE accounts SET name = ?, access_key_id = ?, access_key_secret = ?
                    WHERE id = ?
                    """,
                    (name, access_key_id, access_key_secret, account_id),
                )
                connection.execute(
                    "DELETE FROM ecs_targets WHERE account_id = ?", (account_id,)
                )
                connection.execute(
                    "DELETE FROM rds_targets WHERE account_id = ?", (account_id,)
                )
            connection.executemany(
                """
                INSERT INTO ecs_targets (account_id, region_id, security_group_id)
                VALUES (?, ?, ?)
                """,
                (
                    (account_id, region_id, security_group_id)
                    for region_id, security_group_id in security_groups
                ),
            )
            connection.executemany(
                "INSERT INTO rds_targets (account_id, instance_id) VALUES (?, ?)",
                ((account_id, instance_id) for instance_id in rds_instances),
            )
        return account_id

    def delete_account(self, account_id):
        with self.connect() as connection:
            connection.execute("DELETE FROM accounts WHERE id = ?", (account_id,))

    def get_additional_ips(self):
        with self.connect() as connection:
            rows = connection.execute("SELECT ip FROM additional_ips ORDER BY ip").fetchall()
        return tuple(row["ip"] for row in rows)

    def set_additional_ips(self, ips):
        with self.connect() as connection:
            connection.execute("DELETE FROM additional_ips")
            connection.executemany(
                "INSERT INTO additional_ips (ip) VALUES (?)", ((ip,) for ip in ips)
            )

    def load_config(self):
        return Config(
            settings=self.get_settings(),
            accounts=tuple(self.list_accounts(include_disabled=False)),
            additional_ips=self.get_additional_ips(),
        )

    def has_accounts(self):
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM accounts").fetchone()
        return bool(row["count"])

    def import_configuration(self, settings, accounts, additional_ips, last_ips):
        with self.connect() as connection:
            connection.execute("DELETE FROM accounts")
            connection.execute("DELETE FROM additional_ips")
            connection.execute(
                """
                UPDATE settings SET
                    check_interval_seconds = ?, allowed_country = ?, allowed_region = ?,
                    ipinfo_token = ?, ecs_rule_description = ?, rds_whitelist_name = ?,
                    feishu_webhook_url = ?, keep_history = ?
                WHERE id = 1
                """,
                (
                    settings.check_interval_seconds,
                    settings.allowed_country,
                    settings.allowed_region,
                    settings.ipinfo_token,
                    settings.ecs_rule_description,
                    settings.rds_whitelist_name,
                    settings.feishu_webhook_url,
                    int(settings.keep_history),
                ),
            )
            for account in accounts:
                cursor = connection.execute(
                    """
                    INSERT INTO accounts (name, access_key_id, access_key_secret)
                    VALUES (?, ?, ?)
                    """,
                    (
                        account["name"],
                        account["access_key_id"],
                        account["access_key_secret"],
                    ),
                )
                account_id = cursor.lastrowid
                connection.executemany(
                    """
                    INSERT INTO ecs_targets
                        (account_id, region_id, security_group_id)
                    VALUES (?, ?, ?)
                    """,
                    (
                        (account_id, region_id, security_group_id)
                        for region_id, security_group_id in account["security_groups"]
                    ),
                )
                connection.executemany(
                    "INSERT INTO rds_targets (account_id, instance_id) VALUES (?, ?)",
                    (
                        (account_id, instance_id)
                        for instance_id in account["rds_instances"]
                    ),
                )
            connection.executemany(
                "INSERT INTO additional_ips (ip) VALUES (?)",
                ((ip,) for ip in additional_ips),
            )
            connection.execute(
                "UPDATE runtime_state SET last_ips = ? WHERE id = 1", (last_ips,)
            )
            connection.execute(
                """
                INSERT INTO metadata (key, value) VALUES ('env_imported', '1')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """
            )

    def get_runtime_state(self):
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM runtime_state WHERE id = 1"
            ).fetchone()

    def record_success(self, ips, finished_at):
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE runtime_state
                SET last_ips = ?, last_success_at = ?, last_error = '' WHERE id = 1
                """,
                (ips, finished_at),
            )

    def record_error(self, error):
        with self.connect() as connection:
            connection.execute(
                "UPDATE runtime_state SET last_error = ? WHERE id = 1", (error,)
            )

    def record_worker_started(self, started_at):
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE runtime_state SET worker_started_at = ?,
                    worker_heartbeat_at = ?, worker_next_run_at = NULL,
                    worker_active = 1 WHERE id = 1
                """,
                (started_at, started_at),
            )

    def record_worker_schedule(self, heartbeat_at, next_run_at):
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE runtime_state SET worker_heartbeat_at = ?,
                    worker_next_run_at = ?, worker_active = 1 WHERE id = 1
                """,
                (heartbeat_at, next_run_at),
            )

    def record_worker_stopped(self, stopped_at):
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE runtime_state SET worker_heartbeat_at = ?,
                    worker_next_run_at = NULL, worker_active = 0 WHERE id = 1
                """,
                (stopped_at,),
            )

    def add_sync_run(
        self,
        started_at,
        finished_at,
        detected_ips,
        target_ips,
        success,
        message,
        resources=(),
    ):
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO sync_runs
                    (started_at, finished_at, detected_ips, target_ips, success, message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    started_at,
                    finished_at,
                    detected_ips,
                    target_ips,
                    int(success),
                    message,
                ),
            )
            connection.executemany(
                """
                INSERT INTO sync_run_resources
                    (run_id, account_name, resource_type, resource_id,
                     success, action, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        cursor.lastrowid,
                        resource["account_name"],
                        resource["resource_type"],
                        resource["resource_id"],
                        int(resource["success"]),
                        resource["action"],
                        resource["message"],
                    )
                    for resource in resources
                ),
            )
            return cursor.lastrowid

    def list_sync_runs(self, limit=100):
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sync_runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            runs = [dict(row) for row in rows]
            if not runs:
                return runs
            placeholders = ",".join("?" for _ in runs)
            resource_rows = connection.execute(
                f"""
                SELECT * FROM sync_run_resources
                WHERE run_id IN ({placeholders}) ORDER BY id
                """,
                tuple(run["id"] for run in runs),
            ).fetchall()
        resources_by_run = {}
        for row in resource_rows:
            resources_by_run.setdefault(row["run_id"], []).append(dict(row))
        for run in runs:
            run["resources"] = resources_by_run.get(run["id"], [])
        return runs

    def count_sync_runs(self):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM sync_runs"
            ).fetchone()
        return row["count"]

    def clear_sync_runs(self):
        with self.connect() as connection:
            connection.execute("DELETE FROM sync_runs")

    def get_web_secret(self):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'web_secret'"
            ).fetchone()
        return row["value"]
