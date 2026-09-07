import argparse
import os
import time
from datetime import datetime, timedelta

from .database import Database
from .sync_service import SyncAlreadyRunning, sync_once


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(PROJECT_DIR, "data", "app.db")


def local_time(offset_seconds=0):
    value = datetime.now().astimezone() + timedelta(seconds=offset_seconds)
    return value.isoformat(timespec="seconds")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="执行一次后退出")
    args = parser.parse_args()

    database = Database(DATABASE_PATH)
    database.initialize()
    database.record_worker_started(local_time())
    try:
        while True:
            database.record_worker_schedule(local_time(), None)
            try:
                sync_once(database)
            except SyncAlreadyRunning as error:
                print(error)
            except Exception as error:
                print(f"同步失败: {error}")
            if args.once:
                break
            interval = database.get_settings().check_interval_seconds
            database.record_worker_schedule(local_time(), local_time(interval))
            time.sleep(interval)
    except KeyboardInterrupt:
        print("同步服务已停止")
    finally:
        database.record_worker_stopped(local_time())
