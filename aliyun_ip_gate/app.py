import argparse
import os
import time

from .database import Database
from .sync_service import SyncAlreadyRunning, sync_once


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(PROJECT_DIR, "data", "app.db")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="执行一次后退出")
    args = parser.parse_args()

    database = Database(DATABASE_PATH)
    database.initialize()
    try:
        while True:
            try:
                sync_once(database)
            except SyncAlreadyRunning as error:
                print(error)
            except Exception as error:
                print(f"同步失败: {error}")
            if args.once:
                break
            time.sleep(database.get_settings().check_interval_seconds)
    except KeyboardInterrupt:
        print("同步服务已停止")
