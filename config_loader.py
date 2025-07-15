import hashlib
import os
import yaml
from logger import logger
from pathlib import Path
from threading import Lock, RLock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class ConfigLoader:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._data = {}
        self._lock = Lock()
        self._last_modified = 0
        self._callbacks = []
        self.observer = None

        # 回调
        self._cb_lock = RLock()
        self._file_hash = None
        self._active_config_version = 0  # 配置版本号

        self.load_config()
        self.start_watchdog()

    def load_config(self):
        """加载或重载配置"""
        try:
            with self._lock:

                # 计算文件哈希防止重复加载
                raw_data = self.config_path.read_bytes()
                current_hash = hashlib.md5(raw_data).hexdigest()

                if current_hash == self._file_hash:
                    return

                # current_modified = self.config_path.stat().st_mtime
                # if current_modified > self._last_modified:
                new_config = yaml.safe_load(raw_data.decode('utf-8'))
                prev_version = self._active_config_version
                self._data = self._replace_env_vars(new_config)
                self._file_hash = current_hash
                self._active_config_version += 1

                # 触发回调
                self._execute_callbacks(prev_version)
                logger.info(f"配置已更新至版本 {self._active_config_version}")

        except Exception as e:
            logger.error(f"Config load failed: {str(e)}")

    def _replace_env_vars(self, config: dict) -> dict:
        """递归替换环境变量"""
        # 实现前文提到的环境变量替换逻辑
        # 这里简化为直接替换 ${VAR} 格式
        import re
        pattern = re.compile(r'\$\{([^}]+)\}')

        def _replace(obj):
            if isinstance(obj, dict):
                return {k: _replace(v) for k, v in obj.items()}
            elif isinstance(obj, str):
                matches = pattern.findall(obj)

                for var_name in matches:
                    env_value = os.getenv(var_name)
                    obj = obj.replace(r'${' + var_name + '}', env_value)

                return obj
            return obj

        return _replace(config)

    def _execute_callbacks(self, prev_version: int):
        """执行所有注册的回调"""
        with self._cb_lock:
            for callback, opts in self._callbacks:
                try:
                    callback(
                        old_version=prev_version,
                        new_version=self._active_config_version,
                        configs=self._data,
                        **opts
                    )
                except Exception as e:
                    logger.error(f"回调执行失败: {str(e)}")

    def start_watchdog(self):
        """启动文件监视"""
        event_handler = _ConfigHandler(self.load_config)
        self.observer = Observer()
        self.observer.schedule(
            event_handler,
            path=str(self.config_path.parent),
            recursive=False
        )
        self.observer.start()

    def get(self, key: str, default=None):
        """线程安全获取配置"""
        with self._lock:
            keys = key.split('.')
            value = self._data
            for k in keys:
                value = value.get(k)
                if value is None:
                    return default
            return value

    def add_update_callback(self, callback, **kwargs):
        """添加配置更新回调函数"""
        with self._lock:
            self._callbacks.append((callback, kwargs))
            logger.info(f"新增配置回调：{callback.__name__}")


class _ConfigHandler(FileSystemEventHandler):
    """私有文件处理器类"""

    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if event.src_path.endswith('.yaml'):
            self.callback()
