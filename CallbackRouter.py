import threading

from logger import logger


class CallbackRouter:
    """动态回调路由器"""

    def __init__(self, protector):
        self.protector = protector
        self.current_mode = "default"
        self.callbacks = {
            "default": protector.default_result_handler,
            "snapshot": None,
            "monitor": None,
            "custom": None
        }
        self.lock = threading.Lock()

    def __call__(self, file_path, result):
        """路由回调请求"""
        with self.lock:
            callback = self.callbacks.get(self.current_mode)

        if callback:
            try:
                callback(file_path, result)
            except Exception as e:
                logger.error(f"回调执行失败: {str(e)}")

    def set_mode(self, mode, callback=None):
        """设置当前回调模式"""
        with self.lock:
            if mode == "snapshot" and callback is None:
                raise ValueError("快照模式需要指定回调函数")

            self.current_mode = mode
            if callback:
                self.callbacks[mode] = callback

    def get_current_callback(self):
        """获取当前回调函数"""
        with self.lock:
            return self.callbacks.get(self.current_mode)