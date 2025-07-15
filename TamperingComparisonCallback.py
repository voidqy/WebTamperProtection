from logger import logger


class TamperingComparisonCallback:
    """实时监控回调处理器"""

    def __init__(self, protector):
        self.protector = protector
        self.last_hashes = {}

    def __call__(self, file_path, result):
        """监控回调函数"""
        try:
            rel_path = self.protector.get_relative_path(file_path)
            if not rel_path:
                return

            # 获取当前哈希
            current_hash = result[1] if result and result[0] != "error" else None

            # 与上次结果比较
            if rel_path in self.last_hashes:
                last_hash = self.last_hashes[rel_path]
                logger.debug(
                    f"rel_path：{rel_path} - current_hash: {current_hash} - self.last_hashes: {self.last_hashes}")
                if current_hash != last_hash:
                    self.protector.handle_tamper(rel_path, "last哈希变化")

            # 与快照比较
            if rel_path in self.protector.snapshot:
                snapshot_hash = self.protector.snapshot[rel_path]["hash"][1]
                logger.debug(
                    f"rel_path：{rel_path} - current_hash: {current_hash} - snapshot_hash: {snapshot_hash}")
                if current_hash != snapshot_hash:
                    self.protector.handle_tamper(rel_path, "快照不匹配")

                # 记录当前哈希
                self.last_hashes[rel_path] = snapshot_hash

        except Exception as e:
            logger.error(f"监控回调错误: {str(e)}")
