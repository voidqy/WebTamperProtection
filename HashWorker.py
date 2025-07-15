import hashlib
import os
import queue
import threading
import time
import zlib

from logger import logger


class HashWorker(threading.Thread):
    """哈希计算工作线程"""

    def __init__(self, task_queue, callback_router, config):
        super().__init__(daemon=True)
        self.callback_router = callback_router
        self.task_queue = task_queue
        self.config = config
        self.running = True

    def run(self):
        logger.info(f"哈希工作线程启动: {self.name}")
        while self.running:
            try:
                # 获取任务
                file_path = self.task_queue.get(timeout=1.0)

                if file_path is None:
                    logger.info(f"工作线程停止: {self.name}")
                    break

                # 计算哈希
                file_hash = self.calculate_hash(file_path)

                # 使用回调路由器处理结果
                self.callback_router(file_path, file_hash)

                # 标记任务完成
                self.task_queue.task_done()

            except queue.Empty:
                continue

    def calculate_hash(self, file_path):

        start_time = time.time()

        """高效计算文件哈希"""
        if not os.path.exists(file_path):
            return None

        file_size = os.path.getsize(file_path)

        # 使用CRC32进行快速初步检查
        crc_value = 0
        if self.config.get('optimize.use_crc32', True):
            try:
                with open(file_path, 'rb') as f:
                    crc_value = zlib.crc32(f.read(4096)) & 0xFFFFFFFF
            except Exception:
                pass

        # 对于小文件，直接计算完整哈希
        if file_size < self.config.get('optimize.max_file_size', 1048576):
            result = self._full_hash(file_path)
        else:
            # 大文件使用分块哈希
            result = self._chunked_hash(file_path, crc_value, file_size)

        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"哈希计算完成: {file_path} 文件, 耗时 {elapsed} 毫秒")

        return result

    @staticmethod
    def _sync_calculate(file_path, callback_router, config) -> tuple[str, str] | None:
        """同步计算文件哈希（"""
        worker = HashWorker(
            task_queue=None,
            callback_router=callback_router,
            config=config
        )
        return worker.calculate_hash(file_path)

    def _full_hash(self, file_path):
        """计算小文件的完整哈希"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(self.config.get('optimize.hash_chunk_size')):
                    hash_sha256.update(chunk)
            return ("full", hash_sha256.hexdigest())
        except Exception as e:
            logger.error(f"完整哈希计算错误 {file_path}: {str(e)}")
            return None

    def _chunked_hash(self, file_path, crc_value, file_size):
        """计算大文件的分块哈希"""
        try:
            # 计算文件关键区域的哈希
            with open(file_path, "rb") as f:
                # 读取文件头
                f.seek(0)
                head_chunk = f.read(4096)

                # 读取文件尾
                f.seek(max(0, file_size - 4096))
                tail_chunk = f.read(4096)

                # 读取中间随机块（如果文件足够大）
                mid_hash = ""
                if file_size > 8192:
                    f.seek(file_size // 2)
                    mid_chunk = f.read(4096)
                    mid_hash = hashlib.sha256(mid_chunk).hexdigest()[:16]

                # 组合关键区域哈希
                combined = head_chunk + tail_chunk
                hash_value = hashlib.sha256(combined).hexdigest()

                # 包含CRC和中间块信息
                return ("chunked", f"{crc_value:08x}-{mid_hash}-{hash_value}")
        except Exception as e:
            logger.error(f"分块哈希计算错误 {file_path}: {str(e)}")
            return None
