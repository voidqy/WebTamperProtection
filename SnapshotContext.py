import os
import threading
import time

from logger import logger


class SnapshotContext:
    """快照创建上下文管理器"""

    def __init__(self, protector):
        self.protector = protector
        self.results = []  # 收集的结果 (rel_path, hash, file_stat)
        self.pending_tasks = {}  # 未完成任务 (file_path, rel_path)
        self.lock = threading.Lock()

    def __enter__(self):
        """进入上下文"""
        # 设置快照模式并注册处理函数
        self.protector.callback_router.set_mode("snapshot", self.handle_result)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文"""
        # 恢复默认模式
        self.protector.callback_router.set_mode("default")

        if exc_type:
            logger.error(f"快照创建异常: {exc_val}")
            # 清理未完成任务
            with self.lock:
                self.pending_tasks.clear()

    def submit_task(self, file_path, rel_path):
        """提交任务并记录相关信息"""
        with self.lock:
            self.pending_tasks[file_path] = rel_path
        self.protector.hash_task_queue.put(file_path)

    def handle_result(self, file_path, result):
        """处理哈希结果（回调函数）"""

        with self.lock:
            rel_path = self.pending_tasks.pop(file_path, None)

        if rel_path is None:
            logger.warning(f"收到未提交任务的结果: {file_path}")
            return

        try:
            # 取得文件属性
            file_stat = os.stat(file_path)
        except Exception as e:
            logger.error(f"处理结果失败: {file_path} - {str(e)}")
            file_stat = None

        self.results.append((rel_path, result, file_stat))

    def wait_for_completion(self, total_tasks):
        """等待所有任务完成"""
        logger.info(f"等待 {total_tasks} 个任务完成...")
        start_time = time.time()
        last_reported = start_time

        while True:
            # 检查超时
            current_time = time.time()
            elapsed = current_time - start_time
            if elapsed > self.protector.config.get('base.snapshot_timeout'):
                logger.error(f"快照创建超时 ({elapsed:.1f}秒)")
                break

            # 定期报告进度
            if current_time - last_reported > 5.0:
                completed = len(self.results)
                remaining = total_tasks - completed
                logger.info(
                    f"快照进度: {completed}/{total_tasks} "
                    f"({completed / total_tasks:.1%}), "
                    f"剩余: {remaining}"
                )
                last_reported = current_time

            # 检查是否完成
            with self.lock:
                pending_count = len(self.pending_tasks)

            if pending_count == 0:
                logger.info("所有任务已完成")
                break

            # 等待一段时间
            time.sleep(0.5)

        # 报告未完成任务
        with self.lock:
            if self.pending_tasks:
                logger.warning(f"{len(self.pending_tasks)} 个任务未完成")
