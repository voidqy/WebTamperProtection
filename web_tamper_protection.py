import hashlib
import json
import logging
import os
import queue
import shutil
import sys
import threading
import time
from datetime import datetime

from watchdog.observers import Observer

from BackupManager import BackupManager
from CallbackRouter import CallbackRouter
from EventProcessor import EventProcessor
from FileMonitor import FileMonitor
from HashWorker import HashWorker
from SnapshotContext import SnapshotContext
from TamperingComparisonCallback import TamperingComparisonCallback
from Alert import Alert
from config import config
from logger import logger


class WebTamperProtector:
    """高性能网页防篡改核心类"""

    def __init__(self):
        self.config = config
        self.event_queue = None
        self.hash_task_queue = None
        self.monitor = None
        self.snapshot = {}
        self.observer = None

        self.event_processors = []
        self.hash_workers = []
        self.running = False
        self.callback_router = CallbackRouter(self)
        self.alert = Alert(self.config)

        self.suspicious_dir = self.config.get('base.suspicious_dir', './suspicious')
        os.makedirs(self.suspicious_dir, exist_ok=True)  # 确保文件夹存在

        # 1. 初始化备份系统
        self.backup_manager = BackupManager(self, self.config)
        if not self.backup_manager.initialize_backup_system():
            raise RuntimeError("备份系统初始化失败")

        # 2. 初始化工作线程池
        self.init_queues_workers()

        # 3. 加载快照（此时工作线程已就绪）
        self.load_snapshot()

        # 4. 启动状态监控
        self.status_monitor = threading.Thread(
            target=self._monitor_system_status,
            daemon=True
        )

        self.status_monitor.start()

    def init_queues_workers(self):

        """初始化工作线程池"""
        logger.info("初始化工作线程...")

        self.hash_task_queue = queue.Queue()
        self.event_queue = queue.Queue()

        # 事件处理器线程
        for i in range(self.config.get('optimize.event_processors', 4)):
            processor = EventProcessor(self, self.event_queue, self.config)
            processor.start()
            self.event_processors.append(processor)
            logger.debug(f"启动事件处理器 #{i}")

        # 哈希计算工作线程
        for i in range(self.config.get('optimize.worker_threads', 4)):
            worker = HashWorker(
                self.hash_task_queue,
                self.callback_router,
                self.config
            )
            worker.start()
            self.hash_workers.append(worker)
            logger.debug(f"启动哈希工作线程 #{i}")

        logger.info(
            f"工作线程初始化完成: {len(self.event_processors)} 事件处理器, {len(self.hash_workers)} 哈希工作线程, 事件处理延迟{self.config.get('optimize.event_process_delay')}(秒) ")

    def calculate_hash(self, file_path):
        """提交哈希计算任务"""
        self.hash_task_queue.put(file_path)

    def _full_hash(self, file_path):
        """同步计算完整哈希（用于验证）"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(self.config.get('optimize.hash_chunk_size', 131072, )):
                    hash_sha256.update(chunk)
            return ("full", hash_sha256.hexdigest())
        except Exception as e:
            logger.error(f"完整哈希计算错误 {file_path}: {str(e)}")
            return None

    def get_relative_path(self, file_path):
        """获取相对于监控目录的路径"""
        try:
            return os.path.relpath(file_path, self.config.get('base.web_dir'))
        except ValueError:
            return None

    def process_event(self, event_type, file_path):
        """处理文件系统事件"""
        rel_path = self.get_relative_path(file_path)
        if not rel_path:
            return

        logger.debug(f"处理事件: {event_type} - {rel_path}")

        if event_type == "deleted":
            # 文件删除
            if rel_path in self.snapshot:
                self.handle_tamper(rel_path, "文件被删除")

        elif event_type == "created":
            # 新文件创建
            if rel_path not in self.snapshot and os.path.exists(file_path):
                result = self.move_suspicious_file(file_path)
                if result == 1:
                    self.alert.alert(f"发现未授权文件: {rel_path}，已移动至可疑文件夹", "篡改检测")
                elif result == 2:
                    self.alert.alert(f"发现未授权文件: {rel_path}，已删除", "篡改检测")
                else:
                    self.alert.alert(f"发现未授权文件: {rel_path}，删除失败", "篡改检测")

        elif event_type == "modified":
            # 文件修改
            if rel_path in self.snapshot and os.path.exists(file_path):
                # 提交哈希检查
                self.calculate_hash(file_path)

    def handle_tamper(self, rel_path, reason):
        """处理篡改事件"""
        logger.warning(f"篡改检测: {reason} - {rel_path}")
        self.alert.alert(f"{reason}: {rel_path}", "篡改检测")
        self.recover_file(rel_path)

    def move_suspicious_file(self, file_path):
        """移动可疑文件"""
        # 生成时间戳
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]  # 精确到毫秒

        # 保留原始文件名和扩展名
        rel_path, ext = os.path.splitext(os.path.basename(file_path))
        new_filename = f"{rel_path}_{timestamp}_{ext}"

        # 构建目标路径
        dest_path = os.path.join(self.suspicious_dir, new_filename)

        try:
            # 移动文件到可疑文件夹
            shutil.move(file_path, dest_path)
            logger.info(f"已移动可疑文件: {file_path} -> {dest_path}")
            return 1
        except Exception as mov_e:
            logger.error(f"移动可疑文件失败: {file_path}, 错误: {str(mov_e)}，尝试删除…")
            try:
                os.remove(file_path)
                logger.error(f"已删除可疑文件: {file_path}")
                return 2
            except Exception as del_e:
                # 删除失败的情况
                logger.error(f"删除文件失败: {file_path}, 错误: {str(del_e)}")
                return 3

    def create_snapshot(self):

        """安全创建快照（确保工作线程已启动）"""
        logger.info("创建新快照...")
        start_time = time.time()

        # 1. 创建快照数据结构
        new_snapshot = {}
        snapshot_errors = 0
        web_dir = self.config.get('base.web_dir')

        # 2. 使用上下文管理器管理结果收集
        with SnapshotContext(self) as context:

            # 3. 提交所有哈希任务
            file_count = 0
            for root, _, files in os.walk(web_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = self.get_relative_path(file_path)

                    if os.path.isfile(file_path):
                        # 提交任务并记录相对路径
                        context.submit_task(file_path, rel_path)
                        file_count += 1

            logger.info(f"提交 {file_count} 个文件进行哈希计算")

            # 4. 等待所有任务完成并收集结果
            context.wait_for_completion(file_count)

            # 5. 处理收集到的结果
            for rel_path, file_hash, file_stat in context.results:
                if file_hash:  # 有效结果
                    new_snapshot[rel_path] = {
                        "hash": file_hash,
                        "size": file_stat.st_size,
                        "mtime": file_stat.st_mtime
                    }
                else:  # 错误记录
                    snapshot_errors += 1

        # 6. 更新并保存快照
        self.snapshot = new_snapshot
        self.save_snapshot()
        elapsed = time.time() - start_time

        success_count = len(new_snapshot)
        logger.info(
            f"快照创建完成: {success_count} 成功, "
            f"{snapshot_errors} 失败, "
            f"耗时 {elapsed:.2f}秒"
        )
        return success_count

    def save_snapshot(self):
        """保存快照到文件"""
        try:
            logger.debug(f"保存快照: {self.snapshot}")
            with open(self.config.get('base.snapshot_file'), "w") as f:
                json.dump(self.snapshot, fp=f, indent=2)
        except Exception as e:
            logger.error(f"保存快照失败: {str(e)}")

    def load_snapshot(self):
        """加载快照（工作线程已就绪）"""
        try:
            snapshot_file = self.config.get('base.snapshot_file')
            if os.path.exists(snapshot_file):
                # 正常加载快照
                with open(snapshot_file, "r") as f:
                    self.snapshot = json.load(f)
                logger.info(f"加载快照: {len(self.snapshot)} 文件")
            else:
                logger.warning("未找到快照文件，将创建新快照")
                # 此时工作线程已初始化，可以安全创建快照
                self.create_snapshot()
        except Exception as e:
            logger.error(f"加载快照失败: {str(e)}")
            self.snapshot = {}

    def recover_file(self, rel_path):
        """恢复被篡改的文件"""

        logger.info(f"恢复文件: {rel_path}")
        # 定位原始文件
        target_path = os.path.join(self.config.get('base.web_dir'), rel_path)

        try:
            # 执行恢复操作
            self.backup_manager.recover_file(rel_path, target_path)

            # 验证恢复结果
            restored_hash = HashWorker._sync_calculate(target_path, self.callback_router, self.config)[1]
            original_hash = self.snapshot[rel_path]["hash"][1]

            if restored_hash != original_hash:
                logger.critical(f"恢复验证失败: {rel_path}，{restored_hash} != {original_hash}")
                self.alert.alert(f"恢复验证失败: {rel_path}", "严重错误")
            else:
                logger.info(f"恢复验证成功 {rel_path}")
        except Exception as e:
            logger.error(f"恢复文件失败 {rel_path}: {str(e)}")
            self.alert.alert(f"文件恢复失败: {rel_path}", "恢复失败")

    def check_all_files(self):
        """全量文件检查（优化版）"""
        if not self.snapshot:
            logger.warning("无有效快照，跳过全量检查")
            return

        logger.info("开始全量文件检查...")
        start_time = time.time()
        issues_found = 0
        checked_count = 0

        web_dir = self.config.get('base.web_dir')

        # 第一步：检查快照中所有文件是否存在
        for rel_path in list(self.snapshot.keys()):
            file_path = os.path.join(web_dir, rel_path)

            if not os.path.exists(file_path):
                logger.warning(f"文件被删除: {rel_path}")
                self.handle_tamper(rel_path, "文件被删除")
                issues_found += 1
                continue

        # 第二步：检查目录中的文件
        for root, _, files in os.walk(web_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = self.get_relative_path(file_path)

                if not rel_path:
                    continue

                # 检查文件是否在快照中
                if rel_path in self.snapshot:
                    # 提交哈希检查
                    self.calculate_hash(file_path)
                    checked_count += 1
                else:
                    result = self.move_suspicious_file(file_path)
                    if result == 1:
                        self.alert.alert(f"发现未授权文件: {rel_path}，已移动至可疑文件夹", "篡改检测")
                    elif result == 2:
                        self.alert.alert(f"发现未授权文件: {rel_path}，已删除", "篡改检测")
                    else:
                        self.alert.alert(f"发现未授权文件: {rel_path}，删除失败", "篡改检测")

        # 等待哈希检查完成
        self.hash_task_queue.join()

        elapsed = time.time() - start_time
        logger.info(f"全量检查完成: 检查 {checked_count} 文件, 发现 {issues_found} 问题, 耗时 {elapsed:.2f}秒")

    def start_monitoring(self):
        """启动文件监控"""
        if self.observer and self.observer.is_alive():
            logger.warning("监控已在运行")
            return

        # 创建监控处理器
        self.monitor = TamperingComparisonCallback(self)

        # 设置监控模式
        self.callback_router.set_mode("monitor", self.monitor)

        logger.info("启动文件监控...")
        self.running = True

        # 创建文件观察者
        self.observer = Observer()
        self.observer.schedule(
            FileMonitor(self.event_queue),
            self.config.get('base.web_dir'),
            recursive=True
        )
        self.observer.start()

        last_full_check = time.time()

        try:
            while self.running:

                # 定期全量检查
                current_time = time.time()
                if current_time - last_full_check > self.config.get('base.full_check_interval', 3600):
                    self.check_all_files()
                    last_full_check = current_time

                time.sleep(1)

        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logger.error(f"监控循环错误: {str(e)}")
            self.stop()

    def stop(self):
        """停止监控服务"""
        logger.info("停止监控服务...")
        self.running = False

        self.callback_router.set_mode("default")

        # 停止事件处理器
        for _ in self.event_processors:
            self.event_queue.put(None)

        # 停止哈希工作线程
        for _ in self.hash_workers:
            self.hash_task_queue.put(None)

        # 停止文件观察者
        if self.observer:
            self.observer.stop()
            self.observer.join()

        logger.info("服务已停止")

    def _monitor_system_status(self):

        """系统状态监控线程"""
        while True:
            # 监控工作线程状态
            active_workers = sum(1 for w in self.hash_workers if w.is_alive())
            if active_workers < len(self.hash_workers):
                logger.warning(f"工作线程状态: {active_workers}/{len(self.hash_workers)} 活跃")

            # 监控队列状态
            event_qsize = self.event_queue.qsize()
            task_qsize = self.hash_task_queue.qsize()

            if event_qsize > 100 or task_qsize > 50:
                logger.info(f"队列状态: 事件={event_qsize}, 任务={task_qsize}")

            time.sleep(10)

    def default_result_handler(self, file_path, result):
        """默认回调"""
        logger.info("默认回调...")
        pass


def main():
    """主函数"""
    logger.info("=" * 60)
    logger.info("启动高性能网页防篡改保护服务")
    logger.info("=" * 60)

    # 启动保护服务
    protector = WebTamperProtector()
    protector.start_monitoring()


if __name__ == "__main__":
    # 禁用watchdog的详细日志
    logging.getLogger("watchdog").setLevel(logging.WARNING)

    # 设置日志级别（生产环境可设为INFO）
    logger.setLevel(logging.DEBUG)

    # 启动服务
    try:
        main()
    except Exception as e:
        logger.exception(f"服务启动失败: {str(e)}")
        sys.exit(1)
