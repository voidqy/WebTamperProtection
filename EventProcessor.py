import queue
import threading
import time

from logger import logger


class EventProcessor(threading.Thread):
    """事件处理线程"""

    def __init__(self, protector, event_queue, config):
        super().__init__()
        self.protector = protector
        self.event_queue = event_queue
        self.daemon = True
        self.running = True
        self.config = config

    def run(self):
        logger.info(f"事件处理器线程启动")
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                if event is None:  # 停止信号
                    break

                # 延迟处理
                time.sleep(self.config.get('optimize.event_process_delay', 1))

                # 处理事件
                if isinstance(event, tuple) and len(event) == 2:
                    event_type, file_path = event
                    self.protector.process_event(event_type, file_path)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"事件处理错误: {str(e)}")

    def stop(self):
        self.running = False
