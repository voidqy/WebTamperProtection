import time

from watchdog.events import FileSystemEventHandler


class FileMonitor(FileSystemEventHandler):
    """文件系统监控"""

    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.last_events = {}

    def _queue_event(self, event_type, src_path):
        """将事件加入队列（合并重复事件）"""
        current_time = time.time()

        # 合并短时间内的重复事件
        if src_path in self.last_events:
            last_time, last_type = self.last_events[src_path]
            if current_time - last_time < 0.5 and event_type == last_type:
                return

        # 加入队列
        self.event_queue.put((event_type, src_path))
        self.last_events[src_path] = (current_time, event_type)

    def on_modified(self, event):
        if not event.is_directory:
            self._queue_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._queue_event("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._queue_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._queue_event("deleted", event.src_path)
            self._queue_event("created", event.dest_path)
