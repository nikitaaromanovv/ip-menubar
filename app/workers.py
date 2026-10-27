"""Bounded worker lanes. All scheduling/polling belongs to the main thread."""
from dataclasses import dataclass
import logging
import queue
import threading


@dataclass(frozen=True)
class JobResult:
    value: object = None
    error: bool = False


class Lane:
    def __init__(self, name):
        self.name = name
        self.busy = False
        self.queue = queue.Queue(maxsize=1)

    def launch(self, fn, *args):
        if self.busy:
            return False
        self.busy = True

        def run():
            try:
                result = JobResult(fn(*args))
            except Exception:
                logging.getLogger('ip_menubar').exception('Worker %s failed', self.name)
                result = JobResult(error=True)
            self.queue.put(result)

        try:
            threading.Thread(target=run, daemon=True, name=self.name).start()
        except RuntimeError:
            self.busy = False
            return False
        return True

    def poll(self):
        try:
            result = self.queue.get_nowait()
        except queue.Empty:
            return None
        self.busy = False
        return result
