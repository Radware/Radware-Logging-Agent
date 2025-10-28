import os
import queue
import shutil
import threading
from typing import Dict, Optional, Tuple

from .data_processor import DataProcessor
from .logging_config import get_logger


class FileQueueAgent:
    """Common queue and worker management for file-based agents."""

    def __init__(
        self,
        agent_config: dict,
        root_path: str,
        completion_strategy: Optional[dict],
        input_type: str,
    ) -> None:
        if not root_path:
            raise ValueError("root_path is required for file-based agents")

        self.agent_config = agent_config
        self.input_type = input_type
        self.root_path = os.path.abspath(root_path)
        self.logger = get_logger(self.__class__.__name__)
        self.data_processor = DataProcessor(agent_config)
        self.processing_queue: "queue.Queue[Optional[dict]]" = queue.Queue()
        self.stop_event = threading.Event()
        self.worker_threads: list[threading.Thread] = []
        self._known_files: Dict[str, Tuple[int, float]] = {}
        self._inflight_files: set[str] = set()
        self._lock = threading.Lock()
        self.completion_strategy = self._normalize_completion_strategy(completion_strategy)

    @staticmethod
    def _normalize_completion_strategy(completion_strategy: Optional[dict]) -> dict:
        if completion_strategy is None:
            return {"mode": "delete"}
        if isinstance(completion_strategy, str):
            return {"mode": completion_strategy}

        strategy = dict(completion_strategy)
        mode = strategy.get("mode", "delete").lower()
        normalized = {"mode": mode}
        if mode == "archive":
            archive_directory = strategy.get("archive_directory")
            if not archive_directory:
                raise ValueError("archive_directory must be provided for archive mode")
            normalized["archive_directory"] = os.path.abspath(archive_directory)
        return normalized

    def _start_worker_threads(self) -> None:
        num_threads = self.agent_config.get("num_worker_threads", 1)
        for index in range(num_threads):
            thread = threading.Thread(target=self._worker_loop, name=f"{self.input_type}-worker-{index}")
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)

    def _worker_loop(self) -> None:
        while True:
            try:
                entry = self.processing_queue.get(timeout=1)
            except queue.Empty:
                if self.stop_event.is_set():
                    break
                continue

            if entry is None:
                self.processing_queue.task_done()
                break

            try:
                self._process_queue_entry(entry)
            except Exception:  # pragma: no cover - defensive logging
                self.logger.exception("Unexpected error processing entry %s", entry)
            finally:
                self.processing_queue.task_done()

    def _process_queue_entry(self, entry: dict) -> bool:
        file_path = entry["file_path"]
        success = False
        try:
            success = self.data_processor.process_data(
                {
                    "file_path": file_path,
                    "key": entry["relative_key"],
                    "expected_size": entry.get("size"),
                }
            )
        except Exception:  # pragma: no cover - defensive logging
            self.logger.exception("DataProcessor raised an exception for %s", file_path)
        finally:
            self._finalize_entry(entry, success)
        return success

    def _finalize_entry(self, entry: dict, success: bool) -> None:
        file_path = entry["file_path"]
        if success:
            self._handle_success_cleanup(entry)
            with self._lock:
                self._inflight_files.discard(file_path)
                self._known_files.pop(file_path, None)
        else:
            with self._lock:
                self._inflight_files.discard(file_path)
            self._reset_tracking_state(file_path)

    def _handle_success_cleanup(self, entry: dict) -> None:
        mode = self.completion_strategy.get("mode", "delete")
        file_path = entry["file_path"]

        if mode == "delete":
            try:
                os.remove(file_path)
                self.logger.debug("Deleted processed file %s", file_path)
            except FileNotFoundError:
                self.logger.debug("File %s already removed", file_path)
            except OSError as exc:
                self.logger.error("Failed to delete %s: %s", file_path, exc)
        elif mode == "archive":
            archive_directory = self.completion_strategy["archive_directory"]
            destination = os.path.join(archive_directory, entry["relative_key"])
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            try:
                shutil.move(file_path, destination)
                self.logger.debug("Archived %s to %s", file_path, destination)
            except FileNotFoundError:
                self.logger.debug("File %s missing before archive", file_path)
            except OSError as exc:
                self.logger.error("Failed to archive %s: %s", file_path, exc)

    def _reset_tracking_state(self, file_path: str) -> None:
        try:
            stat_result = os.stat(file_path)
        except OSError:
            with self._lock:
                self._known_files.pop(file_path, None)
            return

        with self._lock:
            self._known_files[file_path] = (stat_result.st_size, stat_result.st_mtime)

    def _await_worker_completion(self) -> None:
        self.processing_queue.join()
        for _ in self.worker_threads:
            self.processing_queue.put(None)
        for thread in self.worker_threads:
            thread.join(timeout=10)
            if thread.is_alive():
                self.logger.warning("Worker thread %s did not exit cleanly", thread.name)

    def stop(self) -> None:
        self.stop_event.set()

    def _queue_file(self, file_path: str, size: Optional[int] = None) -> bool:
        absolute_path = os.path.abspath(file_path)
        if not self._is_within_root(absolute_path):
            self.logger.warning("Ignoring path outside root: %s", absolute_path)
            return False

        if size is None:
            try:
                size = os.path.getsize(absolute_path)
            except OSError as exc:
                self.logger.error("Unable to stat %s: %s", absolute_path, exc)
                return False

        relative_key = os.path.relpath(absolute_path, self.root_path)
        with self._lock:
            if absolute_path in self._inflight_files:
                return False
            self._inflight_files.add(absolute_path)
            self._known_files.pop(absolute_path, None)

        entry = {
            "input_type": self.input_type,
            "file_path": absolute_path,
            "relative_key": relative_key,
            "size": size,
        }
        self.processing_queue.put(entry)
        self.logger.info("Enqueued file %s (%d bytes)", relative_key, size)
        return True

    def _is_within_root(self, absolute_path: str) -> bool:
        root = self.root_path
        if not absolute_path.startswith(root):
            return False
        # Ensure directories like /tmp/root-other don't match
        return os.path.commonpath([root, absolute_path]) == root

    def _scan_for_files(self) -> None:
        for current_root, _dirs, files in os.walk(self.root_path):
            for filename in files:
                candidate = os.path.join(current_root, filename)
                try:
                    stat_result = os.stat(candidate)
                except OSError:
                    continue

                file_signature = (stat_result.st_size, stat_result.st_mtime)
                with self._lock:
                    if candidate in self._inflight_files:
                        continue
                    previous = self._known_files.get(candidate)
                    if previous == file_signature:
                        should_queue = True
                        self._known_files.pop(candidate, None)
                    else:
                        self._known_files[candidate] = file_signature
                        should_queue = False

                if should_queue:
                    self._queue_file(candidate, size=stat_result.st_size)

        # Remove stale entries for files that disappeared
        with self._lock:
            stale = [path for path in self._known_files if not os.path.exists(path)]
            for path in stale:
                self._known_files.pop(path, None)
                self._inflight_files.discard(path)


class FileAgent(FileQueueAgent):
    """Agent that polls a directory for completed files."""

    def __init__(self, agent_config: dict) -> None:
        settings = agent_config.get("file_settings", {})
        completion = settings.get("completion_strategy")
        super().__init__(
            agent_config,
            root_path=settings.get("root_path", ""),
            completion_strategy=completion,
            input_type="file",
        )
        self.polling_interval = int(settings.get("polling_interval_seconds", 5))

    def start(self) -> None:
        self.logger.info("Starting FileAgent for %s", self.root_path)
        self._start_worker_threads()
        try:
            while not self.stop_event.is_set():
                self._scan_for_files()
                self.stop_event.wait(self.polling_interval)
        finally:
            self.logger.debug("FileAgent scan loop exiting")

        # One final scan to pick up any files that stabilized during shutdown
        self._scan_for_files()
        self._await_worker_completion()
        self.logger.info("FileAgent stopped for %s", self.root_path)
