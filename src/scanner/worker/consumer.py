"""RabbitMQ consumer with a separate processing thread for heartbeat safety."""

from __future__ import annotations

import json
import logging
import queue
import signal
import threading
import time
from typing import Any

import pika
import pika.exceptions

from scanner.worker.config import RabbitMQConfig
from scanner.worker.mongo_store import MongoStore
from scanner.worker.task_runner import TaskRunner

logger = logging.getLogger(__name__)

_RETRY_HEADER = "x-retry-count"


class Consumer:
    """RabbitMQ consumer that processes tasks in a background thread.

    Architecture
    ------------
    * **Main thread** — runs the pika ``BlockingConnection`` event loop.
      Responsible for consuming messages and responding to heartbeats.
    * **Worker thread** — picks messages from an internal ``queue.Queue``,
      runs ``TaskRunner.execute``, then uses ``add_callback_threadsafe`` to
      ACK/NACK back on the main thread.

    This keeps the pika connection alive regardless of how long a scan takes.
    """

    def __init__(
        self,
        rmq_config: RabbitMQConfig,
        task_runner: TaskRunner,
        mongo: MongoStore,
    ):
        self._rmq_cfg = rmq_config
        self._task_runner = task_runner
        self._mongo = mongo
        self._shutdown = threading.Event()
        self._connection: pika.BlockingConnection | None = None
        self._task_queue: queue.Queue = queue.Queue(maxsize=1)

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Connect to RabbitMQ and start consuming (blocks until shutdown)."""
        self._install_signal_handlers()
        worker = threading.Thread(target=self._process_loop, daemon=True)
        worker.start()

        attempt = 0
        while not self._shutdown.is_set():
            try:
                self._connect_and_consume()
                attempt = 0
            except pika.exceptions.AMQPConnectionError as exc:
                attempt += 1
                delay = min(2 ** attempt, 30)
                logger.warning(
                    "RabbitMQ connection lost (%s). Reconnecting in %ds …",
                    exc, delay,
                )
                self._shutdown.wait(delay)
            except Exception:
                if not self._shutdown.is_set():
                    logger.exception("Unexpected error in consumer loop")
                    self._shutdown.wait(5)

        logger.info("Consumer shutdown complete")

    # ------------------------------------------------------------------ #
    #  Connection / consumption
    # ------------------------------------------------------------------ #

    def _connect_and_consume(self) -> None:
        cfg = self._rmq_cfg
        credentials = pika.PlainCredentials(cfg.username, cfg.password)
        params = pika.ConnectionParameters(
            host=cfg.host,
            port=cfg.port,
            virtual_host=cfg.vhost,
            credentials=credentials,
            heartbeat=cfg.heartbeat,
        )

        self._connection = pika.BlockingConnection(params)
        channel = self._connection.channel()
        channel.queue_declare(queue=cfg.queue_name, durable=True)
        channel.basic_qos(prefetch_count=cfg.prefetch_count)
        channel.basic_consume(queue=cfg.queue_name, on_message_callback=self._on_message)

        logger.info(
            "Connected to RabbitMQ %s:%d, consuming queue '%s'",
            cfg.host, cfg.port, cfg.queue_name,
        )

        try:
            while not self._shutdown.is_set():
                self._connection.process_data_events(time_limit=1)
        finally:
            self._safe_close()

    def _on_message(
        self,
        channel: Any,
        method: pika.spec.Basic.Deliver,
        properties: pika.BasicProperties,
        body: bytes,
    ) -> None:
        """Enqueue the message for the worker thread (non-blocking)."""
        self._channel = channel
        self._task_queue.put((channel, method, properties, body))

    # ------------------------------------------------------------------ #
    #  Worker thread
    # ------------------------------------------------------------------ #

    def _process_loop(self) -> None:
        """Drain the internal queue and process tasks."""
        while not self._shutdown.is_set():
            try:
                item = self._task_queue.get(timeout=1)
            except queue.Empty:
                continue

            channel, method, properties, body = item
            task_id = "<unknown>"

            try:
                task_msg = json.loads(body)
                task_id = task_msg.get("task_id", task_id)
                src = task_msg.get("source", "")
                stage = self._task_runner.compute_effective_stage(task_msg)
                logger.info(
                    "Processing task %s source=%s stage=%s",
                    task_id, src, stage,
                )

                self._task_runner.execute(task_msg)
                self._threadsafe_ack(method.delivery_tag)

            except Exception as exc:
                retry = self._get_retry_count(properties)
                if retry < self._rmq_cfg.max_retries:
                    logger.warning(
                        "Task %s failed (attempt %d/%d): %s — requeueing",
                        task_id, retry + 1, self._rmq_cfg.max_retries, exc,
                    )
                    self._threadsafe_retry(body, properties, retry + 1)
                    self._threadsafe_ack(method.delivery_tag)
                else:
                    logger.error(
                        "Task %s failed after %d attempts: %s",
                        task_id, self._rmq_cfg.max_retries, exc,
                    )
                    self._mongo.update_task_status(
                        task_id, "failed", error=str(exc),
                    )
                    self._threadsafe_ack(method.delivery_tag)

    # ------------------------------------------------------------------ #
    #  Thread-safe RabbitMQ operations
    # ------------------------------------------------------------------ #

    def _threadsafe_ack(self, delivery_tag: int) -> None:
        conn = self._connection
        if conn and conn.is_open:
            conn.add_callback_threadsafe(
                lambda: self._safe_basic_ack(delivery_tag)
            )

    def _safe_basic_ack(self, delivery_tag: int) -> None:
        try:
            ch = getattr(self, "_channel", None)
            if ch and ch.is_open:
                ch.basic_ack(delivery_tag)
        except Exception:
            logger.debug("ACK failed (connection may have closed)", exc_info=True)

    def _threadsafe_retry(
        self,
        body: bytes,
        properties: pika.BasicProperties,
        retry_count: int,
    ) -> None:
        headers = dict(properties.headers or {})
        headers[_RETRY_HEADER] = retry_count
        new_props = pika.BasicProperties(
            delivery_mode=2,
            content_type="application/json",
            headers=headers,
        )
        conn = self._connection
        if conn and conn.is_open:
            conn.add_callback_threadsafe(
                lambda: self._safe_publish(body, new_props)
            )

    def _safe_publish(self, body: bytes, properties: pika.BasicProperties) -> None:
        try:
            ch = getattr(self, "_channel", None)
            if ch and ch.is_open:
                ch.basic_publish(
                    exchange="",
                    routing_key=self._rmq_cfg.queue_name,
                    body=body,
                    properties=properties,
                )
        except Exception:
            logger.debug("Retry publish failed", exc_info=True)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _get_retry_count(properties: pika.BasicProperties) -> int:
        if properties.headers and _RETRY_HEADER in properties.headers:
            return int(properties.headers[_RETRY_HEADER])
        return 0

    def _safe_close(self) -> None:
        try:
            if self._connection and self._connection.is_open:
                self._connection.close()
        except Exception:
            pass

    def _install_signal_handlers(self) -> None:
        def _handle(signum: int, _frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Received %s — shutting down gracefully …", sig_name)
            self._shutdown.set()

        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)
