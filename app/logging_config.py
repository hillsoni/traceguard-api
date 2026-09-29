"""
app/logging_config.py — Structured JSON logging configuration.

Configures Python's logging system to emit newline-delimited JSON to stdout,
suitable for consumption by log aggregators (Datadog, ELK, Cloud Logging).

Fields emitted on every record:
  timestamp, level, logger, message, request_id (if in Flask g), +extras
"""
from __future__ import annotations

import json
import logging
import sys
import traceback
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    """
    Converts a LogRecord into a single-line JSON string.

    Extra context injected via logger.info("msg", extra={...}) is merged
    at the top level of the JSON object for easy querying in log aggregators.
    """

    _RESERVED = frozenset(
        logging.LogRecord(
            "", 0, "", 0, "", (), None
        ).__dict__.keys()
    )

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        # Base structured fields
        payload: dict = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Propagate extras (e.g. request_id, method, path)
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value

        # Attach exception info when present
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
            payload["traceback"] = traceback.format_exception(*record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    """
    Replace the root handler with a JSON stdout handler.

    Call once inside create_app(), before registering blueprints.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(numeric_level)

    # Silence noisy third-party loggers
    for noisy in ("werkzeug", "sqlalchemy.engine.Engine", "pymongo"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
