"""
app/services/log_service.py — Request/Response logging business logic.

Centralises all MongoDB persistence for audit logs. Called from the
before_request and after_request hooks registered in create_app().

Security fixes:
  C-4 — Body sanitized before storage (credentials never logged)
  M-2 — CRLF stripped from all string fields (CWE-117)
  M-3 — request_id propagated from Flask g
  M-4 — LogEntry dataclass removes all KeyError risks
  L-3 — Exception stored as str(), not as Python object
  L-2 — Pagination added to log retrieval
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from flask import Response, g, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from pymongo.errors import PyMongoError

from app.exceptions import DatabaseError, NotFoundError
from app.extensions import mongo
from app.models.log_entry import LogEntry
from app.utils.sanitizer import sanitize_body, sanitize_headers

logger = logging.getLogger(__name__)


class LogService:
    """Manages creation, updating, and retrieval of request audit logs."""

    COLLECTION = "request_logs"

    # ── Write path ────────────────────────────────────────────────────────────

    @classmethod
    def capture_request(cls) -> str | None:
        """
        Persist an initial log document at the start of a request.

        Returns the inserted MongoDB document ID (stored in g.log_id so
        after_request can update it). Returns None on MongoDB failure —
        the request is NOT aborted; logging is best-effort.
        """
        user = cls._safe_get_identity()
        entry = LogEntry(
            request_id=g.get("request_id", ""),
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            user=user,
            remote_addr=request.remote_addr or "",
            method=request.method,
            scheme=request.scheme,
            path=request.full_path,
            url=request.url,
            content_type=request.content_type or "",
            # Sanitize body — strips passwords and CRLF (C-4, M-2)
            body=sanitize_body(
                request.get_data(as_text=True),
                content_type=request.content_type or "",
            ),
        )

        try:
            result = mongo.db[cls.COLLECTION].insert_one(entry.to_dict())
            return str(result.inserted_id)
        except PyMongoError as exc:
            logger.warning(
                "log_capture_request_failed",
                extra={"error": str(exc), "request_id": g.get("request_id")},
            )
            return None

    @classmethod
    def capture_response(cls, log_id: str, response: Response) -> None:
        """
        Update the existing log document with response data.
        Non-blocking — failures are logged but not propagated.
        """
        if not log_id:
            return

        update: dict = {
            "$set": {
                "status": response.status,
                "status_code": response.status_code,
                # Only capture small, text responses (avoid logging binary/large payloads)
                "response_body": cls._safe_response_body(response),
            }
        }
        try:
            mongo.db[cls.COLLECTION].update_one(
                {"_id": ObjectId(log_id)}, update
            )
        except PyMongoError as exc:
            logger.warning(
                "log_capture_response_failed",
                extra={"log_id": log_id, "error": str(exc)},
            )

    @classmethod
    def capture_exception(cls, log_id: str, exception: BaseException) -> None:
        """
        Attach a string-serialised exception to the log document (fix L-3).
        """
        if not log_id:
            return
        update: dict = {
            "$set": {
                "exception": str(exception),          # str(), not the object
                "exception_type": type(exception).__name__,
            }
        }
        try:
            mongo.db[cls.COLLECTION].update_one(
                {"_id": ObjectId(log_id)}, update
            )
        except PyMongoError as exc:
            logger.warning(
                "log_capture_exception_failed",
                extra={"log_id": log_id, "error": str(exc)},
            )

    # ── Read path ─────────────────────────────────────────────────────────────

    @classmethod
    def get_logs(
        cls,
        page: int = 1,
        page_size: int = 50,
        filters: Optional[dict] = None,
    ) -> dict:
        """
        Return a paginated list of log entries (fix L-2).

        Args:
            page:       1-based page number.
            page_size:  Records per page (capped at MAX_PAGE_SIZE in the view).
            filters:    Optional MongoDB query dict for filtering.

        Raises:
            DatabaseError: On MongoDB failure.
        """
        query = filters or {}
        skip = (page - 1) * page_size

        try:
            collection = mongo.db[cls.COLLECTION]
            total = collection.count_documents(query)
            cursor = (
                collection
                .find(query, {"_id": 1, "request_id": 1, "timestamp": 1,
                               "method": 1, "path": 1, "status": 1,
                               "user": 1, "remote_addr": 1, "duration_ms": 1})
                .sort("timestamp", -1)
                .skip(skip)
                .limit(page_size)
            )
            items = [cls._mongo_doc_to_dict(doc) for doc in cursor]
        except PyMongoError as exc:
            logger.error("get_logs_failed", extra={"error": str(exc)}, exc_info=True)
            raise DatabaseError("Could not retrieve logs.") from exc

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, -(-total // page_size)),  # ceiling division
        }

    @classmethod
    def get_log_by_id(cls, log_id: str) -> dict:
        """
        Retrieve a single log entry by MongoDB ObjectId string.

        Raises:
            NotFoundError: If the document does not exist.
            DatabaseError: On MongoDB failure.
        """
        try:
            oid = ObjectId(log_id)
        except Exception:
            raise NotFoundError(f"Log entry '{log_id}' not found.")

        try:
            doc = mongo.db[cls.COLLECTION].find_one({"_id": oid})
        except PyMongoError as exc:
            raise DatabaseError("Could not retrieve log entry.") from exc

        if not doc:
            raise NotFoundError(f"Log entry '{log_id}' not found.")

        return cls._mongo_doc_to_dict(doc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_get_identity() -> str | None:
        """Extract JWT identity without raising on missing/invalid token."""
        try:
            verify_jwt_in_request(optional=True)
            return get_jwt_identity()
        except Exception:
            return None

    @staticmethod
    def _safe_response_body(response: Response) -> str:
        """
        Return sanitized response body if small and text-based, else "".
        Prevents log-bloat from large downloads or binary payloads.
        """
        content_type = response.content_type or ""
        if "text" not in content_type and "json" not in content_type:
            return ""
        data = response.get_data(as_text=True)
        if len(data) > 4096:
            return "[TRUNCATED]"
        return sanitize_body(data, content_type=content_type)

    @staticmethod
    def _mongo_doc_to_dict(doc: dict) -> dict:
        """Convert a MongoDB document to a JSON-serialisable dict."""
        doc["id"] = str(doc.pop("_id"))
        return doc
