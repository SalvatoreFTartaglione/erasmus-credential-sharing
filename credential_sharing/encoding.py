"""Deterministic encodings used for hashing, signing and timestamps."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def canonical_json(obj: Any) -> bytes:
    """Serialise ``obj`` deterministically: sorted keys, no whitespace, UTF-8.

    Every hash and signature in the project is computed over this encoding, so
    two parties holding semantically equal JSON always obtain identical bytes.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def b64url_encode(data: bytes) -> str:
    """Base64url without padding (the encoding used by JOSE/JWS)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected a base64url string")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_timestamp(moment: datetime) -> str:
    """Format a datetime as an XML Schema ``dateTime`` in UTC (``...Z``)."""
    return moment.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(text: str) -> datetime:
    return datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
