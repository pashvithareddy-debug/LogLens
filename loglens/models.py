from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class Event:
    """One normalized HTTP request record, whatever the source format was."""

    timestamp: Optional[datetime]
    level: str
    method: str
    endpoint: str
    status: int
    ip: Optional[str] = None
    response_ms: Optional[float] = None
