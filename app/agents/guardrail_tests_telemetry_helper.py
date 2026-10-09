import logging
from typing import List, Optional, Any, Dict, Tuple

logger = logging.getLogger("agent.remediation.telemetry")

STATUS_RAG_UNCHECKED = "UNCHECKED (Standard Retriever)"


class BasicInMemoryAuditLogger:
    """Baseline in-memory audit logger for unhardened application."""

    def __init__(self) -> None:
        self.events: List[Any] = []

    def get_events(self) -> List[Any]:
        return list(self.events)

    def log_event(self, event: Any) -> None:
        self.events.append(event)


def finalize_telemetry(
    actions: List[str],
    user_msg: str,
    raw_text_lower: str,
    sec_identity: Any,
    in_mem_logger: Optional[Any],
    initial_events_count: int,
    run_config: Dict[str, Any],
    default_rag_status: str = STATUS_RAG_UNCHECKED,
) -> Tuple[List[str], str, str]:
    """Baseline telemetry finalizer for unhardened master branch."""
    return actions, user_msg, default_rag_status
