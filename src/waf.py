import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict

from src.logger import setup_logger

logger = setup_logger()


# -----------------------------
# Configuration
# -----------------------------

@dataclass
class WAFConfig:
    max_requests: int
    time_window: int = 10  # seconds
    max_payload_size: int = 500
    sensitive_endpoints: List[str] = field(default_factory=lambda: ["/admin"])


# -----------------------------
# Request Model
# -----------------------------

@dataclass
class Request:
    source: str
    endpoint: str
    payload: str = ""


# -----------------------------
# WAF Engine
# -----------------------------

class WAFEngine:
    def __init__(self, config: WAFConfig):
        self.config = config
        self.request_history: Dict[str, List[float]] = defaultdict(list)

    def _clean_old_requests(self, source: str, current_time: float):
        self.request_history[source] = [
            t for t in self.request_history[source]
            if current_time - t <= self.config.time_window
        ]

    def analyze(self, request: Request):
        current_time = time.time()
        self._clean_old_requests(request.source, current_time)
        self.request_history[request.source].append(current_time)

        score = 0
        reasons = []

        # Signal 1: Request rate
        if len(self.request_history[request.source]) > self.config.max_requests:
            score += 2
            reasons.append("High request rate")

        # Signal 2: Payload size
        if len(request.payload) > self.config.max_payload_size:
            score += 2
            reasons.append("Large payload")

        # Signal 3: Sensitive endpoint
        if any(request.endpoint.startswith(ep) for ep in self.config.sensitive_endpoints):
            score += 2
            reasons.append("Sensitive endpoint access")

        decision = self._decide(score)

        logger.log(
            logging.INFO if decision == "ALLOW"
            else logging.WARNING if decision == "LOG"
            else logging.ERROR,
            "",
            extra={
                "source": request.source,
                "endpoint": request.endpoint,
                "score": score,
                "decision": decision,
                "reasons": reasons,
            }
        )

        return decision, reasons, score

    @staticmethod
    def _decide(score: int) -> str:
        if score >= 4:
            return "BLOCK"
        elif score >= 2:
            return "LOG"
        return "ALLOW"
