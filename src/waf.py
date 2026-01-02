import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict


# -----------------------------
# Configuration
# -----------------------------

@dataclass
class WAFConfig:
    max_requests: int = 5
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
            score += 1
            reasons.append("Sensitive endpoint access")

        decision = self._decide(score)
        return decision, reasons, score

    @staticmethod
    def _decide(score: int) -> str:
        if score >= 4:
            return "BLOCK"
        elif score >= 2:
            return "LOG"
        return "ALLOW"


# -----------------------------
# Simulation
# -----------------------------

if __name__ == "__main__":
    config = WAFConfig()
    waf = WAFEngine(config)

    test_requests = [
        Request("1.1.1.1", "/login", "user=test"),
        Request("1.1.1.1", "/login", "user=test"),
        Request("1.1.1.1", "/login", "user=test"),
        Request("1.1.1.1", "/admin", "X" * 600),
        Request("2.2.2.2", "/home"),
    ]

    for req in test_requests:
        decision, reasons, score = waf.analyze(req)
        print(f"[{decision}] {req.source} → {req.endpoint} | Score={score} | Reasons={reasons}")
        time.sleep(1)
