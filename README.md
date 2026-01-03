# Behavior Based Web Application Firewall (WAF)
## Overview

This repository presents a behavior-based Web Application Firewall (WAF) implemented in Python and integrated as a FastAPI middleware.

The system inspects incoming HTTP requests in real time and applies scoring-based behavioral analysis to decide whether a request should be allowed, logged, or blocked.

## Scope & Goals

### Scope
This project focuses on building a simplified and educational Web Application Firewall (WAF) that analyzes incoming HTTP requests before they reach a web application.

The scope of this project is intentionally limited to:
- Inspecting request metadata such as request rate, endpoint usage, payload size, and basic header patterns
- Applying simple rule-based and behavior-based logic to classify requests
- Making high-level decisions such as allow, block, or log
- Demonstrating defensive reasoning rather than production-grade protection

The project does not attempt to provide full web security coverage or replace enterprise WAF solutions.

---

### Goals
The primary goals of this project are:
- To understand how WAF systems reason about request legitimacy
- To explore how normal request behavior can be distinguished from abnormal patterns

## Quick Start

### Requirements
- Python 3.10+
- Virtual environment (venv)

### Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

uvicorn src.app:app --reload
The service will be available at: http://127.0.0.1:8000

## Threat Model (Simplified)

### Assets
The primary asset protected by this system is the web application itself, specifically its availability and integrity at the HTTP request level.  
The project focuses on protecting application endpoints from abnormal or abusive request behavior rather than protecting sensitive data or user credentials.

---

### Threat Actors
This project considers unsophisticated or automated threat actors, such as:
- Bots generating excessive or repetitive requests
- Scripts attempting to abuse application endpoints
- Automated scanners producing unusual request patterns

Advanced attackers, insider threats, and highly targeted exploitation techniques are considered out of scope.

---

### Attack Vectors
Rather than modeling specific exploits, this project focuses on behavioral attack vectors, including:
- Excessive request rates within short time windows
- Abnormal access patterns to specific endpoints
- Unusually large request payloads
- Repetitive or malformed request structures

These vectors are analyzed based on deviation from expected behavior rather than known attack signatures.

---

### Assumptions
The threat model operates under the following assumptions:
- The protected application follows predictable usage patterns
- Legitimate users interact with the application at reasonable rates
- Requests can be evaluated independently without deep application context
- The WAF operates before requests reach application logic

These assumptions allow the project to remain simple, focused, and educational.

## Detection Logic

This system applies a combination of simple rule-based checks and behavior-based analysis to evaluate incoming HTTP requests. The goal is not to detect specific exploits, but to identify requests that deviate from expected usage patterns.

---

### Behavioral Signals
The following behavioral signals are considered during request evaluation:

- **Request Rate**  
  A high number of requests from the same source within a short time window may indicate automated or abusive behavior.

- **Endpoint Access Patterns**  
  Requests repeatedly targeting a single endpoint or accessing endpoints in unusual sequences may suggest scanning or misuse.

- **Payload Size Anomalies**  
  Requests with payload sizes significantly larger than typical values for a given endpoint may be flagged for inspection.

- **Timing Irregularities**  
  Uniform or highly consistent request timing can indicate non-human behavior, especially when compared to baseline usage patterns.

---

### Rule-Based Checks
In addition to behavioral analysis, basic rule-based checks are applied to provide initial filtering:

- Requests exceeding predefined size limits
- Requests missing required headers
- Requests using unsupported HTTP methods

These rules are intentionally simple and serve as guardrails rather than comprehensive protection mechanisms.

---

### Decision Logic
Each request is evaluated against the defined signals and rules. Based on the results, it assigns one of the following outcomes:

- **Allow** — The request appears consistent with normal behavior  
- **Log** — The request shows minor deviations and is recorded for further analysis  
- **Block** — The request exhibits clear abnormal behavior and is prevented from reaching the application

Decisions are made conservatively to reduce false positives and prioritize observation over enforcement.

## High-Level Architecture

The architecture of this WAF is intentionally simple and modular, designed to clearly demonstrate the flow of request evaluation without introducing unnecessary complexity.

At a high level, incoming HTTP requests pass through the following stages:

1. **Request Intake**  
   The WAF receives an HTTP request before it reaches the web application. At this stage, only request metadata and structure are considered.

2. **Signal Evaluation**  
   The request is analyzed using the defined detection logic, including behavioral signals and basic rule-based checks.

3. **Decision Engine**  
   Based on the evaluation results, the WAF assigns a decision to the request:
   - Allow
   - Log
   - Block

4. **Action Handling**  
   - Allowed requests are forwarded to the application  
   - Logged requests are recorded for later review  
   - Blocked requests are stopped and do not reach application logic

This architecture reflects how real-world WAF systems separate inspection, decision-making, and enforcement while remaining transparent to the protected application.

## Implementation Overview

The project includes a Python-based implementation of a behavior-based Web Application Firewall (WAF).  
The detection logic is implemented using a scoring-based decision engine that evaluates incoming requests based on multiple behavioral signals.

The implementation prioritizes clarity, modular design, and defensive reasoning rather than production deployment.

## Testing

The WAF detection logic is validated using automated unit tests implemented with Python's built-in `unittest` framework.  
The test suite verifies expected behavior across normal usage, anomalous patterns, severe conditions, and false-positive scenarios.

The successful execution of the test suite confirms the consistency and reliability of the decision-making logic.

### Test Results

![Test Results](screenshots/tests-success.png)

## Logging & Observability

Visibility is a critical component of any defensive security system. Rather than focusing solely on blocking requests, this WAF emphasizes logging and observability as primary mechanisms for understanding traffic behavior over time.

Each evaluated request may generate structured log entries that include:
- Timestamp of the request
- Source identifier (such as IP or session reference)
- Targeted endpoint
- Evaluation outcome (Allow, Log, or Block)
- Behavioral signals that influenced the decision

Logged data is intended to support post-analysis rather than real-time enforcement alone. By reviewing logs, analysts can identify recurring patterns, adjust detection thresholds, and reduce false positives without disrupting legitimate traffic.

This observability-first approach reflects real-world defensive practices, where monitoring and analysis often precede strict enforcement decisions.

### Example Log Output

The following screenshot demonstrates structured logging output generated during request evaluation, including decision levels, contextual metadata, and behavioral reasoning.

![Logging Output](screenshots/logging-output.png)

## Limitations

This implementation is intentionally simplified and is not designed to function as a production-grade Web Application Firewall. Its detection logic relies on basic behavioral signals and predefined thresholds, which may result in false positives or missed detections under certain conditions.

The project does not account for advanced evasion techniques, encrypted traffic inspection, deep application context, or distributed attack coordination. Additionally, decisions are made based on limited request metadata rather than full session awareness.

These limitations are accepted by design in order to keep the project focused, understandable, and suitable for educational purposes.

## Conclusion

This project demonstrates how a Web Application Firewall can be approached from a defensive and analytical perspective. By focusing on behavioral patterns, baseline expectations, and conservative decision-making, the system illustrates how abnormal request activity can be identified without relying on exploit-specific signatures.

The emphasis on scope definition, threat modeling, and observability reflects real-world security engineering practices, where understanding traffic behavior is as important as enforcing controls. While simplified, the system provides a strong foundation for further exploration and incremental improvement.

## Project Evolution
This project initially began as a conceptual prototype and evolved into a tested implementation through iterative design and validation.

## Ethical Notice

This project was developed strictly for educational and defensive purposes.  
No attacks were executed, and no real systems were targeted or disrupted during its design or demonstration.
- To apply behavioral analysis concepts rather than relying solely on signature-based rules
- To design a clear and ethical defensive security system
- To strengthen foundational skills in web security analysis and system design
