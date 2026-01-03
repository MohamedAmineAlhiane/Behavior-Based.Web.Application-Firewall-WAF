from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.waf import WAFEngine, WAFConfig, Request as WAFRequest
from src.config import ConfigLoader
from src.logger import setup_logger


# -----------------------------
# Setup core components
# -----------------------------

logger = setup_logger()
loader = ConfigLoader()

# Load WAF configuration from config.json
waf_settings = loader.get_waf_config()

waf_config = WAFConfig(
    max_requests=waf_settings.get("max_requests", 5),
    time_window=waf_settings.get("time_window", 10),
    max_payload_size=waf_settings.get("max_payload_size", 500),
    sensitive_endpoints=waf_settings.get("sensitive_endpoints", ["/admin"]),
)

waf = WAFEngine(waf_config)

app = FastAPI(title="Behavior-Based Web Application Firewall")


# -----------------------------
# WAF Middleware
# -----------------------------

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    source_ip = request.client.host if request.client else "unknown"
    endpoint = request.url.path

    try:
        body_bytes = await request.body()
        payload = body_bytes.decode(errors="ignore")
    except Exception:
        payload = ""

    waf_request = WAFRequest(
        source=source_ip,
        endpoint=endpoint,
        payload=payload,
    )

    decision, reasons, score = waf.analyze(waf_request)

    if decision == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Request blocked by WAF",
                "reasons": reasons,
            },
        )

    response = await call_next(request)
    return response


# -----------------------------
# Example Endpoints
# -----------------------------

@app.get("/home")
def home():
    return {"message": "Welcome home"}


@app.get("/login")
def login():
    return {"message": "Login page"}


@app.get("/admin")
def admin():
    return {"message": "Admin panel"}
