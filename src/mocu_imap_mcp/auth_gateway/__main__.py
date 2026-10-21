import logging

import uvicorn

from .app import create_gateway
from .config import GatewaySettings
from .provider import Provider


def main() -> None:
    # Third-party HTTP debug logs can contain OAuth URLs or credentials. Never enable them here.
    logging.basicConfig(level=logging.WARNING)
    for name in ("authlib", "requests", "urllib3", "httpx", "httpcore"):
        logging.getLogger(name).disabled = True
    try:
        settings = GatewaySettings()  # type: ignore[call-arg]  # populated by environment
        provider = Provider(settings)
        # Validate local secrets now. Discovery is verified on first authentication;
        # provider downtime must deny access without creating a proxy startup cycle.
        with provider.client():
            pass
    except Exception:
        logging.error("Auth gateway preflight failed; check provider and configuration")
        raise SystemExit(1) from None
    uvicorn.run(create_gateway(settings, provider), host=settings.gateway_bind, port=settings.gateway_port,
                access_log=False, proxy_headers=False, log_level="warning")


if __name__ == "__main__":
    main()
