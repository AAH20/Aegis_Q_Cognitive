"""FastAPI entrypoint for AQC compliance-as-a-service (optional ``[api]`` extra)."""

from __future__ import annotations

import os

from fastapi import FastAPI

from aqc_api import __version__
from aqc_api.routers import compliance

app = FastAPI(
    title="Aegis Quantum-Cognitive API",
    description=(
        "Upload PCAP or CycloneDX CBOM JSON — receive a combined FDA e-STAR + "
        "NSM-10 narrative PDF. Unlicensed tier embeds a non-submittable watermark."
    ),
    version=__version__,
    openapi_tags=[
        {
            "name": "compliance",
            "description": "FDA / DoD compliance document generation",
        },
    ],
)

app.include_router(compliance.router, prefix="/api/v1", tags=["compliance"])


@app.get("/healthz", tags=["meta"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def main() -> None:
    import uvicorn

    host = os.environ.get("AQC_API_HOST", "0.0.0.0")
    port = int(os.environ.get("AQC_API_PORT", os.environ.get("PORT", "8080")))
    uvicorn.run(
        "aqc_api.main:app",
        host=host,
        port=port,
        factory=False,
    )


if __name__ == "__main__":
    main()
