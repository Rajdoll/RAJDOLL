"""FastAPI application entry point for the `api` service."""

from fastapi import FastAPI

from rajdoll import __version__


def create_app() -> FastAPI:
    app = FastAPI(title="RAJDOLL", version=__version__, docs_url=None, redoc_url=None)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "api", "version": __version__}

    return app


app = create_app()
