import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import config
from app.routers import tickets, auth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)-5s %(name)s - %(message)s"
)

logger = logging.getLogger("main")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    logger.info("================================================================================")
    logger.info(" Starting Enterprise IT Assistant FastAPI Server...")
    logger.info(f" Configured Model 1: {config.model1_name} ({config.model1_base_url})")
    logger.info(f" Configured Model 2: {config.model2_name} ({config.model2_base_url})")
    logger.info("================================================================================")
    yield

app = FastAPI(
    title="Enterprise IT Incident & Service Desk Assistant",
    description="Python Enterprise IT Assistant with Web Standard Security and RBAC",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tickets.router)
app.include_router(auth.router)
app.include_router(auth.router, prefix="/api/v1")


def main():
    import uvicorn
    uvicorn.run("app.main:app", host=config.server_host, port=config.server_port, reload=False)


if __name__ == "__main__":
    main()
