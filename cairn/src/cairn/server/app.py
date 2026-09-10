from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server import db
from cairn.server.routers import ctf, export, hints, intents, projects, settings, research, research_runtime_status, research_identities, research_sources, research_source_compare

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    yield


app = FastAPI(
    title="Cairn",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(export.router)
app.include_router(ctf.router)
app.include_router(research.router)
app.include_router(research_runtime_status.router)
app.include_router(research_identities.router)
app.include_router(research_sources.router)
app.include_router(research_source_compare.router)


@app.get("/", include_in_schema=False)
def index():
    """The legacy global index (vulnerability mining UI) was removed; land the
    operator on the current research workbench."""
    return RedirectResponse(url="/research", status_code=302)


@app.get("/research", include_in_schema=False)
@app.get("/research/", include_in_schema=False)
def research_index():
    return FileResponse(STATIC_DIR / "research" / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
