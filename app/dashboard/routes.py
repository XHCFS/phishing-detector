from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import pathlib

router = APIRouter()
templates = Jinja2Templates(directory=str(pathlib.Path(__file__).parent / "templates"))

@router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "title": "Dashboard"})

