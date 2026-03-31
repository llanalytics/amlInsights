from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

app = FastAPI()
app.add_middleware(HTTPSRedirectMiddleware)
templates = Jinja2Templates(directory="templates")


@app.get("/")
def hello_world(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Test1",
            "heading": "Hello, World from FastAPI on Heroku!",
            "message": "The app is running and serving HTML with Jinja2 templates.",
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
