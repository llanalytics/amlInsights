import os

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

from auth import hash_password, needs_rehash, verify_password
from database import SessionLocal
from models import User

app = FastAPI()
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
)
templates = Jinja2Templates(directory="templates")


def get_db() -> Session:
    return SessionLocal()


def is_authenticated(request: Request) -> bool:
    return "user" in request.session


@app.get("/")
def hello_world(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Test1",
            "heading": "Hello, World from FastAPI on Heroku!",
            "message": "The app is running and serving HTML with Jinja2 templates.",
            "is_authenticated": is_authenticated(request),
            "user": request.session.get("user"),
        },
    )


@app.get("/login")
def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "title": "Login",
            "error": None,
            "has_users": has_users(),
        },
    )


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = get_db()

    try:
        user = db.query(User).filter(User.username == username).first()
        if user and verify_password(password, user.password_hash):
            if needs_rehash(user.password_hash):
                user.password_hash = hash_password(password)
                db.commit()
            request.session["user"] = user.username
            return RedirectResponse(url="/dashboard", status_code=303)
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "title": "Login",
            "error": "Invalid username or password.",
            "has_users": has_users(),
        },
        status_code=401,
    )


@app.get("/dashboard")
def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "title": "Dashboard",
            "user": request.session["user"],
        },
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


def has_users() -> bool:
    db = get_db()
    try:
        return db.query(User.id).first() is not None
    finally:
        db.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
