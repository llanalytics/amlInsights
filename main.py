import os
import secrets

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

from auth import hash_password, needs_rehash, verify_password
from database import SessionLocal
from models import User

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required.")

app = FastAPI()
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="lax",
    max_age=60 * 60 * 8,
)
templates = Jinja2Templates(directory="templates")


def get_db() -> Session:
    return SessionLocal()


def is_authenticated(request: Request) -> bool:
    return "user" in request.session


def get_csrf_token(request: Request) -> str:
    csrf_token = request.session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = csrf_token
    return csrf_token


def validate_csrf(request: Request, csrf_token: str) -> None:
    session_token = request.session.get("csrf_token")
    if not session_token or not secrets.compare_digest(session_token, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


@app.get("/")
def hello_world(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "AML Insights",
            "heading": "Hello, World from FastAPI on Heroku!",
            "message": "The app is running and serving HTML with Jinja2 templates.",
            "is_authenticated": is_authenticated(request),
            "user": request.session.get("user"),
            "csrf_token": get_csrf_token(request),
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
            "csrf_token": get_csrf_token(request),
        },
    )


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    validate_csrf(request, csrf_token)
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
            "csrf_token": get_csrf_token(request),
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
            "csrf_token": get_csrf_token(request),
        },
    )


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
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
