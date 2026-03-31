# FastAPI Hello World for Heroku

This project runs FastAPI on Heroku with `uvicorn`.

## Files

- `main.py`: FastAPI app and routes
- `database.py`: SQLAlchemy engine and session setup
- `models.py`: database models
- `auth.py`: password hashing helpers
- `create_user.py`: bootstrap script for creating a user
- `set_password.py`: reset a user's password
- `alembic/`: database migrations
- `requirements.txt`: Python dependencies
- `Procfile`: Heroku process definition
- `.python-version`: Python version used by Heroku

## 1) Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Set environment variables:

```bash
export SECRET_KEY="replace-this-with-a-long-random-secret"
export DATABASE_URL="sqlite:///./app.db"
```

Run the database migration:

```bash
alembic upgrade head
```

Create your first user:

```bash
python create_user.py admin
```

Reset a user's password later if needed:

```bash
python set_password.py admin
```

## 2) Run locally

```bash
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/`.

## 3) Deploy to Heroku

This repo targets Python `3.13` for Heroku, which is a currently supported major version.

Create the app and deploy:

```bash
heroku create
git add .
git commit -m "Add Heroku deployment support"
git push heroku main
```

Then open the app:

```bash
heroku open
```

For a database on Heroku, provision Postgres and keep `SECRET_KEY` set:

```bash
heroku addons:create heroku-postgresql:essential-0
heroku config:set SECRET_KEY="replace-this-with-a-long-random-secret"
```

Heroku now runs migrations automatically during deploy via the `release` process in [`Procfile`](/home/ehale/Documents/test1/Procfile#L1).

## Endpoints

- `GET /` -> homepage
- `GET /login` -> login form
- `GET /dashboard` -> protected page
- `GET /health` -> health check
