# FastAPI Hello World for Heroku

This project runs FastAPI on Heroku with `uvicorn`.

## Files

- `main.py`: FastAPI app and routes
- `database.py`: SQLAlchemy engine and session setup
- `models.py`: database models
- `auth.py`: password hashing helpers
- `scripts/create_user.py`: bootstrap script for creating an app user
- `scripts/set_password.py`: reset an app user's password
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
export OPENAI_API_KEY=""
export OPENAI_MODEL="gpt-4o-mini"
```

`SECRET_KEY` is required. The app will not start without it.

`OPENAI_API_KEY` and `OPENAI_MODEL` are optional. If set, the Red Flag Catalog Assistant will use OpenAI to improve ranking/explanations while still staying catalog-only.

Run the database migration:

```bash
alembic upgrade head
```

Safer helper with local/remote targeting:

```bash
./scripts/migrate_db.sh local
./scripts/migrate_db.sh remote
```

Create your first user:

```bash
python scripts/create_user.py admin@example.com
python scripts/create_user.py admin@example.com remote
```

Bootstrap platform admin (for `/api/admin/*` and tenant management UI):

```bash
python scripts/create_platform_admin.py owner@amlinsights.local
AML_TARGET=remote python scripts/create_platform_admin.py owner@amlinsights.local
```

Migrate legacy `users` records into `app_users` after upgrading:

```bash
python scripts/migrate_users_to_app_users.py
```

Reset a user's password later if needed:

```bash
python scripts/set_password.py admin@example.com
python scripts/set_password.py admin@example.com remote
```

## 2) Run locally

```bash
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/`.

### Local DB Override Helper

When `.env` points to Heroku Postgres, use the helper below to force a local DB for development:

```bash
./scripts/start_local.sh
```

Optional arguments:

```bash
./scripts/start_local.sh app.db 8000
./scripts/start_local.sh /home/ehale/Documents/amlredflags/amlredflags_v2.db 8000
./scripts/start_local.sh sqlite:///./app.db 8001
```

### Share One Database Across `amlInsights` and `amlredflags`

Use the same `DATABASE_URL` in both apps.

- Local (SQLite): point both apps to the same file, for example:

```bash
export DATABASE_URL="sqlite:////home/ehale/Documents/amlInsights/app.db"
```

- Heroku (Postgres): point both apps to the same Postgres add-on URL.
- For Postgres, set the same schema in both apps (`DB_SCHEMA=public` is the simplest).

After changing `DATABASE_URL`, run migrations in both repos:

```bash
alembic upgrade head
```

Or run the helper from `amlInsights` to migrate both repos into one local SQLite file:

```bash
./scripts/migrate_shared_local.sh
```

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
