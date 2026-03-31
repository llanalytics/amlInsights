# FastAPI Hello World for Heroku

This project runs FastAPI on Heroku with `uvicorn`.

## Files

- `main.py`: FastAPI app
- `requirements.txt`: Python dependencies
- `Procfile`: Heroku process definition
- `.python-version`: Python version used by Heroku

## 1) Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Run locally (optional)

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

## Endpoints

- `GET /` -> hello world message
- `GET /health` -> health check
