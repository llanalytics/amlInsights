# FastAPI Hello World for AWS Lambda

This project runs FastAPI on AWS Lambda using `Mangum` and AWS SAM, and it can also run on Heroku with `uvicorn`.

## Files

- `main.py`: FastAPI app + Lambda handler (`handler = Mangum(app)`)
- `requirements.txt`: Python dependencies
- `template.yaml`: AWS SAM infrastructure definition
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

## 3) Deploy to AWS Lambda with SAM

Prerequisites:
- AWS CLI configured (`aws configure`)
- AWS SAM CLI installed

Build and deploy:

```bash
sam build
sam deploy --guided
```

For future deploys (after guided setup):

```bash
sam build
sam deploy
```

After deploy, use the `ApiEndpoint` output URL.

## 4) Deploy to Heroku

Heroku does not use `template.yaml`. It uses `requirements.txt`, `.python-version`, and `Procfile`.

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
