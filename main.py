from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()


@app.get("/")
def hello_world() -> dict[str, str]:
    return {"message": "Hello, World from FastAPI on AWS Lambda!"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


handler = Mangum(app)
