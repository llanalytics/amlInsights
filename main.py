from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def hello_world() -> dict[str, str]:
    return {"message": "Hello, World from FastAPI on Heroku!"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
