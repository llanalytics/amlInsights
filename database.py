import os

from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def get_database_url() -> str:
    database_url = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


DATABASE_URL = get_database_url()
DB_SCHEMA = None
if not DATABASE_URL.startswith("sqlite"):
    configured_schema = os.environ.get("DB_SCHEMA", "").strip().strip("'\"")
    if configured_schema.lower() in {"", "none", "null"}:
        DB_SCHEMA = None
    else:
        DB_SCHEMA = configured_schema


class Base(DeclarativeBase):
    metadata = MetaData(schema=DB_SCHEMA)


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
