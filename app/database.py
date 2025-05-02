from sqlalchemy import create_engine
from sqlalchemy.orm import Session, registry

from app.settings import settings

table_registry = registry()

engine = create_engine(settings.DATABASE_URL)


def get_session():
    with Session(engine) as session:
        yield session
