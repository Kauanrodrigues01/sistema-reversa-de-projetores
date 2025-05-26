import pytest
from factory.base import Factory
from factory.declarations import LazyAttribute
from factory.faker import Faker
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import get_session, table_registry
from app.main import app
from app.security import get_password_hash, create_access_token, create_refresh_token
from modules.users.models import User


class UserFactory(Factory):
    class Meta:
        model = User

    email = Faker('email')
    name = Faker('name')
    password = LazyAttribute(lambda obj: f'{obj.name}@Password8965')


@pytest.fixture
def client(session):
    def get_session_override():
        return session

    with TestClient(app) as client:
        app.dependency_overrides[get_session] = get_session_override
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def user(session: Session):
    password = 'testtest'
    user = UserFactory(password=get_password_hash(password))
    session.add(user)
    session.commit()
    session.refresh(user)

    user.clean_password = password

    return user


@pytest.fixture
def user2(session: Session):
    password = 'testtest'
    user = UserFactory(password=get_password_hash(password))
    session.add(user)
    session.commit()
    session.refresh(user)

    user.clean_password = password

    return user


@pytest.fixture
def list_with_10_users(session: Session):
    users = UserFactory.create_batch(10)
    session.bulk_save_objects(users)
    session.commit()

    return users


@pytest.fixture
def session():
    engine = create_engine(
        'sqlite:///:memory:',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )

    table_registry.metadata.create_all(engine)

    with Session(engine) as session:
        yield session

    table_registry.metadata.drop_all(engine)


@pytest.fixture
def create_token():
    def _create_token(user: User):
        access_token = create_access_token({'sub': user.email})
        refresh_token = create_refresh_token({'sub': user.email})
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }
    return _create_token
