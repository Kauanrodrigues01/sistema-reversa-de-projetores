import pytest
from factory.base import Factory
from factory.declarations import LazyAttribute
from factory.faker import Faker
from sqlalchemy.orm import Session

from users.models import User


class UserFactory(Factory):
    class Meta:
        model = User

    email = Faker('email')
    name = Faker('name')
    password = LazyAttribute(lambda obj: f'{obj.name}@Password8965')


@pytest.fixture
def user(session: Session):
    user = UserFactory()
    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@pytest.fixture
def user2(session: Session):
    user = UserFactory()
    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@pytest.fixture
def list_with_10_users(session: Session):
    users = UserFactory.create_batch(10)
    session.bulk_save_objects(users)
    session.commit()

    return users
