import pytest
from factory.base import Factory
from factory.declarations import LazyAttribute, Sequence
from sqlalchemy.orm import Session

from users.models import User


class UserFactory(Factory):
    class Meta:
        model = User

    username = Sequence(lambda n: f'User {n}')
    password = LazyAttribute(lambda obj: f'{obj.username}@Password8965')


@pytest.fixture
def user(session: Session):
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
