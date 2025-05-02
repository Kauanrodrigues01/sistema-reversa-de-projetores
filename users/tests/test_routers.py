from http import HTTPStatus

from sqlalchemy import select

from users.models import User
from users.schemas import UserPublicSchema


def test_create_user_success(client, session):
    """Tests successful user creation with valid data"""
    user_data = {
        'username': 'test_name',
        'password': 'secret',
    }

    response = client.post('/users', json=user_data)

    response_user_data = user_data.copy()
    del response_user_data['password']
    response_user_data['id'] = 1

    assert response.status_code == HTTPStatus.CREATED
    assert response.json() == response_user_data

    db_user = session.scalar(
        select(User).where(
            (User.id == 1) & (User.username == user_data['username'])
        )
    )

    assert db_user is not None


def test_create_user_with_duplicate_username(client, user):
    """Tests user creation fails when username already exists"""
    user_data = {
        'username': user.username,  # duplicate username
        'password': 'secret',
    }

    response = client.post('/users/', json=user_data)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {'detail': 'Username already registered'}


def test_read_users_success(client):
    """Tests empty user list is returned when no users exist"""
    response = client.get('/users')

    assert response.status_code == HTTPStatus.OK
    assert response.json() == []


def test_read_users_with_user_success(client, user):
    """Tests single user is returned correctly in list"""
    response = client.get('/users')

    user_schema = UserPublicSchema.model_validate(user.__dict__)
    user_data = user_schema.model_dump()

    assert response.status_code == HTTPStatus.OK
    assert response.json() == [user_data]


def test_read_users_with_skip_param(client, list_with_10_users):
    """Tests pagination works correctly with skip parameter"""
    response = client.get('/users?skip=5')

    assert response.status_code == HTTPStatus.OK
    assert len(response.json()) == 5


def test_read_users_with_limit_param(client, list_with_10_users):
    """Tests pagination works correctly with limit parameter"""
    response = client.get('/users?limit=3')

    assert response.status_code == HTTPStatus.OK
    assert len(response.json()) == 3


def test_read_users_with_skip_and_limit(client, list_with_10_users):
    """Tests combined skip and limit parameters work correctly"""
    response = client.get('/users?skip=2&limit=4')
    json_response = response.json()

    assert response.status_code == HTTPStatus.OK
    assert len(json_response) == 4
    assert (
        json_response[0]['id'] == 3
    )  # check if really skipped the first 2 items


def test_read_users_empty_with_high_skip(client, list_with_10_users):
    """Tests empty list is returned when skip exceeds total users"""
    response = client.get('/users?skip=20')

    assert response.status_code == HTTPStatus.OK
    assert response.json() == []
