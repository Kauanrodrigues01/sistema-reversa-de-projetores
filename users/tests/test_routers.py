from http import HTTPStatus

from sqlalchemy import select

from users.models import User


def test_create_user_success(client, session):
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
    user_data = {
        'username': user.username,  # duplicate username
        'password': 'secret',
    }

    response = client.post('/users/', json=user_data)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {'detail': 'Username already registered'}
