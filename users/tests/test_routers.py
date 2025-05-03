from fastapi import status
from sqlalchemy import select

from app.security import verify_password
from users.models import User
from users.schemas import UserPublicSchema


def test_create_user_success(client, session):
    """Tests successful user creation with valid data"""
    user_data = {
        'email': 'test@example.com',
        'name': 'test name',
        'password': 'secret',
    }

    response = client.post('/users', json=user_data)

    response_user_data = user_data.copy()
    del response_user_data['password']
    response_user_data['id'] = 1

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == response_user_data

    db_user = session.scalar(
        select(User).where((User.id == 1) & (User.email == user_data['email']))
    )

    assert db_user is not None


def test_create_user_password_is_hashed_correctly(client, session):
    """Tests if the user's password is properly hashed and verifiable upon creation"""
    user_data = {
        'email': 'test@example.com',
        'name': 'test name',
        'password': 'secret',
    }

    client.post('/users', json=user_data)

    db_user = session.scalar(
        select(User).where((User.id == 1) & (User.email == user_data['email']))
    )

    assert verify_password(
        plain_password=user_data['password'], hashed_password=db_user.password
    )


def test_create_user_with_duplicate_email(client, user):
    """Tests user creation fails when email already exists"""
    user_data = {
        'email': user.email,
        'name': 'test name',
        'password': 'secret',
    }

    response = client.post('/users', json=user_data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {'detail': 'Email already registered'}


def test_read_users_success(client):
    """Tests empty user list is returned when no users exist"""
    response = client.get('/users')

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


def test_read_users_with_user_success(client, user):
    """Tests single user is returned correctly in list"""
    response = client.get('/users')

    user_schema = UserPublicSchema.model_validate(user.__dict__)
    user_data = user_schema.model_dump()

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == [user_data]


def test_read_users_with_skip_param(client, list_with_10_users):
    """Tests pagination works correctly with skip parameter"""
    response = client.get('/users?skip=5')

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 5


def test_read_users_with_limit_param(client, list_with_10_users):
    """Tests pagination works correctly with limit parameter"""
    response = client.get('/users?limit=3')

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 3


def test_read_users_with_skip_and_limit(client, list_with_10_users):
    """Tests combined skip and limit parameters work correctly"""
    response = client.get('/users?skip=2&limit=4')
    json_response = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert len(json_response) == 4
    assert (
        json_response[0]['id'] == 3
    )  # check if really skipped the first 2 items


def test_read_users_empty_with_high_skip(client, list_with_10_users):
    """Tests empty list is returned when skip exceeds total users"""
    response = client.get('/users?skip=20')

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


def test_patch_user_success(client, session, user):
    """Tests if successfully updates email, name, and password."""
    user_update_data = {
        'email': 'test_update@gmail.com',
        'name': 'test update name',
        'password': 'test_new_password',
    }

    response = client.patch(
        f'/users/{user.id}',
        json=user_update_data,
    )
    json_response = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert json_response['email'] == user_update_data['email']
    assert json_response['name'] == user_update_data['name']

    db_user = session.get(User, user.id)

    assert db_user.email == user_update_data['email']
    assert db_user.name == user_update_data['name']
    assert verify_password(
        plain_password=user_update_data['password'],
        hashed_password=db_user.password,
    )


def test_patch_user_updates_only_email(client, session, user):
    """Tests if updates only email field when provided alone."""
    user_update_data = {
        'email': 'test_update@gmail.com',
    }

    response = client.patch(
        f'/users/{user.id}',
        json=user_update_data,
    )
    json_response = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert json_response['email'] == user_update_data['email']

    db_user = session.get(User, user.id)

    assert db_user.email == user_update_data['email']


def test_patch_user_updates_only_name(client, session, user):
    """Tests if updates only name field when provided alone."""
    user_update_data = {
        'name': 'test update name',
    }

    response = client.patch(
        f'/users/{user.id}',
        json=user_update_data,
    )
    json_response = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert json_response['name'] == user_update_data['name']

    db_user = session.get(User, user.id)

    assert db_user.name == user_update_data['name']


def test_patch_user_updates_only_password(client, session, user):
    """Tests if updates and hashes password when provided alone."""
    user_update_data = {'password': 'test_new_password'}

    response = client.patch(
        f'/users/{user.id}',
        json=user_update_data,
    )

    assert response.status_code == status.HTTP_200_OK

    db_user = session.get(User, user.id)

    assert verify_password(
        plain_password=user_update_data['password'],
        hashed_password=db_user.password,
    )


def test_patch_user_returns_not_found(client):
    """Tests if returns 404 when user doesn't exist."""
    response = client.patch(
        '/users/100000000',
        json={},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {'detail': 'User not found'}


def test_patch_user_rejects_duplicate_email(client, user, user2):
    """Tests if rejects already registered email."""
    user_update_data = {
        'email': user2.email,
        'name': 'test update name',
        'password': 'test_new_password',
    }

    response = client.patch(
        f'/users/{user.id}',
        json=user_update_data,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()['detail'] == 'Email already registered'


def test_delete_user_success(client, user, session):
    """Tests if a user is correctly deleted from the database"""
    response = client.delete(f'/users/{user.id}')

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not response.text

    db_user = session.scalar(select(User).where(User.id == user.id))
    assert db_user is None


def test_delete_user_returns_not_found_for_invalid_id(client):
    """Tests the response when trying to delete a non-existent user"""
    response = client.delete('/users/100000')

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {'detail': 'User not found'}
