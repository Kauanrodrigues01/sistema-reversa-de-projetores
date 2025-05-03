import datetime
from unittest.mock import patch
from zoneinfo import ZoneInfo

import jwt
import pytest
from fastapi import status
from freezegun import freeze_time

from app.settings import settings
from auth.schemas import TokenSchema


def test_login_success(client, user):
    """Tests successful login with valid credentials"""
    response = client.post(
        '/auth/token',
        data={
            'username': user.email,
            'password': user.clean_password,
            'grant_type': 'password',
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert TokenSchema(**response.json())

    data = response.json()
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert data['token_type'] == 'Bearer'


def test_login_invalid_credentials(client, user):
    """Tests login with invalid credentials"""
    response = client.post(
        '/auth/token',
        data={
            'username': user.email,
            'password': 'wrong_password',
            'grant_type': 'password',
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()['detail'] == 'Incorrect email or password'


def test_login_nonexistent_user(client):
    """Tests login with non-existent user"""
    response = client.post(
        '/auth/token',
        data={
            'username': 'nonexistent@example.com',
            'password': 'any_password',
            'grant_type': 'password',
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()['detail'] == 'Incorrect email or password'


def test_refresh_token_success(client, user):
    """Tests token refresh with valid refresh_token"""
    login_response = client.post(
        '/auth/token',
        data={
            'username': user.email,
            'password': user.clean_password,
            'grant_type': 'password',
        },
    )
    refresh_token = login_response.json()['refresh_token']

    response = client.post(
        '/auth/token/refresh', json={'refresh_token': refresh_token}
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert 'access_token' in data
    assert data['token_type'] == 'Bearer'
    assert 'refresh_token' not in data


def test_refresh_invalid_token(client):
    """Tests refresh with invalid token"""
    response = client.post(
        '/auth/token/refresh', json={'refresh_token': 'invalid_token'}
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()['detail'] == 'Invalid refresh token'


def test_refresh_token_for_nonexistent_user(client):
    """Tests refresh for non-existent user"""
    refresh_token = jwt.encode(
        {
            'sub': 'deleted@example.com',
            'exp': datetime.datetime.now(tz=ZoneInfo('UTC'))
            + datetime.timedelta(hours=1),
            'type': 'refresh',
        },
        key=settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    response = client.post(
        '/auth/token/refresh', json={'refresh_token': refresh_token}
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()['detail'] == 'User not found'


def test_refresh_with_access_token(client, user):
    """Tests using access_token as refresh_token"""
    login_response = client.post(
        '/auth/token',
        data={
            'username': user.email,
            'password': user.clean_password,
            'grant_type': 'password',
        },
    )
    access_token = login_response.json()['access_token']

    response = client.post(
        '/auth/token/refresh', json={'refresh_token': access_token}
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()['detail'] == 'Invalid token type'


def test_token_expiration(client, user):
    """Tests token expiration behavior"""
    # Get initial tokens
    now = datetime.datetime(2025, 4, 27, 12, 0, 0)

    with freeze_time(now):
        response = client.post(
            '/auth/token',
            data={
                'username': user.email,
                'password': user.clean_password,
                'grant_type': 'password',
            },
        )
        access_token = response.json()['access_token']
        refresh_token = response.json()['refresh_token']

    # Test access token just before expiration
    access_expire_time = now + datetime.timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES - 1
    )
    with freeze_time(access_expire_time):
        payload = jwt.decode(
            access_token,
            key=settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        assert payload['sub'] == user.email

    # Test access token after expiration
    access_expired_time = now + datetime.timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES + 1
    )
    with freeze_time(access_expired_time):
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(
                access_token,
                key=settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )

    # Test refresh token just before expiration
    refresh_expire_time = now + datetime.timedelta(
        hours=settings.REFRESH_TOKEN_EXPIRE_HOURS - 1
    )
    with freeze_time(refresh_expire_time):
        response = client.post(
            '/auth/token/refresh', json={'refresh_token': refresh_token}
        )
        assert response.status_code == status.HTTP_200_OK

    # Test refresh token after expiration
    refresh_expired_time = now + datetime.timedelta(
        hours=settings.REFRESH_TOKEN_EXPIRE_HOURS + 1
    )
    with freeze_time(refresh_expired_time):
        response = client.post(
            '/auth/token/refresh', json={'refresh_token': refresh_token}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()['detail'] == 'Refresh token expired'


def test_refresh_token_unexpected_error(client, session, user):
    """Tests handling of unexpected exceptions during token refresh"""
    # First get a valid refresh token
    login_response = client.post(
        '/auth/token',
        data={
            'username': user.email,
            'password': user.clean_password,
            'grant_type': 'password',
        },
    )
    refresh_token = login_response.json()['refresh_token']

    # Specific mock for the function used in the router
    with patch('auth.router.verify_refresh_token') as mock_verify:
        mock_verify.side_effect = Exception('Unexpected database error')

        response = client.post(
            '/auth/token/refresh', json={'refresh_token': refresh_token}
        )

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert 'Unexpected database error' in response.json()['detail']
