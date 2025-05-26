from datetime import datetime, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

import jwt
import pytest
from fastapi import HTTPException, status
from jwt import PyJWTError

from app.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    password_hash,
    verify_password,
    verify_refresh_token,
    blacklist_token,
    is_token_blacklisted,
)
from app.settings import settings

from sqlalchemy.orm import Session

from app.security import get_current_user


# Fixtures
@pytest.fixture
def user_payload():
    return {'sub': 'user@example.com'}


# Tests for password hashing
def test_get_password_hash():
    """Test password hashing returns a hash"""
    password = 'securepassword123'
    hashed = get_password_hash(password)
    assert hashed != password
    assert isinstance(hashed, str)


def test_verify_password_correct():
    """Test password verification with correct password"""
    password = 'securepassword123'
    hashed = password_hash.hash(password)
    assert verify_password(password, hashed) is True


def test_verify_password_incorrect():
    """Test password verification with incorrect password"""
    password = 'securepassword123'
    wrong_password = 'wrongpassword'
    hashed = password_hash.hash(password)
    assert verify_password(wrong_password, hashed) is False


# Tests for token creation
def test_create_access_token_success(user_payload):
    """Test successful access token creation"""
    token = create_access_token(user_payload)
    assert isinstance(token, str)

    # Verify the token can be decoded
    payload = jwt.decode(
        token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    assert payload['sub'] == user_payload['sub']
    assert payload['type'] == 'access'


def test_create_access_token_missing_sub():
    """Test access token creation with missing sub field"""
    with pytest.raises(ValueError, match="Payload must contain 'sub' field"):
        create_access_token({})


def test_create_refresh_token_success(user_payload):
    """Test successful refresh token creation"""
    token = create_refresh_token(user_payload)
    assert isinstance(token, str)

    payload = jwt.decode(
        token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    assert payload['sub'] == user_payload['sub']
    assert payload['type'] == 'refresh'


def test_create_refresh_token_missing_sub():
    """Test refresh token creation with missing sub field"""
    with pytest.raises(ValueError, match="Payload must contain 'sub' field"):
        create_refresh_token({})


def test_create_refresh_token_jwt_error(user_payload):
    """Test error handling during refresh token creation using unittest.mock"""
    with patch('jwt.encode') as mock_encode:
        # Configura o mock para levantar uma exceção
        mock_encode.side_effect = PyJWTError('Mocked JWT encoding error')

        # Testa a função
        with pytest.raises(HTTPException) as exc_info:
            create_refresh_token(user_payload)

        # Verificações
        assert (
            exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        assert (
            'Failed to generate refresh token: Mocked JWT encoding error'
            in str(exc_info.value.detail)
        )
        mock_encode.assert_called_once()


# Tests for token verification
def test_verify_refresh_token_success(user_payload):
    """Test successful refresh token verification"""
    token = create_refresh_token(user_payload)
    payload = verify_refresh_token(token)
    assert payload['sub'] == user_payload['sub']


def test_verify_refresh_token_expired(user_payload):
    """Test verification of expired refresh token"""
    # Create an expired token
    expired_payload = user_payload.copy()
    expired_payload['exp'] = int(
        (datetime.now(tz=ZoneInfo('UTC')) - timedelta(hours=1)).timestamp()
    )
    expired_payload['type'] = 'refresh'
    token = jwt.encode(
        expired_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token(token)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == 'Refresh token expired'


def test_verify_refresh_token_invalid_type(user_payload):
    """Test verification with wrong token type"""
    access_token = create_access_token(user_payload)
    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token(access_token)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == 'Invalid token type'


def test_verify_refresh_token_invalid_signature(user_payload):
    """Test verification with invalid signature"""
    token = create_refresh_token(user_payload)
    # Tamper with the token
    tampered_token = token[:-5] + 'aaaaa'
    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token(tampered_token)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == 'Invalid refresh token'


def test_verify_refresh_token_malformed():
    """Test verification with malformed token"""
    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token('not.a.real.token')
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == 'Invalid refresh token'


# Tests for error handling in token creation
def test_token_creation_jwt_error(user_payload, monkeypatch):
    """Test error handling during token creation"""

    def mock_jwt_encode(*args, **kwargs):
        raise jwt.PyJWTError('Mocked error')

    monkeypatch.setattr(jwt, 'encode', mock_jwt_encode)

    with pytest.raises(HTTPException) as exc_info:
        create_access_token(user_payload)
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert 'Failed to generate access token' in exc_info.value.detail


# Edge cases
def test_token_expiration_calculation(user_payload):
    """Test token expiration timing is correct"""
    now = datetime.now(tz=ZoneInfo('UTC'))
    token = create_access_token(user_payload)
    payload = jwt.decode(
        token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )

    expected_exp = now + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    assert payload['exp'] == int(expected_exp.timestamp())


def test_refresh_token_longer_expiration(user_payload):
    """Test refresh token has longer expiration than access token"""
    access_token = create_access_token(user_payload)
    refresh_token = create_refresh_token(user_payload)

    access_payload = jwt.decode(
        access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    refresh_payload = jwt.decode(
        refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )

    assert refresh_payload['exp'] > access_payload['exp']


# Tests for get_current_user function
def test_get_current_user_valid_token(session: Session, user, create_token):
    """Test get_current_user returns the user when token is valid"""
    token_data = create_token(user)
    current_user = get_current_user(session=session, token=token_data['access_token'])

    assert current_user is not None
    assert current_user.email == user.email


def test_get_current_user_user_not_found(session: Session, create_token, user):
    """Test get_current_user raises 401 if user is not found in DB"""
    # Gera token com email válido
    token_data = create_token(user)

    # Remove o user da sessão para simular usuário inexistente
    session.delete(user)
    session.commit()

    with pytest.raises(HTTPException) as exc:
        get_current_user(session=session, token=token_data['access_token'])

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.detail == "Could not validate credentials"


def test_get_current_user_with_invalid_token(session: Session):
    """Test get_current_user raises 401 for an invalid token"""
    fake_token = "invalid.token.string"

    with pytest.raises(HTTPException) as exc:
        get_current_user(session=session, token=fake_token)

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.detail == "Could not validate credentials"


def test_get_current_user_with_expired_token(session: Session, user):
    """Test get_current_user raises 401 for an expired token"""
    expired_payload = {
        "sub": user.email,
        "exp": 0  # tempo de expiração já expirado
    }
    expired_token = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    with pytest.raises(HTTPException) as exc:
        get_current_user(session=session, token=expired_token)

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.detail == "Token expired"


def test_get_current_user_with_none_token(session: Session):
    """Test get_current_user returns None when token is None"""
    result = get_current_user(session=session, token=None)

    assert result is None


# Tests for blacklisting tokens

@pytest.fixture
def token_payload():
    return {
        'jti': 'unique-token-id',
        'exp': int((datetime.utcnow() + timedelta(minutes=5)).timestamp())
    }

@pytest.fixture
def fake_token(token_payload, user, create_token):
    return create_token(user)['refresh_token']

@patch('app.security.redis_client')
@patch('app.security.jwt.decode')
def test_blacklist_token_success(mock_jwt_decode, mock_redis_client, fake_token, token_payload):
    mock_jwt_decode.return_value = token_payload

    blacklist_token(fake_token)

    mock_redis_client.set.assert_called_once_with(
        f'blacklist:{token_payload['jti']}',
        ex=token_payload['exp'],
        value='true',
        nx=True
    )

@patch('app.security.jwt.decode')
def test_blacklist_token_missing_jti_or_exp(mock_jwt_decode):
    mock_jwt_decode.return_value = {}

    with pytest.raises(HTTPException) as exc_info:
        blacklist_token('invalid-token')
    
    assert exc_info.value.status_code == 400
    assert 'missing jti or exp' in str(exc_info.value.detail)

@patch('app.security.redis_client')
@patch('app.security.jwt.decode')
def test_is_token_blacklisted_true(mock_jwt_decode, mock_redis_client, fake_token, token_payload):
    mock_jwt_decode.return_value = token_payload
    mock_redis_client.exists.return_value = 1

    result = is_token_blacklisted(refresh_token=fake_token)
    assert result is True

@patch('app.security.redis_client')
@patch('app.security.jwt.decode')
def test_is_token_blacklisted_false(mock_jwt_decode, mock_redis_client, fake_token, token_payload):
    mock_jwt_decode.return_value = token_payload
    mock_redis_client.exists.return_value = 0

    result = is_token_blacklisted(refresh_token=fake_token)
    assert result is False

def test_is_token_blacklisted_missing_jti():
    with pytest.raises(HTTPException) as exc_info:
        is_token_blacklisted(refresh_token=None, jti=None)
    
    assert exc_info.value.status_code == 400
    assert 'jti not found' in str(exc_info.value.detail)
