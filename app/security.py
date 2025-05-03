from datetime import datetime, timedelta
from http import HTTPStatus
from zoneinfo import ZoneInfo

import jwt
from fastapi import HTTPException
from jwt import ExpiredSignatureError, PyJWTError
from pwdlib import PasswordHash

from app.settings import settings

password_hash = PasswordHash.recommended()


def get_password_hash(plain_password: str):
    return password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str):
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(data_payload: dict) -> str:
    if 'sub' not in data_payload:
        raise ValueError("Payload must contain 'sub' field")

    to_encode = data_payload.copy()
    expire = datetime.now(tz=ZoneInfo('UTC')) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({
        'exp': int(expire.timestamp()),
        'iat': int(datetime.now(tz=ZoneInfo('UTC')).timestamp()),
        'type': 'access',
    })

    try:
        return jwt.encode(
            payload=to_encode,
            key=settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
    except PyJWTError as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f'Failed to generate access token: {str(e)}',
        )


def create_refresh_token(data_payload: dict) -> str:
    if 'sub' not in data_payload:
        raise ValueError("Payload must contain 'sub' field")

    to_encode = data_payload.copy()
    expire = datetime.now(tz=ZoneInfo('UTC')) + timedelta(
        hours=settings.REFRESH_TOKEN_EXPIRE_HOURS
    )

    to_encode.update({
        'exp': int(expire.timestamp()),
        'iat': int(datetime.now(tz=ZoneInfo('UTC')).timestamp()),
        'type': 'refresh',
    })

    try:
        return jwt.encode(
            payload=to_encode,
            key=settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
    except PyJWTError as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f'Failed to generate refresh token: {str(e)}',
        )


def verify_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )

        if payload.get('type') != 'refresh':
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST, detail='Invalid token type'
            )

        return payload

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail='Refresh token expired'
        )
    except PyJWTError:
        raise HTTPException(status_code=401, detail='Invalid refresh token')
