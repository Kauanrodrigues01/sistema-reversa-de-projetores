import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from jwt import ExpiredSignatureError, PyJWTError
from pwdlib import PasswordHash

from app.settings import settings
from app.database import get_session
from app.redis import redis_client
from modules.users.models import User

password_hash = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/token', auto_error=False)


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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Failed to generate access token: {str(e)}',
        )


def create_refresh_token(data_payload: dict) -> str:
    if 'sub' not in data_payload:
        raise ValueError("Payload must contain 'sub' field")

    to_encode = data_payload.copy()
    
    jti = str(uuid.uuid4())
    expire = datetime.now(tz=ZoneInfo('UTC')) + timedelta(
        hours=settings.REFRESH_TOKEN_EXPIRE_HOURS
    )

    to_encode.update({
        'jti': jti,
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Failed to generate refresh token: {str(e)}',
        )


def verify_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )

        if payload.get('type') != 'refresh':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Invalid token type',
            )

        return payload

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Refresh token expired',
        )
    except PyJWTError:
        raise HTTPException(status_code=401, detail='Invalid refresh token')


def get_current_user(
    session: Session = Depends(get_session),
    token: str = Depends(oauth2_scheme)
):
    if token is None:
        return None

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        payload = jwt.decode(
            token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        email = payload.get('sub')
        
        current_user = session.scalar(
            select(User).where(User.email == email)
        )

        if current_user is None:
            raise credentials_exception

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Token expired',
        )

    except PyJWTError:
        raise credentials_exception
    
    return current_user


def blacklist_token(refresh_token: str):
    """Invalidate a refresh_token by storing its jti in Redis with an expiration time."""
    try:
        payload = jwt.decode(refresh_token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get('jti')
        exp = payload.get('exp')
    
        if exp is None or jti is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Invalid token: missing jti or exp',
            )

        redis_client.set(
            f'blacklist:{jti}',
            ex=exp,
            value='true',
            nx=True  # Only set if the key does not already exist
        )
    except PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'Invalid token: {str(e)}',
        )
    


def is_token_blacklisted(refresh_token: str = None, jti: str = None) -> bool:
    """Check if a token is blacklisted by checking its jti in Redis."""
    if refresh_token:
        payload = jwt.decode(refresh_token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get('jti')
    
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid token: jti not found',
        )
    
    return redis_client.exists(f'blacklist:{jti}') > 0

