from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.dependencies import T_Session
from app.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    verify_refresh_token,
)
from auth.schemas import (
    RefreshTokenRequestSchema,
    RefreshTokenSchema,
    TokenSchema,
)
from users.models import User

router = APIRouter(prefix='/auth', tags=['auth'])


@router.post('/token', response_model=TokenSchema)
def login_for_access_token(
    session: T_Session,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    user = session.scalar(select(User).where(User.email == form_data.username))

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail='Incorrect email or password',
        )

    data_payload = {'sub': user.email}

    access_token = create_access_token(data_payload)
    refresh_token = create_refresh_token(data_payload)

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
    }


@router.post('/token/refresh', response_model=RefreshTokenSchema)
def refresh_access_token(
    request: RefreshTokenRequestSchema, session: T_Session
):
    try:
        payload = verify_refresh_token(request.refresh_token)
        user_email = payload.get('sub')

        user = session.scalar(select(User).where(User.email == user_email))

        if not user:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail='User not found'
            )

        new_access_token = create_access_token({'sub': user.email})

        return {'access_token': new_access_token, 'token_type': 'Bearer'}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f'Erro ao renovar token: {str(e)}',
        )
