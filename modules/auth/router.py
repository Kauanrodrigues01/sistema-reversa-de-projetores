from modules.auth.schemas import (
    RefreshTokenRequestSchema,
    AccessTokenSchema,
    TokenSchema,
)
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from modules.users.models import User

from app.dependencies import T_Session
from app.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    verify_refresh_token,
    blacklist_token,
    is_token_blacklisted,
)

router = APIRouter(prefix='/auth', tags=['auth'])


@router.post('/login', response_model=TokenSchema)
def login_for_access_token(
    session: T_Session,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    user = session.scalar(select(User).where(User.email == form_data.username))

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
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


@router.post('/refresh', response_model=AccessTokenSchema)
def refresh_access_token(
    request: RefreshTokenRequestSchema, session: T_Session
):
    try:
        payload = verify_refresh_token(request.refresh_token)
        email = payload.get('sub')
        jti = payload.get('jti')
        
        if is_token_blacklisted(jti=jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Token has been blacklisted',
            )

        user = session.scalar(select(User).where(User.email == email))

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail='User not found'
            )

        new_access_token = create_access_token({'sub': user.email})

        return {'access_token': new_access_token, 'token_type': 'Bearer'}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Erro ao renovar token: {str(e)}',
        )


@router.post('/logout', status_code=status.HTTP_205_RESET_CONTENT)
def logout(request: RefreshTokenRequestSchema):
    try:
        blacklist_token(refresh_token=request.refresh_token)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Error during logout: {str(e)}',
        )


@router.post('/request-password-reset')
def request_password_reset():
    return {'message': 'Password reset request successful'}


@router.post('/reset-password')
def reset_password():
    return {'message': 'Password reset successful'}
