from http import HTTPStatus

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.dependencies import T_FilterPage, T_Session
from app.security import get_password_hash
from users import utils
from users.models import User
from users.schemas import (
    UserPublicSchema,
    UserSchema,
    UserUpdateSchema,
)

router = APIRouter(prefix='/users', tags=['users'])


@router.post(
    '', response_model=UserPublicSchema, status_code=HTTPStatus.CREATED
)
def create_user(user: UserSchema, session: T_Session):
    utils.verify_duplicate_email(email=user.email, session=session)

    db_user = User(
        email=user.email,
        name=user.name,
        password=get_password_hash(user.password),
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@router.get('', response_model=list[UserPublicSchema])
def list_users(session: T_Session, filter_page: T_FilterPage):
    users = session.scalars(
        select(User).offset(filter_page.skip).limit(filter_page.limit)
    ).all()
    return users


@router.patch('/{user_id}', response_model=UserPublicSchema)
def update_user(user: UserUpdateSchema, session: T_Session, user_id: int):
    db_user = session.scalar(select(User).where(User.id == user_id))

    if not db_user:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail='User not found.'
        )

    utils.verify_duplicate_email(
        email=user.email, session=session, user_id=db_user.id
    )

    for key, value in user.model_dump(exclude_unset=True).items():
        if key == 'password':
            setattr(db_user, key, get_password_hash(value))
            continue
        setattr(db_user, key, value)

    session.commit()
    session.refresh(db_user)

    return db_user


@router.delete('/{user_id}', status_code=HTTPStatus.NO_CONTENT)
def delete_user(session: T_Session, user_id: int):
    db_user = session.scalar(select(User).where(User.id == user_id))

    if not db_user:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail='User not found.'
        )

    session.delete(db_user)
    session.commit()
