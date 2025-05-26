from fastapi import APIRouter, status
from sqlalchemy import select

from app.dependencies import T_FilterPage, T_Session, T_User
from app.security import get_password_hash
from app.utils import verify_duplicate_email, auth_required
from modules.users.models import User
from modules.users.schemas import (
    UserPublicSchema,
    UserSchema,
    UserUpdateSchema,
)

router = APIRouter(prefix='/users', tags=['users'])


@router.post(
    '/register',
    response_model=UserPublicSchema,
    status_code=status.HTTP_201_CREATED,
)
def create_user(user_data: UserSchema, session: T_Session):
    verify_duplicate_email(email=user_data.email, session=session)

    db_user = User(
        email=user_data.email,
        name=user_data.name,
        password=get_password_hash(user_data.password),
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


@router.patch('/me', response_model=UserPublicSchema)
@auth_required
def update_user(user: T_User, user_data: UserUpdateSchema, session: T_Session):
    verify_duplicate_email(
        email=user_data.email, session=session, user_id=user.id
    )

    for key, value in user_data.model_dump(exclude_unset=True).items():
        if key == 'password':
            setattr(user, key, get_password_hash(value))
            continue
        setattr(user, key, value)

    session.commit()
    session.refresh(user)

    return user


@router.delete('/me', status_code=status.HTTP_204_NO_CONTENT)
@auth_required
def delete_user(user: T_User, session: T_Session):
    session.delete(user)
    session.commit()
