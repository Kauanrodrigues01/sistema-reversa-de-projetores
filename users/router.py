from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_session
from app.security import get_password_hash
from users import utils
from users.models import User
from users.schemas import FilterPage, UserPublicSchema, UserSchema

router = APIRouter(prefix='/users', tags=['users'])

T_Session = Annotated[Session, Depends(get_session)]
T_FilterPage = Annotated[FilterPage, Query()]


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
