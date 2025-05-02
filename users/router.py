from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_session
from users import utils
from users.models import User
from users.schemas import UserPublicSchema, UserSchema

router = APIRouter(prefix='/users', tags=['users'])

T_Session = Annotated[Session, Depends(get_session)]


@router.post(
    '', response_model=UserPublicSchema, status_code=HTTPStatus.CREATED
)
def create_user(user: UserSchema, session: T_Session):
    utils.verify_duplicate_username(username=user.username, session=session)

    db_user = User(
        username=user.username,
        password=user.password,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user
