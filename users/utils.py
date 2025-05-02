from http import HTTPStatus

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from users.models import User


def verify_duplicate_username(
    username: str, session: Session, user_id: int = None
):
    db_user = session.scalar(select(User).where(User.username == username))

    if db_user and db_user.id != user_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail='Username already registered',
        )
