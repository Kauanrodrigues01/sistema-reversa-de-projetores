from http import HTTPStatus

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from users.models import User


def verify_duplicate_email(email: str, session: Session, user_id: int = None):
    db_user = session.scalar(select(User).where(User.email == email))

    if db_user and db_user.id != user_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail='Email already registered',
        )
