from functools import wraps

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import T_User
from modules.users.models import User


def get_object_or_404(
    model, obj_id: int, session: Session, detail: str = 'Object not found'
):
    obj = session.scalar(select(model).where(model.id == obj_id))

    if not obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=detail
        )

    return obj


def auth_required(func):
    @wraps(func)
    def wrapper(user: T_User, *args, **kwargs):
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Not authenticated',
            )
        return func(user, *args, **kwargs)
    return wrapper


def verify_duplicate_email(email: str, session: Session, user_id: int = None):
    db_user = session.scalar(select(User).where(User.email == email))

    if db_user and db_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Email already registered',
        )
