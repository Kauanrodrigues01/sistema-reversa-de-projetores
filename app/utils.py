from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session


def get_object_or_404(model, obj_id: int, session: Session, detail: str = 'Object not found'):
    obj = session.scalar(select(model).where(model.id == obj_id))

    if not obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail
        )

    return obj
