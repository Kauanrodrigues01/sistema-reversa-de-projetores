from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.orm import Session

from app.database import get_session
from app.schemas import FilterPage
from app.security import get_current_user

from modules.users.models import User

T_Session = Annotated[Session, Depends(get_session)]
T_FilterPage = Annotated[FilterPage, Query()]
T_User = Annotated[User | None, Depends(get_current_user)]
