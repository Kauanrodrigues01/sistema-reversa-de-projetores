from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.orm import Session

from app.database import get_session
from app.schemas import FilterPage

T_Session = Annotated[Session, Depends(get_session)]
T_FilterPage = Annotated[FilterPage, Query()]
