from pydantic import BaseModel


class FilterPage(BaseModel):
    skip: int = 0
    limit: int = 100
