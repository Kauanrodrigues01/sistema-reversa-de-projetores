from pydantic import BaseModel


class UserSchema(BaseModel):
    username: str
    password: str


class UserPublicSchema(BaseModel):
    id: int
    username: str


class FilterPage(BaseModel):
    skip: int = 0
    limit: int = 100
