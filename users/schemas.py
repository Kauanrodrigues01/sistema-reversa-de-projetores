from pydantic import BaseModel


class UserSchema(BaseModel):
    username: str
    password: str


class UserPublicSchema(BaseModel):
    id: int
    username: str
