from pydantic import BaseModel, EmailStr


class UserSchema(BaseModel):
    email: EmailStr
    name: str
    password: str


class UserPublicSchema(BaseModel):
    id: int
    email: EmailStr
    name: str


class FilterPage(BaseModel):
    skip: int = 0
    limit: int = 100
