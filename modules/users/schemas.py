from pydantic import BaseModel, EmailStr


class UserSchema(BaseModel):
    email: EmailStr
    name: str
    password: str


class UserPublicSchema(BaseModel):
    id: int
    email: EmailStr
    name: str


class UserUpdateSchema(BaseModel):
    email: EmailStr | None = None
    name: str | None = None
    password: str | None = None
