from pydantic import BaseModel


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class AccessTokenSchema(BaseModel):
    access_token: str
    token_type: str


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str
