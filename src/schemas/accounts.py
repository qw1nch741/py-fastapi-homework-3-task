from pydantic import BaseModel, EmailStr, field_validator, Field, ConfigDict

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr


class AccountActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    refresh_token: str
