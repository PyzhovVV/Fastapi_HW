from datetime import datetime

from uuid import uuid4

from fastapi.encoders import jsonable_encoder
from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint("username"),
        UniqueConstraint("email"),
        UniqueConstraint("password_hash")
    )
    uuid: str = Field(default=str(uuid4()), primary_key=True)
    username: str = Field()
    roles: str = Field(default='user has no roles')
    created_at: str = Field(default=jsonable_encoder(datetime.utcnow()), nullable=False)
    is_superuser: bool = Field(default=False)
    is_totp_enabled: bool = Field(default=False)
    is_active: bool = Field(default=True)
    email: str = Field()
    password_hash: str = Field()
