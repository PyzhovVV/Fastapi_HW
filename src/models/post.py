from datetime import datetime
from typing import Optional
from fastapi.encoders import jsonable_encoder

from sqlmodel import Field, SQLModel

__all__ = ("Post",)


class Post(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(nullable=False)
    description: str = Field(nullable=False)
    views: int = Field(default=0)
    created_at: str = Field(default=jsonable_encoder(datetime.utcnow()), nullable=False)
    user_uuid: str = Field(foreign_key="user.uuid")
