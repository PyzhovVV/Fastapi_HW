from datetime import datetime, timedelta

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import (
    JWTError,
    jwt,
)
from passlib.hash import bcrypt
from pydantic import ValidationError
from sqlmodel import Session

from src import models
from src.api.v1 import schemas
from src.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, CACHE_EXPIRE_IN_SECONDS
from src.db import get_session
from src.models import User


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/v1/login')


def get_current_user(token: str = Depends(oauth2_scheme)) -> schemas.User:
    return AuthService.validate_token(token)


class AuthService:

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def validate_token(cls, token: str) -> schemas.User:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )
        try:
            payload = jwt.decode(
                token=token,
                key=JWT_SECRET_KEY,
                algorithms=JWT_ALGORITHM
            )
        except JWTError:
            raise exception from None

        user_data = payload.get('user')

        try:
            user = models.User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: models.User) -> schemas.Token:
        user_data = models.User.from_orm(user)
        now = datetime.utcnow()
        payload_access_token = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=CACHE_EXPIRE_IN_SECONDS),
            'type': 'access',
            'user': user_data.dict(),
        }
        access_token = jwt.encode(
            claims=payload_access_token,
            key=JWT_SECRET_KEY,
            algorithm=JWT_ALGORITHM,
        )
        payload_refresh_token = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=CACHE_EXPIRE_IN_SECONDS),
            'type': 'refresh',
            'user_uuid': str(user_data.uuid)
        }
        refresh_token = jwt.encode(
            claims=payload_refresh_token,
            key=JWT_SECRET_KEY,
            algorithm=JWT_ALGORITHM,
        )
        return schemas.Token(access_token=access_token, refresh_token=refresh_token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: schemas.UserCreate) -> dict:
        "Регистрация пользователя"
        user = User(
            email=user_data.email,
            username=user_data.username,
            password_hash=self.hash_password(user_data.password),
        )
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user.dict()

    def authenticate_user(self, username: str, password: str) -> schemas.Token:
        "Авторизация пользователя"
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )

        user = (
            self.session
            .query(User)
            .filter(User.username == username)
            .first()
        )

        if not user:
            raise exception

        if not self.verify_password(password, user.password_hash):
            raise exception

        return self.create_token(user)

