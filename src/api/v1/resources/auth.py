from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from src.api.v1 import schemas
from src.api.v1.schemas import UserCreate, Token, PostCreate, PostModel
from src.services import PostService, get_post_service
from src.services.auth import AuthService, get_current_user

router = APIRouter()


@router.post(
    path="/signup",
    summary="123",
    response_model=Token,
    tags=["auth"]
    )
def signup(user_data: UserCreate, service: AuthService = Depends()):
    return service.register_new_user(user_data)


@router.post(
    path="/login",
    summary="324",
    response_model=Token,
    tags=["auth"]
    )
def login(from_data: OAuth2PasswordRequestForm = Depends(), service: AuthService = Depends()):
    return service.authenticate_user(from_data.username, from_data.password)


@router.get(path='/user/',
            response_model=schemas.User,
            summary="657",
            tags=["auth"]
            )
def get_user(user: schemas.User = Depends(get_current_user)):
    return user
