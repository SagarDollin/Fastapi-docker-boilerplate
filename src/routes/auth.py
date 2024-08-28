from fastapi import APIRouter, Request, Depends, HTTPException, status

from controllers.users import *

router = APIRouter()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    token = login_for_access_token_controller(user)
    return token

@router.get("/me", response_description="User Profile", response_model=User)                  # Pass request as param to function inside Depends
async def user_profile(request: Request, current_user: User = Depends(get_current_active_user)):    # https://stackoverflow.com/questions/68668417/is-it-possible-to-pass-path-arguments-into-fastapi-dependency-functions
    return current_user

@router.post("/signup", response_description="New user signup", response_model = str)
async def signup(request: Request, user: NewUser):                           
    signup_response = signup_controller(request, user)
    return signup_response
