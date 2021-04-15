from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

import requests
from fastapi import Body, FastAPI
import json
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse
app = FastAPI()

class User(BaseModel):
    client_key: str
    client_secret: str

# set denylist enabled to True
# you can set to check access or refresh token or even both of them
class Settings(BaseModel):
    authjwt_secret_key: str = "70292F6B15DDBE9D199755BC1FB211E0EB25F4046440791517BA4AA50E7D4E9ERY3CDEImn5WNmRoY38zPYHfM6gw8kcdcC2pgjJMAoO5FVAnFAiRU95Py3Skfu30"
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access","refresh"}

@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

# A storage engine to save revoked tokens. in production,
# you can use Redis for storage system
denylist = set()

# For this example, we are just checking if the tokens jti
# (unique identifier) is in the denylist set. This could
# be made more complex, for example storing the token in Redis
# with the value true if revoked and false if not revoked

@AuthJWT.token_in_denylist_loader
def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in denylist

@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    response = requests.post("http://192.168.1.159:8000/client/auth" , data={"client_uid":user.client_key, "client_secret":user.client_secret})
    if response.status_code== 401:
            raise HTTPException( status_code=401,detail="Bad client_key or client_secret")
    print(response.json())
    client_id = response.json()['client_id']
    access_token = Authorize.create_access_token(subject=client_id)
    refresh_token = Authorize.create_refresh_token(subject=client_id)
    return {"access_token": access_token, "refresh_token": refresh_token}

# Standard refresh endpoint. Token in denylist will not
# be able to access this endpoint
@app.post('/refresh')
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}

# Endpoint for revoking the current users access token
@app.delete('/access-revoke')
def access_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    jti = Authorize.get_raw_jwt()['jti']
    denylist.add(jti)
    return {"detail":"Access token has been revoke"}

# Endpoint for revoking the current users refresh token
@app.delete('/refresh-revoke')
def refresh_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    jti = Authorize.get_raw_jwt()['jti']
    denylist.add(jti)
    return {"detail":"Refresh token has been revoke"}

# A token in denylist will not be able to access this any more
@app.get('/authorise')
async def protected(request: Request, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    client_id = Authorize.get_jwt_subject()
    print("dddd")
    #print(response.json())
    return "s"

@app.post("/neuralgenie/predict")
async def create_upload_file(response: Response,xrayfile: bytes = File(...), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    client_id = Authorize.get_jwt_subject()
    response = requests.post("http://192.168.1.159:8000/client/subcriptions" , data={"client_id":client_id})
    if response.status_code!= 200:
            raise HTTPException(status_code=401,detail=response.json().get('message'))
    neural_genie_url = "https://fusion1.genieminds.com/neuralgenie/apis/predict/"
    payload={}
    files=[
    ('xrayfile',xrayfile)
    ]
    # logger.info("requesting neuralgenie api for fetching kl-grading")
    response_kl = requests.request("POST", neural_genie_url, data=payload, files=files)

    if response_kl.status_code == 200:
       return response_kl.json()
    else:
       return JSONResponse(status_code=400, content=response_kl.json())

@app.post("/neuralgenie/apis/extract-features")
def extract_features(response: Response,xrayfile: bytes = File(...), Authorize: AuthJWT = Depends()):
    # Authorize.jwt_required()
    # client_id = Authorize.get_jwt_subject()
    # response = requests.post("http://192.168.1.159:8000/client/subcriptions" , data={"client_id":client_id})
    # if response.status_code!= 200:
    #         raise HTTPException(status_code=401,detail=response.json().get('message'))
    neural_genie_url = "http://192.168.1.153:8001/neuralgenie/apis/extract-features/"
    payload={}
    files=[
    ('xrayfile',xrayfile)
    ]
    response_kl = requests.request("POST", neural_genie_url, data=payload, files=files)

    if response_kl.status_code == 200:
       return response_kl.json()
    else:
       return JSONResponse(status_code=400, content=response_kl.json())