import os, sys
print("Current working directory:", os.getcwd())

sys.path.append('/src')

import uvicorn
from routes.auth import router as user_router
from app import *

from controllers.users import *

@app.get("/")
async def root():
    return {"message": "Welcome to the PyMongo tutorial!"}

app.include_router(user_router, tags=["Users"], prefix="/users")

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=80, reload=True)