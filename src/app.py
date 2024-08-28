from fastapi import FastAPI
from dotenv import dotenv_values
from pymongo import MongoClient
from fastapi.staticfiles import StaticFiles


app = FastAPI()

config = dotenv_values(".env")

@app.on_event("startup")
def startup_db_client():
    app.mongodb_client = MongoClient(config["ATLAS_URI"])
    app.database = app.mongodb_client[config["DB_NAME"]]
    print("Connected to the MongoDB database!")

@app.on_event("shutdown")
def shutdown_db_client():
    app.mongodb_client.close()
    