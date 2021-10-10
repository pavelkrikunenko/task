from fastapi import FastAPI
from . import database, crud, models, schemas
from .database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

from api import routes
