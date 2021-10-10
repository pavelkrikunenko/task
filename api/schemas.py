from pydantic import BaseModel
from typing import List, Optional
from datetime import date


class TaskBase(BaseModel):
    title: str
    description: str
    end_date: date


class CreateTask(TaskBase):
    pass


class UpdateTask(TaskBase):
    id: int


class DeleteTask(BaseModel):
    id: int


class Task(TaskBase):
    id: int
    executor_id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    login: str
    fullname: str


class CreateUser(UserBase):
    password: str


class User(UserBase):
    id: int
    tasks: List[Task] = None

    class Config:
        orm_mode = True


class LoginUser(BaseModel):
    login: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
