from sqlalchemy.orm import Session
from . import models, schemas
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from .database import SessionLocal
from datetime import timedelta, datetime
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
SECRET_KEY = '6a54a3bdd7a04d2ba934b041006bed1b6be350bc7de54941e8c8680e064154e8'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db, login: str, password: str):
    user = get_user(db, login=login)
    if not user:
        return False
    if not verify_password(password, user.pwhash):
        return False
    return user


def create_access_token(data: dict,
                        expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme),
                           db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db=db, login=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    return current_user


def get_all_users(db: Session, skip: int = 0, limit: int = 100):
    users = db.query(models.User).limit(limit).offset(skip).all()
    return users


def create_user(db: Session, user: schemas.CreateUser):
    pwhash = get_password_hash(user.password)

    db_user = models.User(
        login=user.login,
        fullname=user.fullname,
        pwhash=pwhash
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_task(db: Session,
                task: schemas.CreateTask,
                executor_id: int):
    db_task = models.Task(
        title=task.title,
        description=task.description,
        end_date=task.end_date,
        executor_id=executor_id
    )
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task


def get_user(db: Session, login: str):
    return db.query(models.User).filter(models.User.login == login).first()


def get_task(db: Session, task_id: int):
    return db.query(models.Task).filter(models.Task.id == task_id).first()


def get_tasks(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Task).offset(skip).limit(limit).all()


def get_tasks_by_user(db: Session,
                      user: schemas.User = Depends(get_current_user)):
    db_user = db.query(models.User).filter(models.User.login == user.login).first()
    return db.query(models.Task).filter(models.Task.executor_id == db_user.id).all()


def update_task(db: Session,
                task: schemas.UpdateTask,
                user: schemas.User = Depends(get_current_user)):
    db_user = get_user(db=db, login=user.login)
    db_task = db.query(models.Task).filter(models.Task.id == task.id).first()
    if db_user.id == db_task.executor_id:
        db_task.title = task.title
        db_task.description = task.description
        db_task.end_date = task.end_date
        db.commit()
        return db_task
    raise HTTPException(status_code=400, detail='You are not executor for this task')


def delete_task(db: Session,
                task: schemas.DeleteTask,
                user: schemas.User = Depends(get_current_user)):
    db_user = get_user(db=db, login=user.login)
    db_task = db.query(models.Task).filter(models.Task.id == task.id).first()

    if db_user.id == db_task.executor_id:
        db.delete(db_task)
        db.commit()
        return db_task

    raise HTTPException(status_code=400, detail='You are not executor for this task')
