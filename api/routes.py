from fastapi import Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from . import crud, schemas, app

from pydantic import ValidationError

from sqlalchemy.orm import Session
from datetime import timedelta


@app.get('/')
def index():
    return HTMLResponse('<a href="/docs/">docs</a>')


@app.get('/tasks/')
async def get_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(crud.get_db)):
    tasks = crud.get_tasks(db=db, limit=limit, skip=skip)
    return tasks


@app.get('/users/me/my-tasks')
async def get_task_by_current_user(current_user: schemas.User = Depends(crud.get_current_active_user)):
    return current_user.tasks


@app.post('/login/')
async def login(form_data: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(crud.get_db)):
    user = crud.get_user(db=db, login=form_data.username)
    if not user or not crud.verify_password(plain_password=form_data.password, hashed_password=user.pwhash):
        raise HTTPException(status_code=400, detail='Incorrect username or password')

    return {'access_token': user.login, 'token_type': 'bearer'}


@app.post('/token/', response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(crud.get_db)):
    user = crud.authenticate_user(db=db, login=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'}
        )
    access_token_expires = timedelta(minutes=crud.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crud.create_access_token(
        data={'sub': user.login}, expires_delta=access_token_expires
    )
    return {'access_token': access_token, 'token_type': 'bearer'}


@app.post('/users/', response_model=schemas.User)
async def create_user(user: schemas.CreateUser, db: Session = Depends(crud.get_db)):
    db_user = crud.get_user(db=db, login=user.login)
    if db_user:
        raise HTTPException(status_code=400, detail='Login already registered')
    try:
        return crud.create_user(db=db, user=user)
    except ValidationError as e:
        raise e.json()


@app.post('/tasks/', response_model=schemas.Task)
async def create_task(task: schemas.CreateTask,
                      db: Session = Depends(crud.get_db),
                      current_user: schemas.User = Depends(crud.get_current_user)):
    if current_user:
        db_task = crud.create_task(db=db, task=task, executor_id=current_user.id)
        return db_task


@app.put('/tasks/', response_model=schemas.Task)
async def update_task(task: schemas.UpdateTask,
                      db: Session = Depends(crud.get_db),
                      current_user: schemas.User = Depends(crud.get_current_user)):
    if current_user:
        db_task = crud.get_task(db=db, task_id=task.id)
        if db_task:
            return crud.update_task(db=db, task=task)
        else:
            raise HTTPException(status_code=400, detail='Task was not exist')
    else:
        raise HTTPException(status_code=400, detail='You need to authorization')


@app.delete('/tasks/', response_model=schemas.Task)
async def delete_task(task: schemas.DeleteTask,
                      db: Session = Depends(crud.get_db),
                      current_user: schemas.User = Depends(crud.get_current_user)):
    if current_user:
        db_task = crud.get_task(db=db, task_id=task.id)
        if db_task:
            return crud.delete_task(db=db, task=task, user=current_user)
        else:
            raise HTTPException(status_code=400, detail='Task was not exist')
