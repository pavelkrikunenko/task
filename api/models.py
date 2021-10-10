from sqlalchemy import String, Column, Date, Integer, Text, ForeignKey
from .database import Base
from datetime import date
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    login = Column(String(250), unique=True, nullable=False)
    fullname = Column(String(250), unique=True, nullable=False)
    pwhash = Column(Text)
    tasks = relationship('Task', backref='executor', cascade='all, delete-orphan')


class Task(Base):
    __tablename__ = 'tasks'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(250), nullable=False)
    description = Column(Text, nullable=False)
    end_date = Column(Date, default=date.today())
    executor_id = Column(Integer, ForeignKey('users.id'))
