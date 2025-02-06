# models.py
import re
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates, Session
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(150))
    name = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    last_logged_in = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    confirmed = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self, password):
        return check_password_hash(self.password_hash,password)    