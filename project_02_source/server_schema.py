from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

db = SQLAlchemy()

@dataclass
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(256), unique=True, nullable=False)
    public_key_pem: str = db.Column(db.String(2048), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)
    def __repr__(self):
        return '<User %r>' % self.username

@dataclass
class Note(db.Model):
    __tablename__ = 'note'
    id: int = db.Column(db.Integer, primary_key=True)
    note_uuid: str = db.Column(db.String(40), nullable=False) # Unique identifier for the note from the same creator but different recipients
    sender_id: int = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id: int = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    salt: str = db.Column(db.String(50), nullable=False)

    name: str = db.Column(db.String(256), nullable=False)
    content: str = db.Column(db.LargeBinary, nullable=False) # Encrypted content
    expiration: datetime = db.Column(db.DateTime, nullable=False)
    access_count: int = db.Column(db.Integer, nullable=False, default=0)
    max_access_count: int = db.Column(db.Integer, nullable=False, default=1)
    sharing: bool = db.Column(db.Boolean, nullable=False, default=True)
    def __repr__(self):
        return '<Note %r>' % self.id

