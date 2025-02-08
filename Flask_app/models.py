from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    license_key = db.Column(db.String(100), unique=True, nullable=True)

class GameResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    week = db.Column(db.Integer, nullable=False)
    team1 = db.Column(db.String(50), nullable=False)
    team1_score = db.Column(db.Integer, nullable=False)
    team2 = db.Column(db.String(50), nullable=False)
    team2_score = db.Column(db.Integer, nullable=False)
    home_team = db.Column(db.String(50), nullable=False)

class FutureGame(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    week = db.Column(db.String(50), nullable=False)
    team1 = db.Column(db.String(50), nullable=False)
    team2 = db.Column(db.String(50), nullable=False)
