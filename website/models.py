from . import db
from flask_login import UserMixin

class Roles(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(150))

    users = db.relationship('User', back_populates='role')


class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email= db.Column(db.String(150), unique=True)
    password =db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    role_id = db.Column(db.Integer,db.ForeignKey('roles.id'))
    role = db.relationship('Roles', back_populates='users')
    is_active = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(16), nullable=True)
    activation_token = db.Column(db.String(100), unique=True)



