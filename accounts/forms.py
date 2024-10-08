from flask import Flask
from flask_wtf import FlaskForm
from setuptools.config.pyprojecttoml import validate
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

class RegistrationForm(FlaskForm):
    email = StringField(validators = [DataRequired()])
    firstname = StringField(validators = [DataRequired()])
    lastname = StringField(validators = [DataRequired()])
    phone = StringField(validators = [DataRequired()])
    password = PasswordField(validators = [DataRequired()])
    confirm_password = PasswordField(validators = [DataRequired(), EqualTo('password', message = "Both Password fields must be equal")])
    submit = SubmitField()

class LoginForm(FlaskForm):
    email = StringField(validators = [DataRequired()])
    password = PasswordField(validators = [DataRequired()])
    submit = SubmitField()

