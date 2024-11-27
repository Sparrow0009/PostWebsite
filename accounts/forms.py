from flask import Flask
from flask_wtf import FlaskForm, RecaptchaField
from setuptools.config.pyprojecttoml import validate
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

class RegistrationForm(FlaskForm):
    email = StringField(validators = [DataRequired()])
    firstname = StringField(validators = [DataRequired()])
    lastname = StringField(validators = [DataRequired()])
    phone = StringField(validators = [DataRequired()])
    password = PasswordField(validators = [DataRequired(),
                             Length(min = 8, message = "Password too Short."), Length(max = 15, message = "Password too Long."),
                             Regexp('.*[A-Z]', message = 'Password must contain at least 1 Upper Case letter'),
                             Regexp('.*[a-z]', message = 'Password must contain at least 1 Lower Case letter'),
                             Regexp('.*\d', message = 'Password must contain at least one digit'),
                             Regexp('.*[@$!%*?&]', message = 'Password must contain at least one special character.')])
    confirm_password = PasswordField(validators = [DataRequired(),
                       EqualTo('password', message = "Both Password fields must be equal")])
    submit = SubmitField()

class LoginForm(FlaskForm):
    email = StringField(validators = [DataRequired()])
    password = PasswordField(validators = [DataRequired()])
    pin = StringField(validators = [DataRequired()])
    submit = SubmitField()
    reCaptcha = RecaptchaField()

