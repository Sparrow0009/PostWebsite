from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp, Email


class RegistrationForm(FlaskForm):
    email = StringField(validators = [DataRequired(), Email(message = "Email should be of the type xxxx@xxxx.xxx")])
    firstname = StringField(validators = [DataRequired(),
                                          Regexp('^[a-zA-Z-]+$', message = 'First Name must contain only alphabets and Hyphens')])
    lastname = StringField(validators = [DataRequired(),
                                         Regexp('^[a-zA-Z-]+$', message = 'Last Name must contain only alphabets and Hyphens')])
    phone = StringField(validators = [DataRequired(),
                                      Regexp('^(02\d-\d{8}|011\d-\d{7}|01\d1-\d{7}|01\d{3}-\d{5,6})$', message = "Phone Number should be of valid format")])
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

