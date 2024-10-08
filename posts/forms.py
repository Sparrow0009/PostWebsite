from wsgiref.validate import validator

from flask_wtf import FlaskForm
from sqlalchemy.sql.ddl import DropTable
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired


class PostForm(FlaskForm):
    title = StringField(validators = [DataRequired()])
    body = TextAreaField(validators = [DataRequired()])
    submit = SubmitField()
