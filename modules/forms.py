from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    name = StringField('login', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class MessageSendForm(FlaskForm):
    recipient = StringField('recipient', validators=[DataRequired()])
    text = TextAreaField('text', validators=[DataRequired()])
    submit = SubmitField('Submit')
