from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    login = StringField(
        "Login",
        validators=[DataRequired(message="Podaj login."), Length(max=64)],
    )
    password = PasswordField(
        "Hasło",
        validators=[DataRequired(message="Podaj hasło."), Length(max=256)],
    )
    submit = SubmitField("Zaloguj")
