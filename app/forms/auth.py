from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Optional


class LoginForm(FlaskForm):
    login = StringField(
        "Login",
        validators=[DataRequired(message="Podaj login."), Length(max=64)],
    )
    password = PasswordField(
        "Hasło",
        validators=[DataRequired(message="Podaj hasło."), Length(max=256)],
    )
    captcha_answer = StringField(
        "Odpowiedź CAPTCHA",
        validators=[Optional(), Length(max=64)],
    )
    honeypot = StringField(
        "Numer telefonu",
        validators=[Optional(), Length(max=128)],
    )
    submit = SubmitField("Zaloguj")
