from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Optional


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Obecne hasło",
        validators=[Optional(), Length(max=256)],
    )
    new_password = PasswordField(
        "Nowe hasło",
        validators=[DataRequired(message="Podaj nowe hasło."), Length(max=256)],
    )
    confirm_password = PasswordField(
        "Potwierdź nowe hasło",
        validators=[DataRequired(message="Potwierdź nowe hasło."), Length(max=256)],
    )
    submit = SubmitField("Zmień hasło")
