from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp


class TotpChallengeForm(FlaskForm):
    code = StringField(
        "Kod TOTP",
        validators=[
            DataRequired(message="Podaj kod z aplikacji."),
            Length(min=6, max=6, message="Kod ma 6 cyfr."),
            Regexp(r"^\d{6}$", message="Kod ma 6 cyfr."),
        ],
    )
    submit = SubmitField("Potwierdź")


class TotpConfirmForm(FlaskForm):
    code = StringField(
        "Kod z aplikacji",
        validators=[
            DataRequired(message="Podaj kod z aplikacji."),
            Length(min=6, max=6, message="Kod ma 6 cyfr."),
            Regexp(r"^\d{6}$", message="Kod ma 6 cyfr."),
        ],
    )
    submit = SubmitField("Włącz TOTP")


class TotpDisableForm(FlaskForm):
    password = PasswordField(
        "Hasło",
        validators=[DataRequired(message="Podaj hasło."), Length(max=256)],
    )
    code = StringField(
        "Kod TOTP",
        validators=[
            DataRequired(message="Podaj kod z aplikacji."),
            Length(min=6, max=6, message="Kod ma 6 cyfr."),
            Regexp(r"^\d{6}$", message="Kod ma 6 cyfr."),
        ],
    )
    submit = SubmitField("Wyłącz TOTP")
