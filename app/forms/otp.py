from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp


class OtpLoginForm(FlaskForm):
    login = StringField(
        "Login",
        validators=[DataRequired(message="Podaj login."), Length(max=64)],
    )
    code = StringField(
        "Kod jednorazowy",
        validators=[
            DataRequired(message="Podaj kod jednorazowy."),
            Length(min=8, max=8, message="Kod musi mieć 8 cyfr."),
            Regexp(r"^\d{8}$", message="Kod musi składać się z 8 cyfr."),
        ],
    )
    submit = SubmitField("Zaloguj kodem")
