from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional


class UserCreateForm(FlaskForm):
    login = StringField(
        "Login",
        validators=[DataRequired(message="Podaj login."), Length(min=3, max=64)],
    )
    display_name = StringField(
        "Nazwa wyświetlana",
        validators=[Optional(), Length(max=128)],
    )
    role = SelectField("Rola", validators=[DataRequired()])
    submit = SubmitField("Dodaj użytkownika")


class UserEditForm(FlaskForm):
    display_name = StringField(
        "Nazwa wyświetlana",
        validators=[Optional(), Length(max=128)],
    )
    role = SelectField("Rola", validators=[DataRequired()])
    is_active = BooleanField("Konto aktywne")
    submit = SubmitField("Zapisz")


class SettingsForm(FlaskForm):
    min_password_length = IntegerField(
        "Minimalna długość hasła",
        validators=[DataRequired(), NumberRange(min=8, max=128)],
    )
    entropy_policy_enabled = BooleanField("Włącz politykę entropii (≥ próg bitów)")
    entropy_min_bits = IntegerField(
        "Minimalna entropia (bity)",
        validators=[DataRequired(), NumberRange(min=1, max=256)],
    )
    password_max_age_days = IntegerField(
        "Ważność hasła (dni, 0 = bez limitu)",
        validators=[DataRequired(), NumberRange(min=0, max=3650)],
    )
    session_idle_timeout_minutes = IntegerField(
        "Czas bezczynności sesji (minuty)",
        validators=[DataRequired(), NumberRange(min=1, max=1440)],
    )
    password_history_size = IntegerField(
        "Liczba pamiętanych poprzednich haseł",
        validators=[DataRequired(), NumberRange(min=0, max=50)],
    )
    submit = SubmitField("Zapisz ustawienia")
