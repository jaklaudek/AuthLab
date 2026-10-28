from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, url_for

from app.auth.session_utils import get_current_user
from app.extensions import db
from app.forms.admin import SettingsForm, UserCreateForm, UserEditForm
from app.models import Role, User
from app.passwords.settings import (
    entropy_min_bits,
    entropy_policy_enabled,
    min_password_length,
    password_history_size,
    password_max_age_days,
    session_idle_timeout_minutes,
    update_policy_settings,
)
from app.rbac.decorators import permission_required
from app.services.users import (
    count_admins,
    create_user,
    delete_user,
    reset_user_password,
    set_user_active,
    update_user,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _role_choices() -> list[tuple[str, str]]:
    return [(role.name, role.name) for role in Role.query.order_by(Role.name).all()]


@bp.get("/")
@permission_required("admin.panel")
def index():
    return redirect(url_for("admin.users"))


@bp.get("/users")
@permission_required("users.list")
def users():
    items = User.query.order_by(User.login).all()
    return render_template("admin/users.html", users=items)


@bp.route("/users/new", methods=["GET", "POST"])
@permission_required("users.create")
def user_create():
    form = UserCreateForm()
    form.role.choices = _role_choices()
    issued_code = None
    expires_at = None

    if form.validate_on_submit():
        try:
            created = create_user(
                login=form.login.data,
                display_name=form.display_name.data or form.login.data,
                role_name=form.role.data,
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash(f"Utworzono użytkownika {created.user.login}.", "success")
            issued_code = created.otp_code
            expires_at = created.otp_expires_at

    return render_template(
        "admin/user_form.html",
        form=form,
        title="Nowy użytkownik",
        issued_code=issued_code,
        expires_at=expires_at,
        editing=False,
    )


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@permission_required("users.edit")
def user_edit(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)

    form = UserEditForm(obj=user)
    form.role.choices = _role_choices()
    if not form.is_submitted():
        form.role.data = user.role.name
        form.is_active.data = user.is_active

    if form.validate_on_submit():
        if (
            user.role.name == "Administrator"
            and form.role.data != "Administrator"
            and count_admins() <= 1
        ):
            flash("Nie można odebrać roli jedynemu aktywnemu administratorowi.", "error")
        else:
            try:
                update_user(
                    user,
                    display_name=form.display_name.data or user.login,
                    role_name=form.role.data,
                    is_active=form.is_active.data,
                )
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("Zapisano zmiany użytkownika.", "success")
                return redirect(url_for("admin.users"))

    return render_template(
        "admin/user_form.html",
        form=form,
        title=f"Edycja: {user.login}",
        issued_code=None,
        expires_at=None,
        editing=True,
        user=user,
    )


@bp.post("/users/<int:user_id>/block")
@permission_required("users.block")
def user_block(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    current = get_current_user()
    if current and current.id == user.id:
        flash("Nie możesz zablokować własnego konta.", "error")
        return redirect(url_for("admin.users"))
    if user.role.name == "Administrator" and count_admins() <= 1:
        flash("Nie można zablokować jedynego aktywnego administratora.", "error")
        return redirect(url_for("admin.users"))
    set_user_active(user, False)
    flash(f"Zablokowano konto {user.login}.", "info")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/unblock")
@permission_required("users.block")
def user_unblock(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    set_user_active(user, True)
    flash(f"Odblokowano konto {user.login}.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/delete")
@permission_required("users.delete")
def user_delete(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    current = get_current_user()
    if current and current.id == user.id:
        flash("Nie możesz usunąć własnego konta.", "error")
        return redirect(url_for("admin.users"))
    if user.role.name == "Administrator" and count_admins() <= 1:
        flash("Nie można usunąć jedynego aktywnego administratora.", "error")
        return redirect(url_for("admin.users"))
    login = user.login
    delete_user(user)
    flash(f"Usunięto użytkownika {login}.", "info")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/reset")
@permission_required("users.reset_password")
def user_reset(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    result = reset_user_password(user)
    return render_template(
        "admin/otp_issued.html",
        user=result.user,
        otp_code=result.otp_code,
        expires_at=result.otp_expires_at,
        purpose="reset",
    )


@bp.route("/settings", methods=["GET", "POST"])
@permission_required("settings.manage")
def settings():
    form = SettingsForm()
    if not form.is_submitted():
        form.min_password_length.data = min_password_length()
        form.entropy_policy_enabled.data = entropy_policy_enabled()
        form.entropy_min_bits.data = int(entropy_min_bits())
        form.password_max_age_days.data = password_max_age_days()
        form.session_idle_timeout_minutes.data = session_idle_timeout_minutes()
        form.password_history_size.data = password_history_size()

    if form.validate_on_submit():
        update_policy_settings(
            min_length=form.min_password_length.data,
            entropy_enabled=bool(form.entropy_policy_enabled.data),
            min_bits=float(form.entropy_min_bits.data),
            max_age_days=form.password_max_age_days.data,
            idle_minutes=form.session_idle_timeout_minutes.data,
            history_size=form.password_history_size.data,
        )
        flash("Zapisano ustawienia bezpieczeństwa.", "success")
        return redirect(url_for("admin.settings"))

    return render_template("admin/settings.html", form=form)
