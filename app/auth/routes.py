from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.auth.service import authenticate, mark_successful_login
from app.auth.session_utils import (
    authenticated_via_otp,
    begin_pending_totp,
    clear_otp_auth_flag,
    clear_pending_totp,
    get_current_user,
    get_pending_totp_user,
    login_required,
    login_user,
    logout_user,
    touch_session_activity,
)
from app.forms.auth import LoginForm
from app.forms.otp import OtpLoginForm
from app.forms.password import ChangePasswordForm
from app.forms.totp import TotpChallengeForm, TotpConfirmForm, TotpDisableForm
from app.passwords.entropy import estimate_entropy_bits
from app.passwords.otp import consume_otp
from app.passwords.service import change_password as perform_password_change
from app.passwords.settings import entropy_min_bits, entropy_policy_enabled, min_password_length
from app.passwords.totp import (
    disable_totp,
    enable_totp,
    generate_secret,
    provisioning_uri,
    qr_svg_data_uri,
    record_totp_success,
    verify_user_totp,
)
from app.rbac.decorators import permission_required

bp = Blueprint("auth", __name__)

_PASSWORD_CHANGE_ALLOWED = {
    "auth.change_password",
    "auth.password_strength",
    "auth.logout",
    "auth.login",
    "auth.otp_login",
    "auth.totp_challenge",
    "static",
    "health",
}


@bp.before_app_request
def enforce_forced_password_change():
    user = get_current_user()
    if user is None or not user.must_change_password:
        return None
    if request.endpoint in _PASSWORD_CHANGE_ALLOWED:
        return None
    return redirect(url_for("auth.change_password"))


@bp.route("/")
def index():
    if get_current_user() is not None:
        return redirect(url_for("auth.dashboard"))
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user() is not None:
        user = get_current_user()
        if user and user.must_change_password:
            return redirect(url_for("auth.change_password"))
        return redirect(url_for("auth.dashboard"))

    if get_pending_totp_user() is not None:
        return redirect(url_for("auth.totp_challenge"))

    form = LoginForm()
    error = None
    if form.validate_on_submit():
        result = authenticate(form.login.data, form.password.data)
        if result.ok and result.user is not None:
            if result.user.totp_enabled:
                begin_pending_totp(result.user)
                flash("Podaj kod z aplikacji uwierzytelniającej.", "info")
                return redirect(url_for("auth.totp_challenge"))

            login_user(result.user)
            mark_successful_login(result.user)
            if result.user.must_change_password:
                flash("Musisz ustawić nowe hasło przed dalszą pracą.", "info")
                return redirect(url_for("auth.change_password"))
            flash("Zalogowano pomyślnie.", "success")
            return redirect(url_for("auth.dashboard"))
        error = current_app.config["LOGIN_ERROR_MESSAGE"]

    return render_template("auth/login.html", form=form, error=error)


@bp.route("/login/totp", methods=["GET", "POST"])
def totp_challenge():
    if get_current_user() is not None:
        return redirect(url_for("auth.dashboard"))

    pending = get_pending_totp_user()
    if pending is None:
        flash("Najpierw zaloguj się loginem i hasłem.", "info")
        return redirect(url_for("auth.login"))

    form = TotpChallengeForm()
    error = None
    if form.validate_on_submit():
        result = verify_user_totp(pending, form.code.data)
        if result.ok and result.counter is not None:
            record_totp_success(pending, result.counter)
            clear_pending_totp()
            login_user(pending)
            mark_successful_login(pending)
            if pending.must_change_password:
                flash("Musisz ustawić nowe hasło przed dalszą pracą.", "info")
                return redirect(url_for("auth.change_password"))
            flash("Zalogowano pomyślnie.", "success")
            return redirect(url_for("auth.dashboard"))
        error = result.error or "Nieprawidłowy kod TOTP."

    return render_template(
        "auth/totp_challenge.html",
        form=form,
        error=error,
        login=pending.login,
    )


@bp.route("/login/totp/cancel", methods=["POST"])
def totp_challenge_cancel():
    clear_pending_totp()
    flash("Logowanie anulowane.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/login/otp", methods=["GET", "POST"])
def otp_login():
    if get_current_user() is not None:
        user = get_current_user()
        if user and user.must_change_password:
            return redirect(url_for("auth.change_password"))
        return redirect(url_for("auth.dashboard"))

    form = OtpLoginForm()
    error = None
    if form.validate_on_submit():
        result = consume_otp(form.login.data, form.code.data)
        if result.ok and result.user is not None:
            clear_pending_totp()
            login_user(result.user, via_otp=True)
            mark_successful_login(result.user)
            flash(
                "Zalogowano kodem jednorazowym. Ustaw nowe hasło, aby kontynuować.",
                "info",
            )
            return redirect(url_for("auth.change_password"))
        error = result.error

    return render_template("auth/otp_login.html", form=form, error=error)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Wylogowano.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/dashboard")
@permission_required("dashboard.view")
def dashboard():
    touch_session_activity()
    user = get_current_user()
    return render_template("auth/dashboard.html", user=user)


@bp.route("/resources")
@permission_required("resources.internal")
def resources():
    touch_session_activity()
    user = get_current_user()
    return render_template("auth/resources.html", user=user)


@bp.route("/password/change", methods=["GET", "POST"])
@permission_required("password.change_own")
def change_password():
    touch_session_activity()
    user = get_current_user()
    form = ChangePasswordForm()
    errors: list[str] = []
    hints: list[str] = []
    forced = bool(user and user.must_change_password)
    via_otp = authenticated_via_otp()

    if form.validate_on_submit() and user is not None:
        if not via_otp and not (form.current_password.data or "").strip():
            errors = ["Podaj obecne hasło."]
        else:
            result = perform_password_change(
                user,
                current_password=form.current_password.data or "",
                new_password=form.new_password.data,
                confirm_password=form.confirm_password.data,
                skip_current_check=via_otp,
            )
            if result.ok:
                clear_otp_auth_flag()
                flash("Hasło zostało zmienione.", "success")
                return redirect(url_for("auth.dashboard"))
            errors = result.errors
            hints = result.hints

    return render_template(
        "auth/change_password.html",
        form=form,
        errors=errors,
        hints=hints,
        forced=forced,
        via_otp=via_otp,
        entropy_policy_enabled=entropy_policy_enabled(),
        entropy_min_bits=entropy_min_bits(),
        min_password_length=min_password_length(),
    )


@bp.route("/password/strength", methods=["POST"])
@permission_required("password.change_own")
def password_strength():
    user = get_current_user()
    payload = request.get_json(silent=True) or {}
    password = payload.get("password") or ""
    estimate = estimate_entropy_bits(
        password,
        user_inputs=[user.login, user.display_name] if user else [],
    )
    policy_on = entropy_policy_enabled()
    threshold = entropy_min_bits()
    minimum = min_password_length()
    length_ok = len(password) >= minimum
    entropy_ok = (not policy_on) or (estimate.bits >= threshold)
    return jsonify(
        {
            "bits": round(estimate.bits, 1),
            "guesses": estimate.guesses,
            "score": estimate.score,
            "hints": estimate.hints,
            "policy_enabled": policy_on,
            "min_bits": threshold,
            "min_length": minimum,
            "length_ok": length_ok,
            "entropy_ok": entropy_ok,
            "ok": bool(password) and length_ok and entropy_ok,
        }
    )


@bp.route("/security/totp", methods=["GET", "POST"])
@permission_required("password.change_own")
def totp_settings():
    touch_session_activity()
    user = get_current_user()
    assert user is not None

    setup_form = TotpConfirmForm(prefix="setup")
    disable_form = TotpDisableForm(prefix="disable")
    setup_secret = session.get("totp_setup_secret")
    setup_uri = None
    setup_qr = None
    error = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "start" and not user.totp_enabled:
            secret = generate_secret()
            session["totp_setup_secret"] = secret
            flash("Zeskanuj kod QR lub wpisz sekret w aplikacji, potem potwierdź kodem.", "info")
            return redirect(url_for("auth.totp_settings"))

        if action == "cancel":
            session.pop("totp_setup_secret", None)
            flash("Konfiguracja TOTP anulowana.", "info")
            return redirect(url_for("auth.totp_settings"))

        if action == "confirm" and setup_form.validate_on_submit():
            secret = session.get("totp_setup_secret")
            if not secret:
                flash("Brak trwającej konfiguracji. Rozpocznij ponownie.", "error")
                return redirect(url_for("auth.totp_settings"))
            result = enable_totp(user, secret, setup_form.code.data)
            if result.ok:
                session.pop("totp_setup_secret", None)
                flash("TOTP włączone. Przy następnym logowaniu wymagany będzie kod.", "success")
                return redirect(url_for("auth.totp_settings"))
            error = result.error

        if action == "disable" and disable_form.validate_on_submit():
            result = disable_totp(
                user,
                password=disable_form.password.data or "",
                code=disable_form.code.data or "",
            )
            if result.ok:
                session.pop("totp_setup_secret", None)
                flash("TOTP wyłączone.", "success")
                return redirect(url_for("auth.totp_settings"))
            error = result.error

    setup_secret = session.get("totp_setup_secret")
    if setup_secret and not user.totp_enabled:
        issuer = current_app.config.get("APP_DISPLAY_NAME", "AuthLab")
        setup_uri = provisioning_uri(secret=setup_secret, login=user.login, issuer=issuer)
        setup_qr = qr_svg_data_uri(setup_uri)

    return render_template(
        "auth/totp_settings.html",
        user=user,
        setup_form=setup_form,
        disable_form=disable_form,
        setup_secret=setup_secret if not user.totp_enabled else None,
        setup_uri=setup_uri,
        setup_qr=setup_qr,
        error=error,
    )
