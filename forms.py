from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from wtforms.widgets import EmailInput


class SignUpForm(FlaskForm):
    first_name = StringField(
        name='first-name',
        label='First Name',
        render_kw={"placeholder": "first name"},
        validators=[DataRequired(message="Your first name is required.")])
    last_name = StringField(
        name='last-name',
        label='Last Name',
        render_kw={"placeholder": "last name"},
        validators=[DataRequired(message="Your last name is required.")])
    email = StringField(
        name='email',
        label="Email",
        render_kw={"placeholder": "email"},
        widget=EmailInput(),
        validators=[DataRequired(message="Your email is required."), Email()])
    password = PasswordField(
        name='password',
        label='Password',
        render_kw={"placeholder": "password"},
        validators=[DataRequired(message="Password must be at least 8 characters long."), Length(min=8)]
    )
    confirm_password = PasswordField(
        name='confirm_password',
        label='Confirm password',
        render_kw={"placeholder": "confirm password"},
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    sign_up = SubmitField("Sign Up")


class LogInForm(FlaskForm):
    email = StringField(
        name='email',
        label="Email",
        render_kw={"placeholder": "email"},
        widget=EmailInput(),
        validators=[DataRequired(message="Your email is required."), Email()])
    password = PasswordField(
        name='password',
        label='Password',
        render_kw={"placeholder": "password"},
        validators=[DataRequired(message="Your password is required")]
    )
    log_in = SubmitField("Log In")


class UpdatePassword(FlaskForm):
    current_password = PasswordField(
        name='current_password',
        label='Password',
        render_kw={"placeholder": "current password"},
        validators=[DataRequired(message="Your password is at least 8 characters long."), Length(min=8)]
    )
    new_password = PasswordField(
        name='new_password',
        label='New password',
        render_kw={"placeholder": "new password"},
        validators=[DataRequired(message="Password must be at least 8 characters long."), Length(min=8)]
    )
    confirm_new_password = PasswordField(
        name='confirm_new_password',
        label='Confirm new password',
        render_kw={"placeholder": "confirm new password"},
        validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')]
    )
    update_password = SubmitField("Update password")


class ResetPasswordForm(FlaskForm):
    reset_password = PasswordField(
        name='password',
        label='Password',
        render_kw={"placeholder": "password"},
        validators=[DataRequired(message="Password must be at least 8 characters long."), Length(min=8)]
    )
    confirm_reset_password = PasswordField(
        name='confirm_password',
        label='Confirm password',
        render_kw={"placeholder": "confirm password"},
        validators=[DataRequired(), EqualTo('reset_password', message='Passwords must match.')]
    )
    set_reset_password = SubmitField("Set new password")


class RequestPasswordResetForm(FlaskForm):
    email = StringField(
        name='email',
        label="Email",
        render_kw={"placeholder": "email"},
        widget=EmailInput(),
        validators=[DataRequired(message="Your email is required."), Email()])
    send_request_password_reset = SubmitField("Send")


class Setup2FA(FlaskForm):
    totp_2fa = StringField(
        name='totp_2fa',
        label='2FA Code',
        render_kw={"placeholder": "2fa code"},
        validators=[DataRequired(message="Your first name is required."), Length(min=6, max=6, message="2FA code must be 6 digits")])
    set_up_2fa = SubmitField("Validate")
