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
