import os
import io
import base64
import time
import hashlib

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, session, Markup, make_response
from werkzeug.datastructures import MultiDict
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message, Mail
import pyotp
import qrcode

from database import mydb, cursor, create_user_query, search_user_with_email_query, search_user_with_id_query, \
    update_password_with_id_query, delete_user_with_id_query, update_confirm_email_query, set_up_2fa_query, remove_2fa_query
from forms import SignUpForm, LogInForm, UpdatePassword, ResetPasswordForm, RequestPasswordResetForm, Setup2FA, Verify2FA

# Set up Flask app and config
app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('APPCONFIGSECRETKEY')
app.config["SECURITY_PASSWORD_SALT"] = 'confirm-email'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('MAILUSERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAILPASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# email validation
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def generate_token(email):
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])


def confirm_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
        return email
    except Exception:
        return False


mail = Mail(app)


def send_verification_email(email):
    token = generate_token(email)
    verification_link = url_for('confirm_email', token=token, _external=True)
    msg = Message(
        subject='Please confirm your email',
        html=f"<p>Thank you for signing up!<p>"
             f"<p>Click the link below to verify your email:</p>"
             f"<p>{verification_link}</p>",
        sender=('Sign-up and Log in', app.config['MAIL_USERNAME']),
        recipients=[email]
    )
    mail.send(msg)


def send_password_reset_request_email(email):
    token = generate_token(email)
    password_reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message(
        subject='Reset your password',
        html=f"<p>We received a password reset request from your account.<p>"
             f"<p>Click the link below to create a new password:</p>"
             f"<p>{password_reset_link}</p>"
             f"If this was sent to you on accident, no need to do anything, your password will remain unchanged.",
        sender=('Sign-up and Log in', app.config['MAIL_USERNAME']),
        recipients=[email]
    )
    mail.send(msg)


def log_user_out():
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('email', None)
    session.pop('first_name', None)
    session.pop('last_name', None)
    session.pop('2fa_secret_key', None)
    session.pop('2fa_enabled', None)
    session.pop('2fa_verified', None)


@app.route('/', methods=["GET", "POST"])
def index():
    return render_template('index.html')


@app.route('/sign-up', methods=["GET", "POST"])
def sign_up():
    sign_up_form = SignUpForm()
    if sign_up_form.validate_on_submit():
        email = sign_up_form.email.data
        # check if user exists
        cursor.execute(search_user_with_email_query, {'email': email})
        check_for_user = cursor.fetchone()
        if check_for_user:
            flash(f"This email already exists, please log in.", category='warning')
            return redirect(url_for('log_in'))

        # create new user
        first_name = sign_up_form.first_name.data
        last_name = sign_up_form.last_name.data
        hashed_salted_pw = generate_password_hash(
            password=sign_up_form.password.data,
            method='pbkdf2:sha256',
            salt_length=14)

        # add new user to database
        new_user = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': hashed_salted_pw
        }
        cursor.execute(create_user_query, new_user)
        mydb.commit()

        # send email verification link
        send_verification_email(email)

        # flash successful message and redirect
        flash(f"Hello {first_name}, your account was created successfully, check your email for a verification link.",
              category='info')
        return redirect(url_for('log_in'))
    else:
        return render_template('sign_up.html', form=sign_up_form)


@app.route('/log-in', methods=["GET", "POST"])
def log_in():
    log_in_form = LogInForm()
    if log_in_form.validate_on_submit():
        email = log_in_form.email.data
        # check if user exists
        cursor.execute(search_user_with_email_query, {'email': email})
        user = cursor.fetchone()
        if not user:
            flash(f"This email doesn't exist, please sign up.", category='warning')
            return redirect(url_for('sign_up'))
        if not check_password_hash(pwhash=user['password'], password=log_in_form.password.data):
            flash(f"Looks like you entered the wrong password, please try again.", category='error')
            return redirect(url_for('log_in'))
        if user['is_verified'] == 0:
            flash(Markup(
                f'You haven\'t verified your email yet, click <a href="/resend-verification-email/{user["email"]}">here</a> to verify your email.'),
                category='info')
            return redirect(url_for('log_in'))
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['first_name'] = user['first_name']
        session['last_name'] = user['last_name']
        if user["2fa_on"] == 0:
            session['loggedin'] = True
            session['2fa_enabled'] = False
            flash(f"Welcome back {user['first_name']}, you are now logged in.", category='info')
            return redirect(url_for('index'))
        else:
            session['2fa_secret_key'] = user['2fa_secret_key']
            session['2fa_enabled'] = True
            return redirect(url_for('verify_2fa'))
    request_password_reset_form = RequestPasswordResetForm()
    if request_password_reset_form.validate_on_submit():
        email = request_password_reset_form.email.data
        # check if user exists
        cursor.execute(search_user_with_email_query, {'email': email})
        user = cursor.fetchone()
        if not user:
            flash(f"This email doesn't exist, please sign up.", category='warning')
            return redirect(url_for('sign_up'))
        send_password_reset_request_email(email)
        flash(f"Check your emails and follow the instruction to reset your password", category='info')
        return redirect(url_for('log_in'))
    return render_template(
        'log_in.html',
        log_in_form=log_in_form,
        request_password_reset_form=request_password_reset_form
    )


@app.route('/log-out')
def log_out():
    log_user_out()
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not session['loggedin']:
        flash(f"Log in to access this page.", category='info')
        return redirect(url_for('index'))
    update_password_form = UpdatePassword()
    if update_password_form.validate_on_submit():
        user_id = session['user_id']
        cursor.execute(search_user_with_id_query, {'id': user_id})
        current_user = cursor.fetchone()
        if not check_password_hash(pwhash=current_user['password'],
                                   password=update_password_form.current_password.data):
            flash(f"Looks like you entered the wrong password, please try again.", category='error')
            return render_template('settings.html', form=update_password_form)
        new_hashed_salted_password = generate_password_hash(
            password=update_password_form.new_password.data,
            method='pbkdf2:sha256',
            salt_length=14)
        cursor.execute(update_password_with_id_query, {'id': user_id, 'password': new_hashed_salted_password})
        mydb.commit()
        flash('Your password was changed successfully.', category='success')
        return render_template('settings.html', form=update_password_form)
    return render_template('settings.html', form=update_password_form)


@app.route('/set-up-2fa', methods=['GET', 'POST'])
def set_up_2fa():
    set_up_2fa_form = Setup2FA()

    if 'secret_2fa_key' not in session:
        secret_2fa_key = pyotp.random_base32()
        session['secret_2fa_key'] = secret_2fa_key
    else:
        secret_2fa_key = session['secret_2fa_key']

    if set_up_2fa_form.validate_on_submit():
        totp_entered = set_up_2fa_form.totp_2fa.data
        totp_verification = pyotp.TOTP(secret_2fa_key).verify(totp_entered)
        if totp_verification:
            print(totp_verification)
            print(session)
            # encoded_secret_2fa_key = base64.urlsafe_b64encode(secret_2fa_key.encode())
            # hashed_salted_secret_key = hashlib.sha256(encoded_secret_2fa_key).hexdigest()
            # hashed_salted_secret_key = generate_password_hash(
            #     password=secret_2fa_key,
            #     method='pbkdf2:sha256',
            #     salt_length=14)
            data = {
                'hashed_2fa_secret_key': secret_2fa_key,
                'date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'user_id': session['user_id']
            }
            cursor.execute(set_up_2fa_query, data)
            mydb.commit()
            session['2fa_enabled'] = True
            flash("2FA was set up successfully.", category='success')
            return redirect(url_for('settings'))
        # if validated: save salted secret key to user database and update relevant database columns
        # if not validated, return to set up page and refresh page to generate new secret key
        else:
            flash("Woops this code didn't work, please try again.", category='warning')
            return render_template("set_up_2fa.html")

    # Generate a QR code image for the TOTP secret key
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(pyotp.totp.TOTP(secret_2fa_key).provisioning_uri('Advanced Log In & Sign-Up'))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # encode image to pass it to HTML
    data = io.BytesIO()
    img.save(data, "JPEG")
    qrcode_img_data = base64.b64encode(data.getvalue())
    decoded_qrcode_data = qrcode_img_data.decode('utf-8')
    qrcode_data = f"data:image/jpeg;base64,{decoded_qrcode_data}"

    return render_template('set_up_2fa.html', form=set_up_2fa_form, secret_2fa_key=secret_2fa_key, qr_code_data=qrcode_data)


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_secret_key' not in session:
        flash("Woops you're not allowed here, sign up or log in please.", category='warning')
        return redirect(url_for('index'))
    verify_2fa_form = Verify2FA()
    if verify_2fa_form.validate_on_submit():
        form_otp = verify_2fa_form.verify_totp_2fa.data
        # encoded_secret_2fa_key = base64.urlsafe_b64encode(form_otp.encode())
        # hashed_salted_form_otp = hashlib.sha256(encoded_secret_2fa_key).hexdigest()
        # hashed_salted_form_otp = generate_password_hash(
        #     password=form_otp,
        #     method='pbkdf2:sha256',
        #     salt_length=14)
        user_2fa_secret_key = session['2fa_secret_key']
        totp_verification = pyotp.TOTP(user_2fa_secret_key).verify(form_otp)
        if totp_verification:
            session['loggedin'] = True
            flash("Successful log in", category='info')
            return redirect(url_for('index'))
        else:
            flash("Woops this code didn't work, please try again.", category='warning')
            return render_template("verify_2fa.html", verify_2fa_form=verify_2fa_form)

    return render_template("verify_2fa.html", verify_2fa_form=verify_2fa_form)


@app.route('/remove-2fa', methods=['GET', 'POST'])
def remove_2fa():
    cursor.execute(remove_2fa_query, {'user_id': session['user_id']})
    mydb.commit()
    session.pop('2fa_enabled', None)
    flash("2-Factor Authentication was successfully removed.", category='info')
    return redirect(url_for('settings'))


@app.route('/delete-account')
def delete_account():
    cursor.execute(delete_user_with_id_query, {'user_id': session['user_id']})
    mydb.commit()
    log_user_out()
    flash(message='Your account was deleted successfully.', category='info')
    return redirect(url_for('index'))


@app.route('/confirm-email/<token>')
def confirm_email(token):
    # find user in database
    email = confirm_token(token)
    cursor.execute(search_user_with_email_query, {'email': email})
    user = cursor.fetchone()
    # check if user exists
    if not user:
        flash("Woops you're not allowed here, sign up or log in please.", category='warning')
        return redirect(url_for('index'))
    # check if user already verified
    if user['is_verified'] == 1:
        flash("Your email has already been verified, please log in.", category='info')
        return redirect(url_for('log_in'))
    cursor.execute(update_confirm_email_query, {'date': time.strftime('%Y-%m-%d %H:%M:%S'), 'email': email})
    mydb.commit()
    flash("Your email is now verified, please log in.", category='info')
    return redirect(url_for('log_in'))


@app.route('/resend-verification-email/<email>')
def resend_verification_email(email):
    # send email verification link
    send_verification_email(email)

    # flash successful message and redirect
    flash(f"Check your email for a verification link.",
          category='info')
    return redirect(url_for('log_in'))


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    print('form loaded')
    email = confirm_token(token)
    cursor.execute(search_user_with_email_query, {'email': email})
    user = cursor.fetchone()
    if not user:
        flash("Woops you're not allowed here, sign up or log in please.", category='warning')
        return redirect(url_for('index'))
    print('user found: ', user)
    reset_password_form = ResetPasswordForm()
    print(reset_password_form.errors)
    if reset_password_form.validate_on_submit():
        print(reset_password_form.errors)
        print('form submitted')
        new_hashed_salted_password = generate_password_hash(
            password=reset_password_form.reset_password.data,
            method='pbkdf2:sha256',
            salt_length=14)
        print(new_hashed_salted_password)
        cursor.execute(update_password_with_id_query, {'id': user['id'], 'password': new_hashed_salted_password})
        mydb.commit()
        flash('Your password was changed successfully.', category='success')
        return redirect(url_for('log_in'))
    print('skipped validation')
    return render_template('reset_password.html', form=reset_password_form, token=token)


if __name__ == "__main__":
    # dev
    # app.run(host="127.0.0.1", port=8080, debug=True)
    # prod
    app.run()
