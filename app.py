import os
import time

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, session, Markup
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message, Mail

from database import mydb, cursor, create_user_query, search_user_with_email_query, search_user_with_id_query, \
    update_password_with_id_query, delete_user_with_id, update_confirm_email_query
from forms import SignUpForm, LogInForm, UpdatePassword, SetNewPasswordForm

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


def log_user_out():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('email', None)
    session.pop('first_name', None)
    session.pop('last_name', None)


@app.route('/', methods=["GET", "POST"])
def index():
    print(session)
    return render_template('index.html')


@app.route('/sign-up', methods=["GET", "POST"])
def sign_up():
    sign_up_form = SignUpForm()
    if sign_up_form.validate_on_submit():
        email = sign_up_form.email.data
        # check if user exists
        cursor.execute(search_user_with_email_query, {'email': email})
        check_for_user = cursor.fetchone()
        print('User trying to sign up ...')
        print('Checked for users:', check_for_user)
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
        print('User trying to log in ...')
        # print('Checked for users:', user)
        if not user:
            flash(f"This email doesn't exist, please sign up.", category='warning')
            return redirect(url_for('sign_up'))
        if not check_password_hash(pwhash=user['password'], password=log_in_form.password.data):
            flash(f"Looks like you entered the wrong password, please try again.", category='error')
            return redirect(url_for('log_in'))
        if user['is_verified'] == 0:
            flash(Markup(f'You haven\'t verified your email yet, click <a href="/resend-verification-email/{user["email"]}">here</a> to verify your email.'), category='info')
            return redirect(url_for('log_in'))
        session['loggedin'] = True
        session['id'] = user['id']
        session['email'] = user['email']
        session['first_name'] = user['first_name']
        session['last_name'] = user['last_name']
        flash(f"Welcome back {user['first_name']}, you are now logged in.", category='info')
        return redirect(url_for('index'))
    return render_template('log_in.html', form=log_in_form)


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
        user_id = session['id']
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


@app.route('/delete-account')
def delete_account():
    user_id = session['id']
    cursor.execute(delete_user_with_id, {'id': user_id})
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


@app.route('/set-new-password', methods=["GET", "POST"])
def set_new_password():
    set_new_password_form = SetNewPasswordForm()
    return render_template('reset_password.html', form = set_new_password_form)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)

# TODO: add reset password feature
# TODO: add URL parameter to speed up entry: if wrong password, populate email field with last email entered
