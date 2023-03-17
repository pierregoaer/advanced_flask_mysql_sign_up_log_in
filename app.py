import os

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

from database import mydb, cursor, create_user_query, search_user_with_email_query, search_user_with_id_query, \
    update_password_with_id_query, delete_user_with_id
from forms import SignUpForm, LogInForm, UpdatePassword

# Set up Flask app
app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('APPCONFIGSECRETKEY')


def log_user_out():
    session['loggedin'] = False
    session.pop('id', None)
    session.pop('first_name', None)
    session.pop('last_name', None)


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
        print(first_name, last_name, email, hashed_salted_pw)

        # add new user to database
        new_user = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': hashed_salted_pw
        }
        cursor.execute(create_user_query, new_user)
        mydb.commit()

        # flash successful message and redirect
        flash(f"Hello {first_name}, your account was created successfully, please log in.", category='info')
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
        session['loggedin'] = True
        session['id'] = user['id']
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


@app.route('/reset-password')
def reset_password():
    return render_template('reset_password.html')


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)

# TODO: add URL parameter to speed up entry: if wrong password, populate email field with last email entered
# TODO: add email link verification
# TODO: add reset password feature
