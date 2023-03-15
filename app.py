import os

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash

from database import mydb, cursor, create_user_query, search_user_with_email_query
from forms import SignUpForm, LogInForm

# Set up Flask app
app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('APPCONFIGSECRETKEY')


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
        check_for_user = cursor.fetchall()
        print('User trying to sign up ...')
        print('Checked for users:', check_for_user)
        if check_for_user:
            flash(f"This email already exists, please log in.")
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
        flash(f"Hello {first_name}, your account was created successfully, please log in.")
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
        check_for_user = cursor.fetchall()
        print('User trying to log in ...')
        print('Checked for users:', check_for_user)
        if not check_for_user:
            flash(f"This email doesn't exist, please sign up.")
            return redirect(url_for('sign_up'))
        user = check_for_user[0]
        if not check_password_hash(pwhash=user['password'], password=log_in_form.password.data):
            print("Woops, looks like your entered the wrong password.")
            flash(f"Looks like you entered the wrong password, please try again.")
            return redirect(url_for('log_in'))

        print(f"Welcome back {user['first_name']}")
        flash(f"Welcome back {user['first_name']}, you are now logged in.")
        return redirect(url_for('index'))
    return render_template('log_in.html', form=log_in_form)


@app.route('/reset-password')
def reset_password():
    return render_template('reset_password.html')


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)

# TODO: enable version control et push to github
# TODO: switch to a hosted database
# TODO: customize alerts (change colour based on type of alert)
# TODO: add email link verification
# TODO: add reset password feature
# TODO: after successful log in, connect user and redirect to home page with specific message
# TODO: add URL parameter to speed up entry: if wrong password, populate email field with last email entered
