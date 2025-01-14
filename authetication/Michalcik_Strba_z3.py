from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import pytz
import hashlib
import os
import re

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

local_timezone = pytz.timezone('Europe/Bratislava')

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela
    - password_hash: hashovane heslo
    - password_salt: salt
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), unique=False, nullable=False)
    password_salt = db.Column(db.String(32), unique=False, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

# check if the password contains at least one lower case, one uppred case, one digit, one symbol
# and is at least 12 chars length
def password_complexity_check(form, field):
    password = field.data

    if len(password) < 12:
        flash('Password must be at least 12 characters long.')
        return False
    if not re.search(r'[A-Z]', password):
        flash('Password must contain at least one uppercase letter.')
        return False
    if not re.search(r'[a-z]', password):
        flash('Password must contain at least one lowercase letter.')
        return False
    if not re.search(r'[0-9]', password):
        flash('Password must contain at least one digit.')
        return False
    if not re.search(r'[\W_]', password):
        flash('Password must contain at least one special character.')
        return False

    return True

# function checks if input password is not obtained in common passwords database/list
def check_common_password(form, field):
    password = field.data
    common_passwords = set()

    password_folder = 'passwords'
    # List all files in the passwords folder
    for filename in os.listdir(password_folder):
        if filename.endswith('.txt'):
            filepath = os.path.join(password_folder, filename)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    common_passwords.add(line.strip().lower())

    if password.lower() in common_passwords:
        flash('Password is too common. Please choose a more secure password.')
        return False

    return True

# function for hashing password, using pbkdf2 requiring salt and iterations
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    iterations = 100000
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()
    return salt_hex, hashed_password_hex

# retrieve hex salt and hex hash from database, convert to byte format and compare with input login password
def verify_password(stored_salt_hex, stored_hash_hex, password_to_check):
    iterations = 100000
    salt = bytes.fromhex(stored_salt_hex)
    stored_hash = bytes.fromhex(stored_hash_hex)
    new_hash = hashlib.pbkdf2_hmac('sha256', password_to_check.encode(), salt, iterations)
    return new_hash == stored_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    db.create_all()

    # Check if the test user already exists to avoid duplication
    if not User.query.filter_by(username='test').first():
        # Hash the password 'test'
        salt_hex, hashed_password_hex = hash_password('test')
        test_user = User(
            username='test',
            password_salt=salt_hex,
            password_hash=hashed_password_hex,
            failed_attempts=0,
            account_locked_until=None
        )
        db.session.add(test_user)
        db.session.commit()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired()])
    submit = SubmitField('Register')


@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user:
            # Convert account_locked_until to timezone-aware if it's naive
            if user.account_locked_until and user.account_locked_until.tzinfo is None:
                user.account_locked_until = local_timezone.localize(user.account_locked_until)

            # Check if account is locked
            if user.account_locked_until and datetime.now(local_timezone) < user.account_locked_until:
                remaining = user.account_locked_until - datetime.now(local_timezone)
                flash(f'Login is disabled. Try again after {int(remaining.total_seconds() // 60)} minutes.')
                return render_template('login.html', form=form)
            # Verify password
            if verify_password(user.password_salt, user.password_hash, password):
                # Successful login
                user.failed_attempts = 0
                user.account_locked_until = None
                db.session.commit()
                login_user(user)
                db.session.commit()
                return redirect(url_for('home'))
            else:
                # Failed login attempt
                user.failed_attempts +=1
                if user.failed_attempts >=5:
                    # Lock account for 5 minutes
                    user.account_locked_until = datetime.now(local_timezone) + timedelta(minutes=5)
                    flash('Too many failed login attempts. Login is disabled for 5 minutes.')
                else:
                    flash('Invalid username or password.')
                db.session.commit()
        else:
            flash('Invalid username or password.')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])  
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        # Check if username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Check password complexity and common passwords handled by validators
        if not password_complexity_check(form, form.password):
            return render_template('register.html', form=form)

        if not check_common_password(form, form.password):
            return render_template('register.html', form=form)

        # Check if password and confirm password are the same
        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html', form=form)

        # Hash the password
        salt_hex, hashed_password_hex = hash_password(password)

        # Create new user with default values for failed_attempts and account_locked_until
        new_user = User(
            username=username,
            password_salt=salt_hex,
            password_hash=hashed_password_hex,
            failed_attempts=0,  # Set initial failed attempts to 0
            account_locked_until=None  # Account is not locked initially
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=1337)