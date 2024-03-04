#!/bin/env python3
# app.py
import os
from flask import Flask, render_template, url_for, request, redirect, session, abort, flash, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from decouple import config
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo, Email, Regexp
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, Serializer, BadSignature
from flask_mail import Mail, Message
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import click

import http.client, ssl

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Mail Settings
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@imhoweb.net'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'imhoweb.net'
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEBUG'] = app.debug
app.config['MAIL_SURPRESS_SEND'] = app.testing
mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'imdata.db')
app.config['SECURITY_PASSWORD_SALT'] = config('SECUTIRY_PASSWORD_SALT', default='very-important')
app.config['BCRYPT_LOG_ROUNDS'] = 13
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)

db = SQLAlchemy(app)

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = 'danger'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(150))
    fname = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    last_logged_in = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    confirmed = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)
     
    def check_password(self, password):
        return check_password_hash(self.password_hash,password)    
        
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

# Forms
class SignupForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(), Length(min=3, max=60), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or underscores')])
    fname = StringField('Name', validators=[DataRequired()])
    email = StringField('Email',validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=8), EqualTo('password', message='Passwords must match')])
    subscribe = BooleanField('Subscribe to our newsletter')
    submit = SubmitField('Sign Up')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

    def validate_password(self,field):
        if self.password.data != self.confirm_password.data:
            raise ValidationError('Passwords must match!')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired(), Length(min=8)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log in')

class WhoisForm(FlaskForm):
    domain = StringField(validators=[InputRequired()])
    submit = SubmitField('Search')

class Support(FlaskForm):
    question = StringField(validators=[InputRequired()])
    submit = SubmitField('Submit')

# Views/Routes
@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_logged_in = datetime.utcnow()
        db.session.commit()

@app.route('/')
@app.route('/index')
@app.route('/index.html')
def index():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/about')
@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/dashboard')
@app.route('/dashboard.html')
def dashboard():
    return render_template('dashboard.html')

@app.route('/domains')
@app.route('/domains.html')
def domains():
    return render_template('domains.html')

@app.route('/contact')
@app.route('/contact.html')
def contact():
    return render_template('contact.html')

@app.route('/hosting')
@app.route('/hosting.html')
def products():
    return render_template('hosting.html')

@app.route('/support', methods=['GET', 'POST'])
@app.route('/support.html')
def support():
    form = Support()
    if form.validate_on_submit():
        flash('Your question has been submitted!')
        return render_template('support.html', form=form)
    return render_template('support.html', form=form)

@app.route('/checkout')
@app.route('/checkout.html')
def checkout():
    return render_template('checkout.html')

@app.route('/whois', methods=['GET', 'POST'])
def whois():
    data = []
    form = WhoisForm()
    # https://rapidapi.com/domaination-domaination-default/api/domaination-io
    if request.method == 'POST' and form.validate_on_submit():
        conn = http.client.HTTPSConnection("domaination.p.rapidapi.com", context = ssl._create_unverified_context())

        headers = {
            'X-RapidAPI-Key': "9af15682a0msh16b3a61943ae91ep146319jsn8ba92346448a",
            'X-RapidAPI-Host': "domaination.p.rapidapi.com"
            }
        qdomain = '/domains/%s' %form.domain.data
        print (qdomain)
        conn.request("GET", qdomain, headers=headers)
        res = conn.getresponse()
        data = res.read()

        print(data.decode("utf-8"))
        return render_template('whois.html', form=form, data=data)
        #return jsonify(data)

    return render_template('whois.html', form=form)

@app.cli.command()
def create_admin():
    #Creates the admin user,
    db.session.add(User(
        email = "ad@min.com",
        password = "admin",
        admin = True,
        confirmed_on = datetime.datetime.now())
    )
    db.session.commit()

@app.route('/signup', methods=['GET', 'POST'])
@app.route('/signup.html')
def signup():
    if current_user.is_authenticated:
        flash('You are already registered.', 'info')
        return redirect('/home')
    form = SignupForm(request.form)
    if form.validate_on_submit():
        user = User(username=form.username.data, fname=form.fname.data, email=form.email.data, confirmed=False)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        flash('You have successfully signed up ', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or as expired.','danger')
    user = User.query.filter_by(email=)

    
@app.route('/<int:user>/edit/', methods=['GET', 'POST'])
@login_required
def edit(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        email = request.form['email']
        fname = request.form['name']
        bio = request.form['bio']

        user.email = email
        user.fname = fname
        user.bio = bio

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('home'))
        
    return render_template('edit.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid email address or Password.')    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/u/<id>',  methods=['GET', 'POST'])
@login_required
def user(id):
    user = User.query.filter_by(id=id).first() 
    if user is None:
        abort(404)
    return render_template('profile.html', user=user)

@app.route('/blog')
@app.route('/blog.html')
def blog():
    return render_template('blog.html')

@app.route('/blog/<int:idx>')
def blog_post(idx):
    messages = ['Message Zero', 'Message One', 'Message Two']
    try:
        return render_template('blog-post.html', message=messages[idx])
    except IndexError:
        abort(404)

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 404 status explicitly
    return render_template('500.html'), 500


# Omittable
if __name__ == "__main__":
    app.run(debug=True)
    app.cli()