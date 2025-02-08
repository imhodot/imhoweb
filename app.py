#!/bin/env python3
# app.py
import os
from flask import (
    Flask, render_template, url_for, request, redirect, 
    session, abort, flash, jsonify, current_app
)
from flask_migrate import Migrate
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_required, 
    login_user, logout_user, current_user
)
from datetime import datetime
from flask_mail import Mail, Message
import click 
from functools import wraps
import http.client, ssl

## Local Imports
# Import configs from config.py
from config import Config

# Import models from models.py
from models import db, User
from forms import SignupForm, LoginForm, WhoisForm, Support
from utils import generate_and_store_code, send_email, validate_verification

# Initialize Flask app and load configuration
app = Flask(__name__)
app.config.from_object(Config)  # from config.py

# Initialize Flask Extensions
db.init_app(app)
migrate = Migrate(app, db)  # Migrate
mail = Mail(app)  # Mail


# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect to login if user is not authenticated
login_manager.login_message_category = 'danger'


# Load the user
@login_manager.user_loader
def load_user(user_id):
    """Load a user by ID."""
    return db.session.get(User, int(user_id))


## Initialize the database (Create the database and tables)
with app.app_context():
    db.create_all()

# Views/Routes-----------------------
@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_logged_in = datetime.utcnow()
        db.session.commit()

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/index1')
def index1():
    return render_template('index1.html')

@app.route('/index3')
def index3():
    return render_template('index3.html')

@app.route('/index4')
def index4():
    return render_template('index4.html')

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
def about():
    return render_template('about.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/shopping_cart', methods=['GET', 'POST'])
def shopping_cart():
    return render_template('shopping_cart.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    return render_template('settings.html')

@app.route('/domains', methods=['GET', 'POST'])
def domains():
    return render_template('domains.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/hosting')
def hosting():
    return render_template('hosting.html')

@app.route('/profile')
@login_required
#@check_confirmed
def profile():
    return render_template('profile.html')

@app.route('/support', methods=['GET', 'POST'])
def support():
    form = Support()
    if form.validate_on_submit():
        flash('Your question has been submitted!')
        return render_template('support.html', form=form)
    return render_template('support.html', form=form)

@app.route('/checkout')
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


# View/Route to handle signup
@app.route('/signup', methods=['GET', 'POST'])
#@logout_required
def signup():
    if current_user.is_authenticated:
        flash('You are already registered.', 'info')
        return redirect('/home')
    form = SignupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, name=form.name.data, email=form.email.data, confirmed=False)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('You can now login.', 'info')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)
    
    
@app.route('/u/<int:user_id>/edit/', methods=['GET', 'POST'])
@login_required
def edit(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        bio = request.form['bio']

        user.email = email
        user.name = name
        user.bio = bio

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('home'))
        
    return render_template('edit.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect('/dashboard')    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user, form.remember.data)
            return redirect(url_for('dashboard'))  
        flash('Invalid username or password.')
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

# Error Handling-------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 404 status explicitly
    return render_template('500.html'), 500

# Omittable-------------------------------------
if __name__ == "__main__":
    app.run(debug=True)