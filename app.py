#!/bin/env python3
# app.py
import os
from flask import Flask, render_template, url_for, request, redirect, session, abort, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from datetime import datetime

import http.client, ssl

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'imdata.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

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
    created_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    last_logged_in = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self, password):
        return check_password_hash(self.password_hash,password)

# Forms
class SignupForm(FlaskForm):
    fname = StringField('Name',validators=[DataRequired()])
    email = StringField('Your Email',validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=6)])
    subscribe = BooleanField('Subscribe to our newsletter')
    submit = SubmitField('Sign Up')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.', category='error')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.', category='error')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired(), Length(min=10) ])
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

@app.route('/support', methods=('GET', 'POST'))
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

@app.route('/whois', methods=('GET', 'POST'))
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

@app.route('/signup', methods=('GET', 'POST'))
@app.route('/signup.html')
def signup():
    if current_user.is_authenticated:
        return redirect('/home')
    form = SignupForm()
    if form.validate_on_submit():
        print ('obago 2')
        user = User(fname=form.fname.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        if confirm_password != password:
            flash('Password did not match!', category='error')
        elif:
            return render_template('signup.html')
        else:
            flash('You can login now!', category='success')
            return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)

@app.route('/<int:user>/edit/', methods=('GET', 'POST'))
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

@app.route('/login', methods=('GET', 'POST'))
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

@app.route('/u/<id>',  methods=('GET', 'POST'))
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