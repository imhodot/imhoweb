#!/bin/env python3
# app.py
import os
from flask import Flask, render_template, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = 'IamHumble!'


@app.route('/')
@app.route('/index.html')
def index():
    return render_template('index.html')

@app.route('/about')
@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/blog')
@app.route('/blog.html')
def blog():
    return render_template('blog.html')

@app.route('/contact')
@app.route('/contact.html')
def contact():
    return render_template('contact.html')

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('500.html'), 500

# Omittable
if __name__ == "__main__":
    app.run(debug=True)


