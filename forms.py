from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo, Email, Regexp

# Forms------------------------
class SignupForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Length(min=3, max=60), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or underscores')])
    name = StringField(validators=[DataRequired()])
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(validators=[DataRequired(), Length(min=8), EqualTo('password', message='Passwords must match')])
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
    email = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired(), Length(min=8)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log in')

class WhoisForm(FlaskForm):
    domain = StringField(validators=[InputRequired()])
    submit = SubmitField('Search')

class Support(FlaskForm):
    question = StringField(validators=[InputRequired()])
    submit = SubmitField('Submit')