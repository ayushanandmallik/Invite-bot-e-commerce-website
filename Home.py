from flask import Flask, render_template, url_for, session, flash, redirect, wrappers
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired, Email, Length, EqualTo
import sqlite3
from passlib.hash import sha256_crypt
import random
import math
from flask_mail import Mail
from flask_mail import Message
import os
import dotenv
from werkzeug.datastructures import ImmutableOrderedMultiDict
from requests import request
import time
import requests


dotenv.load_dotenv()


my_email= os.getenv('EMAIL')
my_pwd= os.getenv('PASSWORD')
secret_key= os.getenv('SECRET_KEY')

app= Flask(__name__)
app.config['SECRET_KEY']= secret_key
app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 465,
    MAIL_USE_TLS = False,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = my_email,
    MAIL_PASSWORD = my_pwd
))
Bootstrap(app)

mail= Mail(app)

class login_form(FlaskForm):
    Discord_username= StringField('Discord Username', validators=[InputRequired()])
    Password= PasswordField('Password', validators=[InputRequired(), Length(min=5,max=50)])

class signup_form(FlaskForm):
    Name= StringField('Name', validators=[InputRequired('Name is required')])
    Discord_username= StringField('Discord Username', validators=[InputRequired('Discord_username is required')])
    Email= StringField('Email', validators=[InputRequired('Email is required'), Email(message='Invalid email')])
    Password= PasswordField('Password', validators=[InputRequired('Password is required'), Length(min=5, max=50)])



def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form= login_form()
    if form.validate_on_submit():
        Discord_username= form.Discord_username.data
        Password= form.Password.data
        db= sqlite3.connect('users.db')
        cursor= db.cursor()
        sql= '''SELECT * FROM member WHERE Discord_username=?'''
        val= (Discord_username,)
        cursor.execute(sql,val)
        us= cursor.fetchone()[2]
        db.commit()
        cursor.close()
        db.close()
        if sha256_crypt.verify(Password,us):
            session['logged_in']= True
            session['Discord_username']= Discord_username
            flash('You are now logged in')
            return redirect(url_for('profile'))
        else:
            flash('Invalid credentials. Try again')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)











@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form= signup_form()
    if form.validate_on_submit():
        Name= form.Name.data
        Discord_username= form.Discord_username.data
        Email= str(form.Email.data)
        Password= sha256_crypt.encrypt(str(form.Password.data))
        db= sqlite3.connect('users.db')
        cursor= db.cursor()

        sql= '''SELECT * FROM member'''
        cursor.execute(sql)
        members= cursor.fetchall()
        for member in members:
            if member[1]==Discord_username or member[5]==Email:
                flash('Member already exist')
                return redirect(url_for('signup'))

        sql1= '''INSERT INTO member(Name, Discord_username, Password, Email) VALUES(?,?,?,?)'''
        val1=(Name,Discord_username, Password, Email)
        cursor.execute(sql1,val1)
        db.commit()
        cursor.close()
        db.close()
        return render_template('after_signup.html')



    return render_template('signup.html', form=form)



@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out!')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    db= sqlite3.connect('users.db')
    username= session['Discord_username']
    cursor= db.cursor()
    sql= '''SELECT * FROM member WHERE Discord_username=?'''
    val= (username,)
    cursor.execute(sql,val)
    curr_user= cursor.fetchone()
    curr_user_name= curr_user[0]
    curr_user_dusername= curr_user[1]
    curr_user_coins= curr_user[3]
    curr_user_rcoins= curr_user[4]
    curr_user_email= curr_user[5]
    user_details={
        'name': curr_user_name,
        'd_username': curr_user_dusername,
        'coins': curr_user_coins,
        'r_coins': curr_user_rcoins,
        'email': curr_user_email
    }
    db.commit()
    cursor.close()
    db.close()

    return render_template('profile.html', user= user_details)




@app.route('/buycoins/<amount>/<price>')
@login_required
def buycoins(amount,price):
    coin_info= {
        'no_of_coins': amount,
        'price': price
    }
    return render_template('buycoins.html', coin= coin_info)

class forgot_password_form(FlaskForm):
    Email= StringField('Email', validators=[Email(message='Invalid email'), InputRequired(message='This field is required')])
    Discord_username= StringField('Discord_username', validators=[InputRequired(message='This field is required')])


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form= forgot_password_form()
    if form.validate_on_submit():
        Email= str(form.Email.data)
        r_email= [form.Email.data,]
        Discord_username= form.Discord_username.data
        db= sqlite3.connect('users.db')
        cursor= db.cursor()
        sql= '''SELECT * FROM member WHERE Email=? and Discord_username=?'''
        val= (Email, Discord_username)
        cursor.execute(sql,val)
        user= cursor.fetchone()
        if user is None:
            flash('No users found associated with the given credentials')
            return redirect(url_for('forgot_password'))
        else:
            string = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
            OTP = ""
            length = len(string)
            for i in range(6):
                OTP += string[math.floor(random.random() * length)]
            sql1= '''UPDATE member SET Temp_code=? WHERE Email=?'''
            val1= (OTP, Email)
            cursor.execute(sql1, val1)
            db.commit()
            cursor.close()
            db.close()
            session['logged_in'] = True
            session['Discord_username'] = Discord_username
            session['Email'] = Email

            msg= Message(OTP, sender=app.config['MAIL_USERNAME'],recipients=r_email)
            mail.send(msg)
            return redirect(url_for('enter_otp'))
    return render_template('forgot_password.html', form= form)

def create_otp_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Invalid request")
            return redirect(url_for('forgot_password'))

    return wrap

class enter_otp_form(FlaskForm):
    OTP= StringField('OTP', validators=[InputRequired('You need to input the OTP!!!')])

@app.route('/enter_otp', methods=['GET','POST'])
@create_otp_required
def enter_otp():
    form= enter_otp_form()
    if form.validate_on_submit():
        Discord_username= session['Discord_username']
        db= sqlite3.connect('users.db')
        cursor= db.cursor()
        sql= '''SELECT * FROM member WHERE Discord_username=?'''
        val=(Discord_username,)
        cursor.execute(sql,val)
        user= cursor.fetchone()
        e_otp= form.OTP.data
        u_otp= user[6]
        if u_otp is None:
            flash('OTP is not created or has been expired.')
            return redirect(url_for('forgot_password'))
        elif u_otp==e_otp:
            sql1= '''UPDATE member SET Temp_code=? WHERE Discord_username=?'''
            code= None
            val1= (code,Discord_username)
            cursor.execute(sql1, val1)
            db.commit()
            cursor.close()
            db.close()
            return redirect(url_for('new_password'))
        else:
            flash('Wrong OTP try again')
            return redirect(url_for('forgot_password'))

    return render_template('enter_otp.html', form=form)

class new_password_form(FlaskForm):
    New_password= PasswordField('Enter new password', validators=[InputRequired('This field cannot be empty')])
    Confirm_password= PasswordField('Confirm new password', validators=[EqualTo('New_password', message='passwords must match'), InputRequired('This field cannot be empty!')])




@app.route('/new_password', methods=['GET', 'POST'])
@create_otp_required
def new_password():
    form= new_password_form()
    if form.validate_on_submit():
        password= sha256_crypt.encrypt(str(form.New_password.data))
        D_username= session['Discord_username']
        db= sqlite3.connect('users.db')
        cursor= db.cursor()
        sql= '''UPDATE member SET Password=? WHERE Discord_username=?'''
        val=(password,D_username)
        cursor.execute(sql,val)
        db.commit()
        cursor.close()
        db.close()
        session.clear()
        flash('Your password has been updated.')
        return redirect(url_for('login'))



    return render_template('new_password.html', form=form)



@app.route('/purchase', methods=['GET', 'POST'])
@login_required
def purchase():
    return render_template('purchase.html')


@app.route('/success')
@login_required
def success():
    return render_template('success.html')


@app.route('/ipn', methods=['POST'])
def ipn():
    try:
        arg = ''
        request.parameter_storage_class = ImmutableOrderedMultiDict
        values = request.form
        for x, y in values.iteritems():
            arg += "&{x}={y}".format(x=x, y=y)

        validate_url = 'https://www.sandbox.paypal.com' \
                       '/cgi-bin/webscr?cmd=_notify-validate{arg}' \
            .format(arg=arg)
        r = requests.get(validate_url)
        if r.text == 'VERIFIED':
            try:
                payer_email = (request.form.get('payer_email'))
                unix = int(time.time())
                payment_date = (request.form.get('payment_date'))
                username = (request.form.get('custom'))
                last_name = (request.form.get('last_name'))
                payment_gross = (request.form.get('payment_gross'))
                payment_fee = (request.form.get('payment_fee'))
                payment_net = float(payment_gross) - float(payment_fee)
                payment_status = (request.form.get('payment_status'))
                txn_id = (request.form.get('txn_id'))
            except Exception as e:
                with open('/tmp/ipnout.txt', 'a') as f:
                    data = 'ERROR WITH IPN DATA\n' + str(values) + '\n'
                    f.write(data)

            with open('/tmp/ipnout.txt', 'a') as f:
                data = 'SUCCESS\n' + str(values) + '\n'
                f.write(data)

            db= sqlite3.connect('users.db')
            cursor= db.cursor()
            sql= '''INSERT INTO ipn (unix, payment_date, username, last_name, payment_gross, payment_fee, payment_net, payment_status, txn_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)'''
            val=(unix, payment_date, username, last_name, payment_gross, payment_fee, payment_net, payment_status, txn_id)
            cursor.execute(sql,val)
            db.commit()
            cursor.close()
            db.close()
        else:
            with open('/tmp/ipnout.txt', 'a') as f:
                data = 'FAILURE\n' + str(values) + '\n'
                f.write(data)

        return r.text
    except Exception as e:
        return str(e)


class adminsignup(FlaskForm):
    Name= StringField('Name')
    Email = StringField('Email', validators=[InputRequired(), Email()])
    Password = PasswordField('Password', validators=[InputRequired()])

@app.route('/admin_signup')
def admin_signup():
    return render_template('adminsignup.html')


class adminlogin(FlaskForm):
    Email= StringField('Email', validators=[InputRequired(), Email()])
    Password= PasswordField('Password', validators=[InputRequired()])

@app.route('/admin')
def admin():
    return render_template('admin.html')


if __name__=='__main__':
    app.run()