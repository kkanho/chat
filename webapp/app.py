# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

import secrets
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash, Blueprint
from flask_mysqldb import MySQL
from flask_session import Session
import yaml

from datetime import timedelta

import requests
import hashlib
from zxcvbn import zxcvbn
from flask_bcrypt import bcrypt
import time

import pyotp
import qrcode
import base64
from io import BytesIO

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from dotenv import load_dotenv
import os

from mnemonic import Mnemonic

load_dotenv()

app = Flask(__name__)

app.config.update(
    TEMPLATES_AUTO_RELOAD = True
)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = os.getenv("SESSION_SECRET_KEY")
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

# Init Flask limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"]
)



@app.route('/')
@limiter.exempt
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
@limiter.exempt
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_messages')
@limiter.exempt
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def signup():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None

    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        captcha = userDetails['g-recaptcha-response']

        # Checking
        if username is None or password is None or captcha is None:
            error = 'Please enter username and password!'
            return render_template('signup.html', error=error)
        
        # check if captcha is valid
        secret_key = os.getenv("SECRET_KEY")
        response = requests.request("POST", f'https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={captcha}')
        if response.json()["success"] is False:
            error = "Invalid recaptcha"
            return render_template('login.html', error=error)
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT username FROM users WHERE username=%s", (username,))
        account = cur.fetchone()
        if account:
            error = 'Username already been taken!'
            return render_template('signup.html', error=error)
        
        # check password length
        if len(password) < 8:
            error = 'Password length must be at least 8!'
            return render_template('signup.html', error=error)
        
        # check password have been pwned
        sha_password = hashlib.sha1(password.encode()).hexdigest()
        url = "https://api.pwnedpasswords.com/range/" + sha_password[0:5]
        response = requests.request("GET", url)
        pwned_dict = {}
        pwned_passwords = response.text.split("\r\n")
        for pwned_password in pwned_passwords:
            pwned_hashes = pwned_password.split(":")
            pwned_dict[pwned_hashes[0]] = pwned_hashes[1]

        if sha_password[5:].upper() in pwned_dict.keys():
            error = 'Password previously exposed in data breaches, try another password!'
            return render_template('signup.html', error=error)
        
        # check password strength (zxcvbn)
        results = zxcvbn(password, user_inputs=[username],)
        if (results["score"] < 3):
            error = 'Password weak, try another password!'
            return render_template('signup.html', error=error)

        # Hash the password
        password_salt = bcrypt.gensalt(15)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), password_salt)

        # (Google Authenticator OTP)
        twofa_key =  pyotp.random_base32() # Generate a random secret key
        uri = pyotp.totp.TOTP(twofa_key).provisioning_uri(name=username, issuer_name="group-39.comp3334.xavier2dc.fr")
        generatedQrCode = qrcode.make(uri)
        buf = BytesIO()
        generatedQrCode.save(buf, "PNG")

        if buf is None:
            error = '2FA for OTP qrcode generate error!!!'
            return render_template('signup.html', error=error)
        
        qrCode = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

        mnemo = Mnemonic("english")
        words = mnemo.generate(strength=128)
        hashed_phrase = hashlib.sha256(words.encode()).hexdigest()

        cur.execute("INSERT INTO users (username, hashed_password, password_salt, twofa_key, hashed_phrase) VALUES (%s, %s, %s, %s, %s)", (username, hashed_password, password_salt, twofa_key, hashed_phrase, ))
        mysql.connection.commit()
        cur.close()


        flash('Sign up successfully. Please login', 'info')
        return render_template('login.html', qrCode=qrCode, twofa_key=twofa_key, words=words)

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        otp = userDetails['otp']
        captcha = userDetails['g-recaptcha-response']
        
        if username is None or password is None or otp is None or captcha is None:
            error = 'Invalid credentials'
            return render_template('login.html', error=error)
        
        # check if captcha is valid
        secret_key = os.getenv("SECRET_KEY")
        response = requests.request("POST", f'https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={captcha}')
        if response.json()["success"] is False:
            error = "Invalid recaptcha"
            return render_template('login.html', error=error)
        
        cur = mysql.connection.cursor()
        # find the user's hashed_password
        cur.execute("SELECT hashed_password FROM users WHERE username=%s", (username,))
        hashed_password = cur.fetchone()
        if hashed_password is None:
            time.sleep(3)
            error = 'Invalid credentials'
            return render_template('login.html', error=error)
        hashed_password = hashed_password[0]

        # verify the password
        if bcrypt.checkpw(password.encode('utf-8'), bytes(hashed_password, 'utf-8')) is False:
            error = 'Invalid credentials'
            return render_template('login.html', error=error)
        
        try:
            # find the user's twofa_key
            cur.execute("SELECT twofa_key FROM users WHERE username=%s", (username,))
            twofa_key = cur.fetchone()
            twofa_key = twofa_key[0]

            # verify the otp
            totp = pyotp.totp.TOTP(twofa_key)
            if totp.verify(otp) is False:
                error = 'Invalid OTP code'
                return render_template('login.html', error=error)
        except:
            error = 'Invalid OTP code'
            return render_template('login.html', error=error)
        
        cur.execute("SELECT user_id FROM users WHERE username=%s AND hashed_password=%s", (username, hashed_password,))
        account = cur.fetchone()
        if account:
            session['username'] = username
            session['user_id'] = account[0]
            session.permanent = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'

    return render_template('login.html', error=error)

@app.route('/forgotPassword', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def forgotPassword():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None

    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        passphrase = userDetails['passphrase']
        new_password = userDetails['password']
        otp = userDetails['otp']
        captcha = userDetails['g-recaptcha-response']
        
        if username is None or passphrase is None or new_password is None or otp is None or captcha is None:
            error = 'Invalid credentials'
            return render_template('forgotPassword.html', error=error)
        
        cur = mysql.connection.cursor()

        # check username
        cur.execute("SELECT username FROM users WHERE username=%s", (username,))
        account = cur.fetchone()
        if not account:
            error = 'Account not found'
            return render_template('forgotPassword.html', error=error)

        # check OTP
        try:
            # find the user's twofa_key
            cur.execute("SELECT twofa_key FROM users WHERE username=%s", (username,))
            twofa_key = cur.fetchone()
            twofa_key = twofa_key[0]

            # verify the otp
            totp = pyotp.totp.TOTP(twofa_key)
            if totp.verify(otp) is False:
                error = 'Invalid OTP code'
                return render_template('forgotPassword.html', error=error)
        except:
            error = 'Invalid OTP code'
            return render_template('forgotPassword.html', error=error)

        # check if captcha is valid
        secret_key = os.getenv("SECRET_KEY")
        response = requests.request("POST", f'https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={captcha}')
        if response.json()["success"] is False:
            error = "Invalid recaptcha"
            return render_template('forgotPassword.html', error=error)
        
        # find the user's hashed_phrase
        cur.execute("SELECT hashed_phrase FROM users WHERE username=%s", (username,))
        hashed_phrase = cur.fetchone()
        if hashed_phrase is None:
            time.sleep(3)
            error = 'Invalid credentials'
            return render_template('forgotPassword.html', error=error)
        hashed_phrase = hashed_phrase[0]

        # compare the phrase
        if hashlib.sha256(passphrase.encode()).hexdigest() != hashed_phrase:
            error = 'Wrong phrase'
            return render_template('forgotPassword.html', error=error)
        

        # check new password length
        if len(new_password) < 8:
            error = 'Password length must be at least 8!'
            return render_template('forgotPassword.html', error=error)
        
        # check new password have been pwned
        sha_password = hashlib.sha1(new_password.encode()).hexdigest()
        url = "https://api.pwnedpasswords.com/range/" + sha_password[0:5]
        response = requests.request("GET", url)
        pwned_dict = {}
        pwned_passwords = response.text.split("\r\n")
        for pwned_password in pwned_passwords:
            pwned_hashes = pwned_password.split(":")
            pwned_dict[pwned_hashes[0]] = pwned_hashes[1]

        if sha_password[5:].upper() in pwned_dict.keys():
            error = 'Password previously exposed in data breaches, try another password!'
            return render_template('forgotPassword.html', error=error)
        
        # check new password strength (zxcvbn)
        results = zxcvbn(new_password, user_inputs=[username],)
        if (results["score"] < 3):
            error = 'Password weak, try another password!'
            return render_template('forgotPassword.html', error=error)

        # Hash the new password
        password_salt = bcrypt.gensalt(15)
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), password_salt)

        # generate new words for next recovery
        mnemo = Mnemonic("english")
        words = mnemo.generate(strength=128)
        hashed_phrase = hashlib.sha256(words.encode()).hexdigest()

        cur.execute("UPDATE users SET hashed_password=%s, password_salt=%s, hashed_phrase=%s WHERE username=%s", (hashed_password, password_salt, hashed_phrase, username, ))
        mysql.connection.commit()
        cur.close()

        flash('Password recovery successful. Please login', 'info')
        return render_template('login.html', error=error, words=words)

    return render_template('forgotPassword.html', error=error)

@app.route('/send_message', methods=['POST'])
@limiter.exempt
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (%s, %s, %s)", (sender, receiver, message,))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
@limiter.exempt
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
@limiter.exempt
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

