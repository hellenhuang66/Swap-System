from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 用于会话加密
app.config['MYSQL_USER'] = 'your_mysql_user'
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
app.config['MYSQL_DB'] = 'user_system'
app.config['MYSQL_HOST'] = 'localhost'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 会话保持7天
bcrypt = Bcrypt(app)
mysql = MySQL(app)

@app.route('/')
def swap_index():
    if 'loggedin' in session:
        return render_template('swap_index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        if user and bcrypt.check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['username'] = user['username']
            if 'remember' in request.form:
                session.permanent = True  # 启用永久会话
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Incorrect username or password!', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account:
            flash('Account already exists!', 'danger')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!', 'danger')
        elif not username or not password:
            flash('Please fill out the form!', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
            mysql.connection.commit()
            flash('You have successfully registered!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    flash('You have successfully logged out!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
