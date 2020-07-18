from flask import Flask
import os

app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
SECRET_KEY='dev',
DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
)

# ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

@app.route('/')
def index():
    return "<h1>My First Website On Heroku</h1>"

def sqema():
    import sqlite3
    db = sqlite3.connect('sqema.sql')
    db.executescript('''
        create teble user(username text, age int);
        insert into user Values('gani', 25),('habib',23);
    ''')

import sqlite3
import click
from flask import current_app, g
from flask.cli import with_appcontext
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

schema = '''
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS post;

CREATE TABLE user (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE NOT NULL,
password TEXT NOT NULL
);
CREATE TABLE post (
id INTEGER PRIMARY KEY AUTOINCREMENT,
author_id INTEGER NOT NULL,
created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
title TEXT NOT NULL,
body TEXT NOT NULL,
FOREIGN KEY (author_id) REFERENCES user (id)
);
'''

def init_db():
    db = get_db()
    db.executescript(schema)

def init_app(app):
    app.teardown_appcontext(close_db)

import functools
from flask import (
Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
        'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)
        if error is None:
            db.execute(
            'INSERT INTO user (username, password) VALUES (?, ?)',
            (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))
        flash(error)
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()
        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
        'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

init_app(app)
app.register_blueprint(bp)
if __name__ == '__main__':
    init_db()
    app.run(debug=True)