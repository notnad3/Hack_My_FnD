from functools import wraps
from flask import request,url_for,redirect



UPLOAD_ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'py','xml','zip'}
SSRF_BlackList = ['', '']
SSTI_BlackList=[]
XSS_BlackList=[]
SQL_BlackList=[' ','or']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        if session_id is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def mysql_real_escape_string(value):
    """
    Escapes special characters in a string for use in an SQL statement.
    This function mimics the behavior of MySQL's mysql_real_escape_string().

    :param value: The string to be escaped.
    :return: The escaped string.
    """
    if value is None:
        return None

    # Define the replacements for special characters
    replacements = {
        '\0': '\\0',
        '\n': '\\n',
        '\r': '\\r',
        '\\': '\\\\',
        '\'': '\\\'',
        '"': '\\"',
        '\x1a': '\\Z'
    }

    escaped_value = []

    for char in value:
        if char in replacements:
            escaped_value.append(replacements[char])
        else:
            escaped_value.append(char)

    return ''.join(escaped_value)

def mysql_real_unescape_string(value):
    """
    Unescapes special characters in a string that were escaped for use in an SQL statement.
    This function reverses the escaping done by mysql_real_escape_string().

    :param value: The escaped string to be unescaped.
    :return: The unescaped string.
    """
    if value is None:
        return None

    # Define the replacements for escaped sequences
    replacements = {
        '\\0': '\0',
        '\\n': '\n',
        '\\r': '\r',
        '\\\\': '\\',
        '\\\'': '\'',
        '\\"': '"',
        '\\Z': '\x1a'
    }

    # Iterate through the replacements and replace each escape sequence with its corresponding character
    for escaped_char, unescaped_char in replacements.items():
        value = value.replace(escaped_char, unescaped_char)

    return value



def allowed_file(filename):
    # return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    return '.' in filename and filename.split('.')[1].lower() in UPLOAD_ALLOWED_EXTENSIONS

def is_blacklisted_SQL(user_id):
    for item in SQL_BlackList:
        if item in user_id:
            return True
    return False

from werkzeug.security import  check_password_hash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

import mysql.connector #这里是mysql-connector-python

from datetime import datetime




app = Flask(__name__)
HOSTNAME = "127.0.0.1"
PORT = 3306
USERNAME = "root"
PASSWORD = "harden13."#password_u_cant_get
DATABASE = "database_learn"
app.config[
    'SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{USERNAME}:{PASSWORD}@{HOSTNAME}:{PORT}/{DATABASE}?charset=utf8"

db = SQLAlchemy(app)

def get_mysql_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='harden13.',
            database='database_learn'
        )
        if conn.is_connected():
            return conn
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_flask_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='harden13.',
            database='hackmyflask'
        )
        if conn.is_connected():
            return conn
    except Exception as e:
        print(f"Error: {e}")
        return None

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique = True,nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    __tablename__ = "usercontent"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(100), db.ForeignKey('user.name'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
