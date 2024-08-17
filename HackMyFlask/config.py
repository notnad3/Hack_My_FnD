
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
