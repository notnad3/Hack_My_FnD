import mimetypes
import os
import pickle
import posixpath
import uuid
import xml
from functools import wraps
from io import BytesIO
import urllib.request
from uuid import UUID
from xml.dom import minidom
import xml.sax.handler
from xml.dom import minidom
import json
import base64
from werkzeug.security import check_password_hash
from forms import LoginForm, PostForm, UploadForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, render_template, url_for, jsonify, redirect, abort, send_file, session, \
    render_template_string, Response, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.utils import secure_filename, send_from_directory
import pycurl
import random
import sqlite3
import mysql.connector #这里是mysql-connector-python
import xml.etree.ElementTree as ET
from lxml import etree
import lxml.objectify
from datetime import datetime
from markupsafe import escape
import shlex
import string



app = Flask(__name__)

# def get_db_connection():
#     conn = sqlite3.connect('database.db')
#     conn.row_factory = sqlite3.Row
#     return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        if session_id is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
# class RemoveSetCookieMiddleware:
#     def __init__(self, app):
#         self.app = app
#
#     def __call__(self, environ, start_response):
#         def custom_start_response(status, headers, exc_info=None):
#             headers = [(name, value) for name, value in headers if name.lower() != 'set-cookie']
#             return start_response(status, headers, exc_info)
#
#         return self.app(environ, custom_start_response)
#
#
# app.wsgi_app = RemoveSetCookieMiddleware(app.wsgi_app)
app.debug = True
app.secret_key = "notbad_3"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# UPLOAD_FOLDER = '.'
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# app.config.from_object(Config)

UPLOAD_ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'py','xml','zip'}
SSRF_BlackList = ['', '']
SSTI_BlackList=[]
XSS_BlackList=[]
SQL_BlackList=[' ','or']

# @app.after_request
# def remove_set_cookie_header(response):
#     response.headers.pop('Set-Cookie', None)
#     return response


sstihtml = """
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f8ff;
            text-align: center;
            padding: 50px;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            display: inline-block;
        }
        p {
            font-size: 18px;
        } 
        .button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
        }    
        h1 {
            color: #4CAF50
        }

    </style>
</head>
<title>SSTI</title>

<body>
<h1>Hello ,your IP is: %s</h1>
    <footer>
        <small>&copy; 2024 <a href="https://notnad3.github.io/" target="_blank" rel="noopener noreferrer">notbad3</a></small>
        <br>
    </footer>
</body>
</html>
"""

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




@app.route('/', methods=['GET', 'POST'])
def index():
    response = make_response(render_template("index.html"))
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    session_id = request.cookies.get('session_id')
    if session_id is None:
        if request.method == 'POST':
            name = request.form.get('name')
            password = request.form.get('password')

            if not name or not password:
                return jsonify({"message": "Name and password are required!"}), 400

            user = User.query.filter_by(name=name).first()
            response = make_response(redirect(url_for('welcome')))

            if user and check_password_hash(user.password, password):
                if user.name == 'admin':
                    response.set_cookie('session_id', 'admin')
                    session['is_admin'] = True
                    return response
                else:
                    response.set_cookie('session_id', user.name)
                    session['is_admin'] = False
                    return response
            else:
                return jsonify({"message": "Invalid name or password!"}), 401

        return render_template("login.html")
    else:
        response = make_response(redirect(url_for('welcome')))
        return response

@app.route('/register', methods=['GET', 'POST'])
def register():
  session_id = request.cookies.get('session_id')
  if session_id:
      return render_template("register_fail.html")
  else:
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')

        if not name or not password:
            flash('Name and password are required!', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(name=name).first()
        if existing_user:
            flash('Username already taken!', 'error')
            return redirect(url_for('register'))
        password = generate_password_hash(password)
        new_user = User(name=name, password=password)

        try:
            db.session.add(new_user)
            db.session.commit()
            return render_template("register_success.html", user=new_user)
        except Exception as e:
            db.session.rollback()
            flash('An error occurred: ' + str(e), 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route("/welcome", methods=['GET', 'POST'])
@login_required
def welcome():
    session_id = request.cookies.get('session_id')

    static_folder = os.path.join(app.root_path, 'static')
    avatar_path_jpg = os.path.join(static_folder, f"{session_id}.jpg")
    avatar_path_png = os.path.join(static_folder, f"{session_id}.png")

    if os.path.exists(avatar_path_jpg):
        avatar_url = f"/static/{session_id}.jpg"
    elif os.path.exists(avatar_path_png):
        avatar_url = f"/static/{session_id}.png"
    else:
        avatar_url = '/static/flask.jpg'

    return render_template("welcome.html", username=session_id, avatar_url=avatar_url)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        session.clear()
        response = make_response(render_template('logout.html', session_id=session_id))

        response.set_cookie('session_id', '', expires=0)

        return response
    else:
        response = make_response(redirect(url_for('login')))
        return response

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_pics():
    session_id = request.cookies.get('session_id')

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if allowed_file(file.filename):
            filename = file.filename
            # filename = secure_filename(file.filename)
            session_id = session.get('session_id', session_id)
            pic_suffix = filename.rsplit('.', 1)[1].lower()
            session['picname'] = f"{session_id}.{pic_suffix}"

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], session['picname'])
            file.save(file_path)

            save_path = os.path.join(app.config['UPLOAD_FOLDER'], session['picname'])
            return render_template("upload_success.html", save_path=save_path)
        else:
            flash('Suffix is not allowed!', 'error')


    return render_template('upload.html')

@app.route('/upload_zip', methods=['GET', 'POST'])
@login_required
def func_uploadunzip():
    session_id = request.cookies.get('session_id')
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']
        print(file)
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if allowed_file(file.filename):
            path = ''.join(random.choices(string.hexdigits, k=16))
            directory = os.path.join(app.config['UPLOAD_FOLDER'], path)
            os.makedirs(directory, exist_ok=True)
            save_path = os.path.join(directory, file.filename)
            file.save(save_path)
            session['filepath'] = save_path
            return render_template("upload_zip_success.html", save_path=save_path)
        else:
            flash('Suffix is not allowed!', 'error')
    else:
        return render_template('upload_zip.html')


@app.route('/unzip', methods=['GET', 'POST'])
@login_required
def func_unzip():
    if request.method == 'POST':
        save_path = session['filepath']
        path = os.path.join(app.config['UPLOAD_FOLDER'], request.form.get('path'))
        os.makedirs(path, mode=0o755, exist_ok=True)
        print(path)
        try:
            os.system(f'tar -xf {save_path} -C {path}')
            # os.system('curl http://lwzd2j1c.requestrepo.com')
            return jsonify({"status": "success", "message": "Unzip successful!"})
        except Exception as e:
            print('There is something wrong with unzip！')
            return jsonify({"status": "error", "message": "Unzip failed!"})
    else:
        return render_template('unzip.html')







# @app.route('/redirect')
# @login_required
# def redirect_to_pic():
#     pic_url = request.args.get('pic_url')
#     if not pic_url:
#         pic_url = app.config['UPLOAD_FOLDER'] + '/' + session.get('picname')
#         return redirect(url_for('userinfo', pic_url=pic_url))
#     return redirect(pic_url)

@app.route("/userinfo", methods=['GET', 'POST'])
@login_required
def userinfo():
    session_id = mysql_real_escape_string(request.cookies.get('session_id'))
    if session_id:
        if not request.args.get('username'):
            return redirect(url_for('userinfo', username=session_id))
        username = request.args.get('username',session_id)
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = f"SELECT * FROM user WHERE name = '{username}'"
            cursor.execute(query)
            user = cursor.fetchall()
            print(user)
        except Exception as e:
            print(f"Error: {e}")
            user = None
        finally:
            cursor.close()
            conn.close()
            username = mysql_real_unescape_string(username)
        return render_template('userinfo.html',user=user,username=username)
    else:
        response = make_response(redirect(url_for('login')))
        return response


@app.route("/changepasswd", methods=['GET', 'POST'])
def changepasswd():
    if request.method == 'POST':
        username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, old_password, new_password, confirm_password]):
            flash('All fields are required!', 'fail')
        elif new_password != confirm_password:
            flash('New passwords do not match!', 'fail')
        else:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)

            try:
                username = mysql_real_escape_string(username)
                query = f"SELECT * FROM user WHERE name = '{username}'"
                print(query)
                cursor.execute(query)
                user = cursor.fetchone()
                print(user)

                if user and check_password_hash(user['password'], old_password):
                    print('user_input_right')
                    new_password_hash = generate_password_hash(new_password)
                    username=mysql_real_unescape_string(username)
                    update_query = f"UPDATE user SET password='{new_password_hash}' WHERE name='{username}';"
                    print(update_query)
                    cursor.execute(update_query)
                    conn.commit()

                    if cursor.rowcount > 0:
                        print('ok')
                        flash('Password changed successfully!', 'success')
                        session.clear()
                        response = make_response(render_template('change_passwd_success.html'))
                        response.set_cookie('session_id', '', expires=0)
                        return response

                    else:
                        print('fail')
                        flash('Password change failed!', 'fail')
                else:
                    print("no!")
                    print(generate_password_hash(old_password))
                    flash('Invalid username or old password!', 'fail')

            except Exception as e:
                flash(f'Error: {e}', 'fail')
            finally:
                cursor.close()
                conn.close()

        return render_template('change_passwd.html')

    return render_template('change_passwd.html')





@app.route('/showpics')
def uploaded_file():
    session_id = request.cookies.get('session_id')
    if session_id:
        filename = request.args.get('filename','flask.jpg')
        if filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                return send_file(filepath)
            else:
                abort(404)
        else:
             abort(400)
    else:
        response = make_response(redirect(url_for('login')))
        return response


@app.route("/list", methods=['GET', 'POST'])
def show_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('show_files.html', files=files)


@app.route("/IP", methods=['GET', 'POST'])
#通过请求头获取IP
def test_ssti():
    if request.headers.getlist("X-Forwarded-For"):
        user_ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        user_ip = request.remote_addr
    name = user_ip
    if name:
        return render_template_string(sstihtml % name)
    else:
        return render_template('404_ssti.html')

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(title=form.title.data, content=form.content.data, author_name=request.cookies.get('session_id'))
        db.session.add(new_post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('view_posts'))
    return render_template('create_post.html', form=form)

@app.route('/posts', methods=['GET'])
@login_required
def view_posts():
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if not request.args.get('orderby'):
            return redirect(url_for('view_posts', orderby='created_at'))
        else:
            orderby = request.args.get('orderby')

        query = f"SELECT * FROM usercontent ORDER BY {orderby}"
        print(query)

        cursor.execute(query)
        posts = cursor.fetchall()

        return render_template('view_posts.html', posts=posts)

    except Exception as e:
        flash(f'Error: {e}', 'fail')

    finally:
        cursor.close()
        conn.close()

@app.route('/post/delete/<int:post_id>')
@login_required
def delete_post(post_id):
    #这里设置CSRF
    post = Post.query.get_or_404(post_id)
    session_id = request.cookies.get('session_id')
    if session_id == 'admin':
        db.session.delete(post)
        db.session.commit()
        flash('Post has been deleted!', 'success')
    else:
        flash('You do not have permission to delete this post!', 'danger')
    return redirect(url_for('view_posts'))






@app.route('/location')
def location():
    return render_template('ssrf.html'), 302, [('Location','http://www.baidu.com')]

# @app.route("/bot", methods=['GET', 'POST'])
# def test_ssti():
#     name = request.args.get('name')
#     if name:
#         return render_template_string(sstihtml %name )
#     else:
#         return render_template('404_ssti.html')




# @app.route('/xss')
# def xss_test():
#     if request.args.get('name'):
#         name = request.args.get('name')
#         # return render_template_string(sstihtml % name)
#         return render_template('XSS.html', name=name)
#     else:
#         return render_template('404_ssti.html')
# @app.route('/check')
# def check():
#     user_input = request.args.get('input', '')
#     template = '''
#     <!DOCTYPE html>
#     <html lang="en">
#     <head>
#         <meta charset="UTF-8">
#         <title>Attribute Injection Example</title>
#     </head>
#     <body>
#         <form action="/check" method="get">
#             <label for="user-input">Enter something:</label>
#             <input type="text" id="user-input" name="input" value={{ user_input }}>
#             <button type="submit">Submit</button>
#         </form>
#     </body>
#     </html>
#     '''
#     return render_template_string(template, user_input=user_input)

@app.route('/readfile')
def read_file():
    admin = session.get("admin")
    if admin:
        filename = request.args.get('filename', 'hello.jpg')
        if filename:
            # 确保文件名安全
            safe_filename = secure_filename(filename)
            safe_filename = filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as file:  # 二进制读取，适用于任意文件类型
                        content = file.read()
                    mimetype, _ = mimetypes.guess_type(filepath)
                    if mimetype is None:
                        mimetype = 'application/octet-stream'  # 默认 MIME 类型
                    return Response(content, mimetype=mimetype)
                except Exception as e:
                    abort(500, description=f"Error reading file: {e}")
            else:
                abort(404, description="File not found")
        else:
            abort(400, description="Bad request: 'filename' parameter is missing")
    else:
        return render_template('404.html')

@app.route('/readfile2')
def read_file2():
    filename = request.args.get('filename', 'hello.jpg')
    if filename:
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # return send_file(path, as_attachment=True)
        return send_file(path)
    else:
        return render_template('404.html')

@app.route('/readfile3')
def read_file3():
    admin = session.get("admin")
    filename = request.args.get('filename')
    if filename:
        try:
            # safe_filename = secure_filename(filename)  # 确保文件名安全
            safe_filename = filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

            if os.path.exists(filepath):
                with open(filepath, 'rb') as file:
                    content = file.read()  # 以二进制形式读取文件内容
                return Response(content)
            else:
                abort(404, description="File not found")

        except Exception as e:
            abort(500, description=f"Error reading file: {e}")

    else:
        abort(400, description="Bad request: 'filename' parameter is missing")




@app.route('/delateuser', methods=['GET'])
def delete_user():
    name = request.args.get('name')
    password = request.args.get('password')

    if name and password:
        user = User.query.filter_by(name=name, password=password).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return render_template("delatewhat.html", user=user)
        else:
            return jsonify({"message": "User not found!"}), 404
    else:
        return jsonify({"message": "Name and password are required!"}), 400


@app.route('/guess', methods=['GET', 'POST'])
#伪随机数
def guess_number():
    random.seed(10)
    random_number = random.randint(1, 999999999)

    if request.method == 'POST':
        user_guess = request.form.get('guess')

        if user_guess:
            try:
                user_guess = int(user_guess)
            except ValueError:
                return render_template("guess.html", error="Invalid input. Please enter a number.")

            path = os.path.join(app.config['UPLOAD_FOLDER'], "flag.txt")

            if user_guess == random_number:
                try:
                    with open(path, 'rb') as file:
                        content = file.read()
                    return render_template("guess_success.html", content=content)
                except Exception as e:
                    abort(500, description=f"Error reading file: {e}")
            else:
                try:
                    os.remove(path)
                    return render_template("guess_unsuccess.html")
                except Exception as e:
                    abort(500, description=f"Error deleting file: {e}")
    return render_template("guess.html")

# @app.route('/pollute')
# def pollute_route():

@app.route('/mysql', methods=['GET', 'POST'])
def sql_inject():
    user_id = request.args.get('id',2)
    conn = get_mysql_connection()
    if conn is None:
        return "Database connection failed", 500

    cursor = conn.cursor(dictionary=True)

    try:
        query = f"SELECT * FROM user WHERE id = {user_id}"
        cursor.execute(query)
        user = cursor.fetchall()
        print(f"Received user_id: {user_id}")
    except Exception as e:
        print(f"Error: {e}")
        user = None
    finally:
        cursor.close()
        conn.close()

    return user if user else "User not found"

@app.route('/mysql2', methods=['GET', 'POST'])
def sql_inject2():
    user_id = request.args.get('id')
    conn = get_mysql_connection()
    if conn is None:
        return "Database connection failed", 500

    cursor = conn.cursor(dictionary=True)

    try:
        query = "SELECT * FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        print(f"Executing query: {query} with user_id: {user_id}")
        user = cursor.fetchall()
    except Exception as e:
        print(f"Error: {e}")
        user = None
    finally:
        cursor.close()
        conn.close()

    return user if user else "User not found"

@app.route('/mysql3', methods=['GET', 'POST'])
def sql_inject3():
    user_id = request.args.get('id')
    conn = get_mysql_connection()
    if conn is None:
        return "Database connection failed", 500

    cursor = conn.cursor(dictionary=True)

    try:
        query = "SELECT * FROM user ORDER BY %s"
        cursor.execute(query, (user_id,), multi=True)
        print(f"Executing query: {query} with user_id: {user_id}")
        user = cursor.fetchall()
    except Exception as e:
        print(f"Error: {e}")
        user = None
    finally:
        cursor.close()
        conn.close()

    return user if user else "User not found"

@app.route('/mysql4', methods=['GET', 'POST'])
def sql_inject4():
    user_id = request.args.get('id',2)
    conn = get_mysql_connection()
    if conn is None:
        return "Database connection failed", 500

    cursor = conn.cursor(dictionary=True)

    try:
        query = f"SELECT * FROM user ORDER BY {user_id}"
        cursor.execute(query,multi=True)
        user = cursor.fetchall()
        print(f"Executing query: {query} with user_id: {user_id}")
    except Exception as e:
        print(f"Error: {e}")
        user = None
    finally:
        cursor.close()
        conn.close()

    return user if user else "User not found"



@app.route('/sql', methods=['GET', 'POST'])
def get_user():
    user_id = request.args.get('id')
    # if not user_id or is_blacklisted_SQL(user_id):
    #     return jsonify({"error": "Invalid ID parameter"}), 400
    conn = get_mysql_connection()
    query = f"SELECT * FROM users WHERE id = {user_id};"
    users = conn.execute(query).fetchall()
    conn.close()
    print(f"Received user_id: {user_id}")
    if users is None:
        return jsonify({"error": "User not found"}), 404
    else:
        try:
            user_dicts = [dict(user) for user in users]
            return jsonify(user_dicts)
        except Exception as e:
            print(f"Error converting users to dictionary: {e}")
            return jsonify({"error": "Failed to retrieve user information"}), 500

@app.route('/orm', methods=['GET', 'POST'])
def sql_in_orm():
    if request.method == 'GET':
        user_id = request.args.get('id')
        users = User.query.filter_by(id = user_id).all()
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'name': user.name,
                'password': user.password
            })

        return jsonify(user_data)

@app.route('/order', methods=['GET', 'POST'])
def sql_in_order():
    if request.method == 'GET':
        user_id = request.args.get('id')
        users = User.query.order_by(user_id).all()
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'name': user.name,
                'password': user.password
            })

        return jsonify(user_data)
@app.route('/redirect', methods=['GET', 'POST'])
def urlbypass():
    if request.values.get('url','https://www.baidu.com'):
        url = request.values.get('url')
        return redirect(url)

# @app.route('/hpp', methods=['GET', 'POST'])
# def hpp_test():
#     money={'1':100,'2':100}
#     payer_id = session.get('id')
#     transfer_amount = request.args.get('money')
#     payee_id = request.args.get('id')
#     payer_money = money('payer_id')-transfer_amount
#     payee_money = money('payee_id')+transfer_amount
#     print(money)
#     return jsonify({'status': 'success', 'money': money})

# @app.route('/pickle', methods=['GET', 'POST'])
# def pickle_test():
#     if request.values.get('url','https://www.baidu.com'):
#         url = request.values.get('url')
#         return redirect(url)


@app.route('/xxe',methods=['POST', 'GET'])
def xxe():
        tree = lxml.objectify.parse('xml2.xml',parser = etree.XMLParser(resolve_entities=True))
        return etree.tostring(tree.getroot())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000)
