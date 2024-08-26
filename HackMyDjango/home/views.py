import os
import string
import random
import subprocess
from io import BytesIO
from django.db import connection
from django.template.loader import render_to_string
from django.utils.html import escape
import pycurl
from django.core.files.storage import default_storage
from django.shortcuts import render
from django.conf import settings
from django.contrib.staticfiles import finders
from django.templatetags.static import static
from abc import ABC, abstractmethod
from djangoStudy.decorators import login_required
from django.shortcuts import render, redirect
# from django.contrib.auth import authenticate, login as auth_login
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.urls import reverse
from django.contrib.auth.hashers import check_password,make_password
from django.contrib import messages
from home.models import User, Post, Postform
from django.contrib.auth import logout as auth_logout  #内置，这个要看
from .utils import allowed_pics , allowed_zip_file ,secure_filename,secure_path, secure_url
import re

def index(request):
    return render(request, "index.html")


# @login_required
def welcome_view(request):
    session_id = request.COOKIES.get('session_id')
    static_folder = settings.STATICFILES_DIRS[0] if settings.STATICFILES_DIRS else settings.STATIC_ROOT
    avatar_path_jpg = os.path.join(static_folder, f"{session_id}.jpg")
    avatar_path_png = os.path.join(static_folder, f"{session_id}.png")

    if os.path.exists(avatar_path_jpg):
        avatar_url = avatar_path_jpg
    elif os.path.exists(avatar_path_png):
        avatar_url = avatar_path_png
    else:
        avatar_url = '/static/flask.jpg'
    return render(request, "welcome.html", {'username': session_id, 'avatar_url': avatar_url})

def login_view(request):
    session_id = request.COOKIES.get('session_id')
    if session_id is None:
        if request.method == 'POST':
            name = request.POST.get('name')
            password = request.POST.get('password')

            if not name or not password:
                messages.error(request, "Name and password are required!")
                return render(request, "login.html")

            try:
                user = User.objects.get(name=name)
            except User.DoesNotExist:
                messages.error(request, "Invalid name or password!")
                return render(request, "login.html")

            if check_password(password, user.password):
                response = redirect(reverse('home:welcome_view'))

                if user.name == 'admin':
                    response.set_cookie('session_id', 'admin')
                    request.session['is_admin'] = True
                else:
                    response.set_cookie('session_id', user.name)
                    request.session['is_admin'] = False

                # auth_login(request, user)
                return response
            else:
                messages.error(request, "Invalid name or password!")
                return render(request, "login.html")

        return render(request, "login.html")
    else:
        response = redirect(reverse('home:welcome_view'))
        return response

def register_view(request):
    session_id = request.COOKIES.get('session_id')
    if session_id:
        return render(request, 'register_fail.html')
    else:
        if request.method == 'POST':
            name = request.POST.get('name')
            password = request.POST.get('password')

            if not name or not password:
                messages.error(request, 'Name and password are required!')
                return redirect(reverse("home:register_view"))

            existing_user = User.objects.filter(name=name).first()
            if existing_user:
                messages.error(request, 'Username already taken!')
                return redirect(reverse("home:register_view"))

            password = make_password(password)
            new_user = User(name=name, password=password)

            try:
                new_user.save()
                print(new_user)
                return render(request, 'register_success.html', {'user': new_user})
            except Exception as e:
                messages.error(request, 'An error occurred: ' + str(e))
                return redirect(reverse("home:register_view"))

        return render(request, 'register.html')

def logout_view(request):
    session_id = request.COOKIES.get('session_id')
    if session_id:
        response = render(request, 'logout.html', {'session_id': session_id})
        response.delete_cookie('session_id')
        return response
    else:
        return redirect(reverse("home:login_view"))

@login_required
def upload_pics(request):
    session_id = request.COOKIES.get('session_id')
    if request.method == 'POST':
        if 'file' not in request.FILES:
            messages.error(request, 'No file part')
            return redirect('upload_pics')

        file = request.FILES['file']

        if not file.name:
            messages.error(request, 'No selected file')
            return redirect('upload_pics')

        if not secure_filename(file.name):
            messages.error(request, 'File is not allowed!')
            return redirect(request.path)

        if allowed_pics(file.name) and file.size < 1000000:
            filename = file.name
            session_id = request.session.get('session_id', session_id)
            pic_suffix = filename.rsplit('.', 1)[1].lower()
            request.session['picname'] = f"{session_id}.{pic_suffix}"

            file_path = os.path.join(settings.MEDIA_ROOT, request.session['picname'])
            with default_storage.open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            return render(request, 'upload_success.html', {'save_path': file_path})
        else:
            messages.error(request, 'Suffix is not allowed or file is too large!')

    return render(request, 'upload.html')


@login_required
def upload_zip(request):
    if request.method == 'POST':
        if 'file' not in request.FILES:
            messages.error(request, 'No file part')
            return redirect(request.path)

        file = request.FILES['file']
        if not file.name:
            messages.error(request, 'No selected file')
            return redirect(request.path)
        if file.size > 10000000:
            messages.error(request, 'File too large!')
            return redirect(request.path)
        if not secure_filename(file.name):
            messages.error(request, 'File is not allowed!')
            return redirect(request.path)
        if allowed_zip_file(file.name) :
            path = ''.join(random.choices(string.hexdigits, k=16))
            directory = os.path.join(settings.MEDIA_ROOT,'ZIP', path)
            os.makedirs(directory, exist_ok=True)
            save_path = os.path.join(directory, file.name)

            with default_storage.open(save_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            request.session['filepath'] = save_path
            return render(request, "upload_zip_success.html", {'save_path': save_path})
        else:
            messages.error(request, 'Suffix is not allowed!')
    return render(request, 'upload_zip.html')


@login_required
def unzip(request):
    if request.method == 'POST':
        save_path = request.session.get('filepath')
        get_path = request.POST.get('path')
        new_path = os.path.join(settings.MEDIA_ROOT, get_path)
        os.makedirs(new_path, mode=0o755, exist_ok=True)
        print(save_path)
        print(new_path)
        if secure_path(save_path) and secure_path(new_path):
            try:
                subprocess.run(['tar', '-xf', save_path, '-C', new_path], check=True, shell=False)
                messages.success(request, 'Unzip successful!')
            except subprocess.CalledProcessError:
                print('There is something wrong with unzip!')
                messages.error(request, 'Unzip failed!')
            except Exception as e:
                print(f'Unexpected error: {e}')
                messages.error(request, 'An unexpected error occurred!')
        else:
            messages.error(request, 'Path is not allowed!')

        return redirect(request.path)
    else:
        return render(request, 'unzip.html')


def SSRF(request):
    url = request.GET.get('url') if request.method == 'GET' else request.POST.get('url')

    if not url:
        return redirect(request.path + '?url=http://www.baidu.com')

    if secure_url(url):
        curl = pycurl.Curl()
        curl.setopt(curl.URL, url)
        curl.setopt(curl.FOLLOWLOCATION, True)
        curl.setopt(curl.MAXREDIRS, 3)
        curl.setopt(curl.CONNECTTIMEOUT, 5)
        buf = BytesIO()
        curl.setopt(curl.WRITEDATA, buf)
        curl.perform()
        curl.close()
        body = buf.getvalue()
        return render(request, 'ssrf.html', {'file': body.decode('utf-8')})
    else:
        return redirect(request.path + '?url=http://www.baidu.com')


@login_required
def userinfo(request):
    session_id = escape(request.COOKIES.get('session_id', ''))
    if session_id:
        if not request.GET.get('username'):
            return redirect(request.path + f'?username={session_id}')
        username = escape(request.GET.get('username', session_id))

        with connection.cursor() as cursor:
            try:
                query = f"SELECT * FROM user WHERE name = %s"
                cursor.execute(query,[username])
                user = cursor.fetchall()
                print(user)
            except Exception as e:
                print(f"Error: {e}")
                user = None

        return render(request, 'userinfo.html', {'user': user, 'username': username})
    else:
        return redirect(reverse('login'))

#或者使用ORM：
# @login_required
# def userinfo(request):
#     session_id = escape(request.COOKIES.get('session_id', ''))
#     if session_id:
#         if not request.GET.get('username'):
#             return redirect(request.path + f'?username={session_id}')
#         username = escape(request.GET.get('username', session_id))
#
#         try:
#             # 使用 Django ORM 进行查询
#             user = User.objects.filter(username=username)
              # 这里相当于执行了：SELECT * FROM auth_user WHERE username = 'XXXXXX';
              # 如果是order by 排序语句：
              # users = User.objects.all().order_by('username') ，等价于 SELECT * FROM auth_user ORDER BY username ASC;
#             print(user)
#         except Exception as e:
#             print(f"Error: {e}")
#             user = None
#
#         return render(request, 'userinfo.html', {'user': user, 'username': username})
#     else:
#         return redirect(reverse('login'))

from django.contrib.auth import authenticate, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages

@login_required
def changepasswd(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important to update the session hash
            messages.success(request, 'Password changed successfully!')
            return redirect('change_passwd_success')  # Redirect to a success page or another URL
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, 'changepasswd.html', {'form': form})


from django.shortcuts import render
def IP(request):
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        user_ip = forwarded_for.split(',')[0]
    else:
        user_ip = request.META.get('REMOTE_ADDR')

    if user_ip:
        return render(request, 'IP.html', {'user_ip': user_ip})
    else:
        return render(request, '404_ssti.html')

@login_required
def new_post(request):
    if request.method == 'POST':
        form = Postform(request.POST)
        if request.POST.get('title') and request.POST.get('content'):
            # 创建新帖子
            new_post = Post(
                title=request.POST.get('title'),
                content=request.POST.get('content'),
                author_name=request.COOKIES.get('session_id')  # 获取 Cookie 中的 session_id
            )
            new_post.save()
            messages.success(request, 'Your post has been created!')
            return redirect(reverse('home:view_posts'))
    else:
        form = Post()

    return render(request, 'create_post.html', {'form': form})

from django.db.models import F
@login_required
def view_posts(request):
    # try:
        orderby = request.GET.get('orderby', 'created_at')
        valid_orderby_fields = ['created_at', 'title', 'author']
        if orderby not in valid_orderby_fields:
            orderby = 'created_at'

        posts = Post.objects.all().order_by(F(orderby).asc())
        print(posts)

        return render(request, 'view_posts.html', {'posts': posts})

    # except Exception as e:
    #     messages.error(request, f'Error: {e}')
    #     return redirect(reverse('home:login_view'))


from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.urls import reverse
from .models import Post

@login_required
def delete_post(request,post_id):
    post = get_object_or_404(Post, id=post_id)
    session_id = request.COOKIES.get('session_id')

    if session_id == 'admin':
        post.delete()
        messages.success(request, 'Post has been deleted!')
    else:
        messages.error(request, 'You do not have permission to delete this post!')

    return redirect(reverse('home:view_posts'))

def location(request):
    response = render(request, 'ssrf.html')
    response.status_code = 302
    response['Location'] = 'http://www.baidu.com'
    return response

def delate_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if not username or not password:
            messages.error(request, "Name and password are required!")
            return render(request, "delate_user.html")
        try:
            user = User.objects.get(name=username)
        except User.DoesNotExist:
            messages.error(request, "Invalid name or password!")
            return render(request, "delate_user.html")

        if check_password(password, user.password):
            user.delete()
            return render(request,'delate_success.html',{'username': username})
        else:
            messages.error(request, "Invalid name or password!")
            return render(request, "delate_user.html")
    else:
        return render(request, "delate_user.html")


