from django.urls import path,reverse
from django.views.generic import TemplateView

from . import views


app_name='home'

urlpatterns = [
 path('',views.index),
 path('welcome/',views.welcome_view,name='welcome_view'),
path('login/',views.login_view,name='login_view'),
path('register/',views.register_view,name='register_view'),
path('logout/',views.logout_view,name='logout_view'),
path('upload/',views.upload_pics,name='upload_pics'),
path('upload_zip/',views.upload_zip,name='upload_zip'),
path('unzip/',views.unzip,name='unzip'),
path('ssrf/',views.SSRF,name='ssrf'),
path('userinfo/',views.userinfo,name='userinfo'),
path('changepasswd/', views.changepasswd, name='changepasswd'),
path('change_passwd_success/', TemplateView.as_view(template_name='change_passwd_success.html'), name='change_passwd_success'),
path('IP/', views.IP, name='IP'),
path('new_post/', views.new_post, name='new_post'),
path('view_posts/', views.view_posts, name='view_posts'),
path('delete_post/<int:post_id>/', views.delete_post, name='delete_post'),
path('location/', views.location, name='location'),
path('delate_user/', views.delate_user, name='delate_user'),
]
